import os
import json
import base64
from flask import Flask, request, jsonify, redirect, session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import requests
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-change-this')

# ============= CONFIGURACIÓN OAUTH2 =============
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

CLIENT_CONFIG = {
    "web": {
        "client_id": os.environ.get('GOOGLE_CLIENT_ID'),
        "client_secret": os.environ.get('GOOGLE_CLIENT_SECRET'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [os.environ.get('REDIRECT_URI', 'https://gmail-discord-bot.onrender.com/oauth2callback')]
    }
}

DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')
PROJECT_ID = os.environ.get('PROJECT_ID', "gmail-discord-bot-463619")
TOPIC_NAME = os.environ.get('TOPIC_NAME', "gmail-notifications")

GMAIL_ACCOUNTS_ENV = os.environ.get('GMAIL_ACCOUNTS')
if GMAIL_ACCOUNTS_ENV:
    GMAIL_ACCOUNTS = GMAIL_ACCOUNTS_ENV.split(',')
else:
    GMAIL_ACCOUNTS = [
        "netonworld1@gmail.com",
        "netflixonworld@gmail.com", 
        "cadete.daniel@gmail.com"
    ]

# ============= CONFIGURACIÓN DE CANALES ESPECÍFICOS =============

# Configuración para detectar pagos específicos por plataforma
PAYMENT_PROVIDERS = {
    "binance": {
        "name": "Binance",
        "webhook_url": os.environ.get('BINANCE_WEBHOOK_URL'),  # Nueva variable de entorno
        "sender_domains": ["binance.com", "directmail.binance.com"],
        "sender_emails": ["donotreply@directmail.binance.com"],
        "subject_keywords": ["Payment Receive Successful", "Deposit Successful", "Transaction Completed"],
        "emoji": "🪙",
        "color": 0xF3BA2F  # Color dorado de Binance
    }
}

# Mantener las palabras clave generales como backup
PAYMENT_KEYWORDS = [
    "pago recibido", "payment received", "payment successful", "transacción exitosa",
    "transferencia recibida", "transfer completed", "deposito realizado",
    "factura pagada", "invoice paid", "cobro realizado"
]

# ============= FUNCIONES PARA PERSISTIR TOKENS =============

def get_token_env_name(email):
    """Genera nombre de variable de entorno para el token de un usuario"""
    # Reemplazar caracteres especiales para crear nombre válido de variable
    clean_email = email.replace('@', '_AT_').replace('.', '_DOT_').replace('+', '_PLUS_')
    return f"OAUTH_TOKEN_{clean_email.upper()}"

def save_user_token(email, credentials):
    """Guarda el token de un usuario en variable de entorno"""
    token_data = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    
    # En desarrollo, solo imprimimos (en producción esto se configuraría en Render)
    env_name = get_token_env_name(email)
    token_json = json.dumps(token_data)
    
    print(f"🔐 Token para {email}:")
    print(f"Variable: {env_name}")
    print(f"Valor: {token_json}")
    print("⚠️  IMPORTANTE: Agrega esta variable en Render Environment")
    
    return env_name, token_json

def load_user_token(email):
    """Carga el token de un usuario desde variable de entorno"""
    env_name = get_token_env_name(email)
    token_json = os.environ.get(env_name)
    
    if not token_json:
        print(f"❌ No se encontró token para {email} (variable: {env_name})")
        return None
    
    try:
        token_data = json.loads(token_json)
        credentials = Credentials.from_authorized_user_info(token_data)
        print(f"✅ Token cargado para {email}")
        return credentials
    except Exception as e:
        print(f"❌ Error cargando token para {email}: {e}")
        return None

def get_gmail_service(email_address):
    """Obtiene servicio Gmail usando tokens persistentes"""
    try:
        credentials = load_user_token(email_address)
        if not credentials:
            return None
        
        service = build('gmail', 'v1', credentials=credentials)
        return service
    except Exception as e:
        print(f"Error creando servicio Gmail para {email_address}: {e}")
        return None

def is_user_authorized(email):
    """Verifica si un usuario está autorizado"""
    return load_user_token(email) is not None

# ============= FUNCIONES OAUTH2 =============

def get_google_flow():
    """Crea el flow de OAuth2"""
    flow = Flow.from_client_config(CLIENT_CONFIG, scopes=SCOPES)
    flow.redirect_uri = CLIENT_CONFIG["web"]["redirect_uris"][0]
    return flow

# ============= FUNCIONES AUXILIARES =============

def extract_payment_info(email_content, subject):
    """Extrae información de pago del email"""
    payment_info = {
        "amount": None,
        "currency": None,
        "method": None,
        "transaction_id": None,
        "sender": None
    }
    
    money_patterns = [
        r'\$\s*(\d+(?:,\d{3})*(?:\.\d{2})?)',
        r'(\d+(?:,\d{3})*(?:\.\d{2})?)\s*(USD|EUR|COP|MXN|ARS)',
        r'(\d+(?:,\d{3})*(?:\.\d{2})?)\s*\$',
    ]
    
    for pattern in money_patterns:
        match = re.search(pattern, email_content, re.IGNORECASE)
        if match:
            if pattern == money_patterns[0]:
                payment_info["amount"] = match.group(1)
                payment_info["currency"] = "USD"
            else:
                payment_info["amount"] = match.group(1)
                payment_info["currency"] = match.group(2) if len(match.groups()) > 1 else "USD"
            break
    
    methods = {
        "paypal": ["paypal", "paypal.com"],
        "stripe": ["stripe", "stripe.com"],
        "zelle": ["zelle", "zelle.com"],
        "mercadopago": ["mercadopago", "mercado pago"],
        "transferencia": ["transferencia", "transfer", "wire transfer"],
        "western union": ["western union", "westernunion"]
    }
    
    content_lower = email_content.lower()
    for method, keywords in methods.items():
        if any(keyword in content_lower for keyword in keywords):
            payment_info["method"] = method
            break
    
    transaction_patterns = [
        r'transaction\s*(?:id|#)?\s*:?\s*([a-zA-Z0-9]+)',
        r'reference\s*(?:id|#)?\s*:?\s*([a-zA-Z0-9]+)',
        r'id\s*:?\s*([a-zA-Z0-9]{10,})',
    ]
    
    for pattern in transaction_patterns:
        match = re.search(pattern, email_content, re.IGNORECASE)
        if match:
            payment_info["transaction_id"] = match.group(1)
            break
    
    return payment_info

def detect_payment_provider(email_details):
    """Detecta si un email es de un proveedor de pagos específico"""
    sender = email_details.get('sender', '').lower()
    subject = email_details.get('subject', '').lower()
    
    for provider_id, config in PAYMENT_PROVIDERS.items():
        # Verificar dominio del remitente
        for domain in config['sender_domains']:
            if domain.lower() in sender:
                # Verificar email específico si está configurado
                if config['sender_emails']:
                    for email in config['sender_emails']:
                        if email.lower() in sender:
                            # Verificar palabras clave en el asunto
                            for keyword in config['subject_keywords']:
                                if keyword.lower() in subject:
                                    return provider_id, config
                else:
                    # Si no hay emails específicos, solo verificar asunto
                    for keyword in config['subject_keywords']:
                        if keyword.lower() in subject:
                            return provider_id, config
    
    return None, None

def send_provider_notification(email_data, payment_info, provider_id, provider_config):
    """Envía notificación específica del proveedor"""
    
    webhook_url = provider_config.get('webhook_url')
    if not webhook_url:
        print(f"❌ No hay webhook configurado para {provider_id}")
        return False
    
    provider_name = provider_config.get('name', provider_id.title())
    emoji = provider_config.get('emoji', '💰')
    color = provider_config.get('color', 0x00ff00)
    
    print(f"🚀 Enviando notificación de {provider_name} para: {email_data.get('subject', 'Sin asunto')}")
    print(f"🔗 Webhook URL: {webhook_url[:50]}...")
    
    embed = {
        "title": f"{emoji} NUEVO PAGO {provider_name.upper()}",
        "color": color,
        "timestamp": datetime.utcnow().isoformat(),
        "fields": [
            {
                "name": "📧 Cuenta Gmail",
                "value": email_data.get("account", "No especificada"),
                "inline": True
            },
            {
                "name": "🏦 Plataforma",
                "value": provider_name,
                "inline": True
            },
            {
                "name": "📝 Asunto",
                "value": email_data.get("subject", "Sin asunto")[:100],
                "inline": False
            }
        ]
    }
    
    # Agregar información de pago si está disponible
    if payment_info["amount"]:
        embed["fields"].append({
            "name": "💵 Monto",
            "value": f"{payment_info['amount']} {payment_info['currency'] or 'USD'}",
            "inline": True
        })
    
    if payment_info["transaction_id"]:
        embed["fields"].append({
            "name": "🔍 ID Transacción",
            "value": payment_info["transaction_id"],
            "inline": True
        })
    
    if email_data.get("sender"):
        embed["fields"].append({
            "name": "👤 De",
            "value": email_data["sender"],
            "inline": True
        })
    
    if email_data.get("snippet"):
        embed["fields"].append({
            "name": "📄 Vista Previa",
            "value": email_data["snippet"][:200] + "..." if len(email_data["snippet"]) > 200 else email_data["snippet"],
            "inline": False
        })
    
    payload = {"embeds": [embed]}
    
    print(f"📦 Payload creado para {provider_name}: {payload}")
    
    try:
        print(f"🌐 Enviando request a Discord ({provider_name})...")
        response = requests.post(webhook_url, json=payload)
        print(f"📊 Respuesta Discord - Status: {response.status_code}")
        
        if response.status_code == 204:
            print(f"✅ Notificación de {provider_name} enviada exitosamente")
            return True
        else:
            print(f"❌ Error enviando notificación de {provider_name}: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error enviando notificación de {provider_name}: {e}")
        return False

def is_payment_email(subject, content):
    """Determina si un email es relacionado con pagos"""
    text_to_check = (subject + " " + content).lower()
    return any(keyword.lower() in text_to_check for keyword in PAYMENT_KEYWORDS)

def get_email_details(service, message_id):
    """Obtiene los detalles completos de un email"""
    try:
        message = service.users().messages().get(userId='me', id=message_id).execute()
        
        headers = message['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'Sin asunto')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Desconocido')
        
        content = ""
        snippet = message.get('snippet', '')
        
        payload = message.get('payload', {})
        if 'parts' in payload:
            for part in payload['parts']:
                if part.get('mimeType') == 'text/plain':
                    data = part.get('body', {}).get('data')
                    if data:
                        content = base64.urlsafe_b64decode(data).decode('utf-8')
                        break
        else:
            if payload.get('mimeType') == 'text/plain':
                data = payload.get('body', {}).get('data')
                if data:
                    content = base64.urlsafe_b64decode(data).decode('utf-8')
        
        return {
            "subject": subject,
            "sender": sender,
            "content": content or snippet,
            "snippet": snippet
        }
        
    except Exception as e:
        print(f"Error obteniendo detalles del email: {e}")
        return None

# ============= RUTAS OAUTH2 =============

@app.route('/authorize/<email>')
def authorize(email):
    """Inicia el flujo de autorización OAuth2"""
    if email not in GMAIL_ACCOUNTS:
        return jsonify({"error": "Email no autorizado"}), 400
    
    flow = get_google_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent',  # Fuerza re-autorización
        login_hint=email
    )
    
    session['state'] = state
    session['email'] = email
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    """Callback de OAuth2"""
    try:
        flow = get_google_flow()
        flow.fetch_token(authorization_response=request.url)
        
        credentials = flow.credentials
        email = session.get('email')
        
        if email:
            # Guardar token persistente
            env_name, token_json = save_user_token(email, credentials)
            
            response_html = f"""
            <h1>✅ Autorización exitosa para {email}</h1>
            <h2>⚠️ IMPORTANTE: Configurar Variable de Entorno</h2>
            <p>Para que el token persista después de redeploys, agrega esta variable en Render:</p>
            <div style="background: #f0f0f0; padding: 10px; margin: 10px 0;">
                <strong>Variable:</strong> <code>{env_name}</code><br>
                <strong>Valor:</strong> <textarea style="width: 100%; height: 100px;">{token_json}</textarea>
            </div>
            <p>1. Ve a Render → Environment → Add variable</p>
            <p>2. Copia exactamente el nombre y valor de arriba</p>
            <p>3. Redeploy la aplicación</p>
            <p><strong>Puedes cerrar esta ventana.</strong></p>
            """
            
            return response_html
        else:
            return "❌ Error: no se encontró el email en la sesión"
            
    except Exception as e:
        print(f"❌ Error en OAuth2 callback: {e}")
        return f"❌ Error en autorización: {e}"

# ============= RUTAS PRINCIPALES =============

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Maneja las notificaciones push de Gmail"""
    try:
        envelope = request.get_json()
        if not envelope:
            return jsonify({"error": "No JSON body"}), 400
        
        pubsub_message = envelope.get('message')
        if not pubsub_message:
            return jsonify({"error": "No Pub/Sub message"}), 400
        
        data = pubsub_message.get('data')
        if data:
            decoded_data = json.loads(base64.b64decode(data).decode('utf-8'))
            email_address = decoded_data.get('emailAddress')
            history_id = decoded_data.get('historyId')
            
            print(f"📧 Notificación recibida para: {email_address}")
            print(f"🔍 History ID: {history_id}")
            
            process_gmail_notification(email_address, history_id)
        
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        print(f"❌ Error procesando webhook: {e}")
        return jsonify({"error": str(e)}), 500

def process_gmail_notification(email_address, history_id):
    """Procesa una notificación de Gmail"""
    try:
        service = get_gmail_service(email_address)
        if not service:
            print(f"❌ No se pudo configurar servicio para {email_address} - usuario no autorizado")
            return
        
        print(f"🔍 Buscando cambios desde History ID: {history_id}")
        
        history = service.users().history().list(
            userId='me',
            startHistoryId=history_id
        ).execute()
        
        print(f"📊 Respuesta completa del history: {history}")
        
        if 'history' not in history:
            print("ℹ️ No hay cambios en el historial")
            print(f"🔍 Claves en respuesta: {list(history.keys())}")
            return
        
        print(f"🔍 Procesando {len(history['history'])} registros de historial")
        
        # Procesar cada cambio
        for i, record in enumerate(history['history']):
            print(f"📝 Procesando registro {i+1}: {record}")
            
            if 'messagesAdded' in record:
                print(f"📬 Encontrados mensajes agregados: {len(record['messagesAdded'])}")
                for j, message_added in enumerate(record['messagesAdded']):
                    message_id = message_added['message']['id']
                    print(f"📧 Procesando mensaje {j+1} con ID: {message_id}")
                    
                    # Obtener detalles del email
                    email_details = get_email_details(service, message_id)
                    if not email_details:
                        print(f"❌ No se pudieron obtener detalles del mensaje {message_id}")
                        continue
                    
                    print(f"📄 Email obtenido - Asunto: {email_details['subject']}")
                    print(f"📄 Contenido preview: {email_details['content'][:100]}...")
                    
                    # Verificar si es un email de pago
                    if is_payment_email(email_details['subject'], email_details['content']):
                        print(f"💰 Email de pago detectado: {email_details['subject']}")
                        
                        # Extraer información de pago
                        payment_info = extract_payment_info(
                            email_details['content'], 
                            email_details['subject']
                        )
                        
                        # Preparar datos para Discord
                        email_data = {
                            "account": email_address,
                            "subject": email_details['subject'],
                            "sender": email_details['sender'],
                            "snippet": email_details['snippet']
                        }
                        
                        # Enviar notificación a Discord
                        send_discord_notification(email_data, payment_info)
                    else:
                        print(f"ℹ️ Email no relacionado con pagos: {email_details['subject']}")
            else:
                print(f"🔍 Registro no contiene 'messagesAdded': {list(record.keys())}")
                if 'messages' in record:
                    print(f"📬 Encontrado campo 'messages': {record['messages']}")
                    # Procesar mensajes en formato diferente
                    for j, message in enumerate(record['messages']):
                        message_id = message['id']
                        print(f"📧 Procesando mensaje alternativo {j+1} con ID: {message_id}")
                        
                        email_details = get_email_details(service, message_id)
                        if not email_details:
                            print(f"❌ No se pudieron obtener detalles del mensaje {message_id}")
                            continue
                        
                        print(f"📄 Email obtenido - Asunto: {email_details['subject']}")
                        
                        if is_payment_email(email_details['subject'], email_details['content']):
                            print(f"💰 Email de pago detectado: {email_details['subject']}")
                            
                            payment_info = extract_payment_info(
                                email_details['content'], 
                                email_details['subject']
                            )
                            
                            email_data = {
                                "account": email_address,
                                "subject": email_details['subject'],
                                "sender": email_details['sender'],
                                "snippet": email_details['snippet']
                            }
                            
                            send_discord_notification(email_data, payment_info)
                        else:
                            print(f"ℹ️ Email no relacionado con pagos: {email_details['subject']}")
        
        print("✅ Procesamiento de historial completado")
    except Exception as e:
        print(f"❌ Error procesando notificación de Gmail: {e}")

@app.route('/setup', methods=['GET', 'POST'])
def setup_gmail_watch():
    """Configura Gmail watch para cuentas autorizadas"""
    results = []
    
    for email_address in GMAIL_ACCOUNTS:
        if not is_user_authorized(email_address):
            results.append({
                "email": email_address,
                "status": "error",
                "message": f"Usuario no autorizado. Visita /authorize/{email_address}"
            })
            continue
            
        try:
            service = get_gmail_service(email_address)
            if not service:
                results.append({
                    "email": email_address,
                    "status": "error",
                    "message": "No se pudo configurar el servicio"
                })
                continue
            
            request_body = {
                'topicName': f'projects/{PROJECT_ID}/topics/{TOPIC_NAME}',
                'labelIds': ['INBOX'],
                'labelFilterBehavior': 'INCLUDE'
            }
            
            watch_response = service.users().watch(userId='me', body=request_body).execute()
            
            results.append({
                "email": email_address,
                "status": "success",
                "historyId": watch_response.get('historyId'),
                "expiration": watch_response.get('expiration')
            })
            
            print(f"✅ Watch configurado para {email_address}")
            
        except Exception as e:
            results.append({
                "email": email_address,
                "status": "error",
                "message": str(e)
            })
            print(f"❌ Error configurando watch para {email_address}: {e}")
    
    return jsonify({"results": results})

@app.route('/status')
def status():
    """Muestra el estado de autorización"""
    status_info = {}
    for email in GMAIL_ACCOUNTS:
        authorized = is_user_authorized(email)
        status_info[email] = {
            "authorized": authorized,
            "authorization_url": f"/authorize/{email}" if not authorized else None,
            "token_env_var": get_token_env_name(email) if not authorized else None
        }
    
    return jsonify(status_info)

@app.route('/test', methods=['GET'])
def test_endpoint():
    """Endpoint de prueba"""
    authorized_count = sum(1 for email in GMAIL_ACCOUNTS if is_user_authorized(email))
    
    return jsonify({
        "status": "Server running",
        "timestamp": datetime.utcnow().isoformat(),
        "configured_accounts": len(GMAIL_ACCOUNTS),
        "authorized_accounts": authorized_count
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check para el servidor"""
    return jsonify({"status": "healthy"}), 200

@app.route('/')
def index():
    """Página principal con links de autorización"""
    html = """
    <h1>Gmail Discord Bot</h1>
    <h2>Autorizar Cuentas Gmail:</h2>
    <ul>
    """
    
    for email in GMAIL_ACCOUNTS:
        if is_user_authorized(email):
            html += f"<li>✅ {email} - Autorizado</li>"
        else:
            html += f'<li>❌ {email} - <a href="/authorize/{email}">Autorizar</a></li>'
    
    html += """
    </ul>
    <p><a href="/status">Ver Status JSON</a></p>
    <p><a href="/setup">Configurar Watches</a></p>
    """
    
    return html

if __name__ == '__main__':
    print("🚀 Iniciando servidor Gmail-Discord con tokens persistentes...")
    print(f"📧 Cuentas configuradas: {len(GMAIL_ACCOUNTS)}")
    print(f"🔐 Tokens persistentes habilitados")
    
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
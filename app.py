import os
import json
import base64
from flask import Flask, request, jsonify
from google.oauth2 import service_account
from googleapiclient.discovery import build
import requests
from datetime import datetime
import re

app = Flask(__name__)

# ============= CONFIGURACIÓN =============
# Configurar estas variables
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1386078281111179316/vLR7d3SuEY-2u_jAtxJqVbyIKNuw2SXwHYbLw_DHo29E4f_VbeCCjP-SyIgAxJySzvxP"
GOOGLE_CREDENTIALS_FILE = "credentials.json"  # Tu archivo JSON descargado
PROJECT_ID = "gmail-discord-bot-463619"  # Tu project ID de Google Cloud
TOPIC_NAME = "gmail-notifications"

# Lista de cuentas Gmail a monitorear
GMAIL_ACCOUNTS = [
    "netflixonworld@gmail.com",
    "netonworld1@gmail.com", 
        # Agrega todas las cuentas que necesites
]

# Palabras clave para detectar pagos (personalízalas)
PAYMENT_KEYWORDS = [
    "pago recibido", "payment received", "paypal", "stripe", "transferencia",
    "deposito", "transaccion", "factura pagada", "invoice paid", "zelle",
    "mercadopago", "western union", "$", "usd", "eur", "cop", "mxn"
]

# ============= FUNCIONES AUXILIARES =============

def setup_gmail_service(email_address):
    """Configura el servicio Gmail API para una cuenta específica"""
    try:
        # Cargar credenciales del service account
        credentials = service_account.Credentials.from_service_account_file(
            GOOGLE_CREDENTIALS_FILE,
            scopes=['https://www.googleapis.com/auth/gmail.readonly']
        )
        
        # Delegar autoridad a la cuenta de Gmail específica
        delegated_credentials = credentials.with_subject(email_address)
        
        # Crear servicio Gmail
        service = build('gmail', 'v1', credentials=delegated_credentials)
        return service
    except Exception as e:
        print(f"Error configurando Gmail service para {email_address}: {e}")
        return None

def extract_payment_info(email_content, subject):
    """Extrae información de pago del email"""
    payment_info = {
        "amount": None,
        "currency": None,
        "method": None,
        "transaction_id": None,
        "sender": None
    }
    
    # Buscar montos con regex
    money_patterns = [
        r'\$\s*(\d+(?:,\d{3})*(?:\.\d{2})?)',  # $1,000.00
        r'(\d+(?:,\d{3})*(?:\.\d{2})?)\s*(USD|EUR|COP|MXN|ARS)',  # 1000.00 USD
        r'(\d+(?:,\d{3})*(?:\.\d{2})?)\s*\$',  # 1000.00$
    ]
    
    for pattern in money_patterns:
        match = re.search(pattern, email_content, re.IGNORECASE)
        if match:
            if pattern == money_patterns[0]:  # Patrón con $
                payment_info["amount"] = match.group(1)
                payment_info["currency"] = "USD"
            else:
                payment_info["amount"] = match.group(1)
                payment_info["currency"] = match.group(2) if len(match.groups()) > 1 else "USD"
            break
    
    # Detectar método de pago
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
    
    # Buscar ID de transacción
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

def send_discord_notification(email_data, payment_info):
    """Envía notificación a Discord con formato rico"""
    
    # Determinar color basado en el monto
    color = 0x00ff00  # Verde por defecto
    if payment_info["amount"]:
        try:
            amount = float(payment_info["amount"].replace(",", ""))
            if amount >= 1000:
                color = 0xff0000  # Rojo para montos altos
            elif amount >= 500:
                color = 0xffa500  # Naranja para montos medios
        except:
            pass
    
    # Crear embed para Discord
    embed = {
        "title": "💰 NUEVO PAGO RECIBIDO",
        "color": color,
        "timestamp": datetime.utcnow().isoformat(),
        "fields": [
            {
                "name": "📧 Cuenta Gmail",
                "value": email_data.get("account", "No especificada"),
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
    
    if payment_info["method"]:
        embed["fields"].append({
            "name": "💳 Método",
            "value": payment_info["method"].title(),
            "inline": True
        })
    
    if payment_info["transaction_id"]:
        embed["fields"].append({
            "name": "🔍 ID Transacción",
            "value": payment_info["transaction_id"],
            "inline": True
        })
    
    # Agregar remitente
    if email_data.get("sender"):
        embed["fields"].append({
            "name": "👤 De",
            "value": email_data["sender"],
            "inline": True
        })
    
    # Agregar preview del contenido
    if email_data.get("snippet"):
        embed["fields"].append({
            "name": "📄 Vista Previa",
            "value": email_data["snippet"][:200] + "..." if len(email_data["snippet"]) > 200 else email_data["snippet"],
            "inline": False
        })
    
    payload = {
        "embeds": [embed]
    }
    
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        if response.status_code == 204:
            print("✅ Notificación enviada a Discord exitosamente")
            return True
        else:
            print(f"❌ Error enviando a Discord: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error enviando notificación a Discord: {e}")
        return False

def is_payment_email(subject, content):
    """Determina si un email es relacionado con pagos"""
    text_to_check = (subject + " " + content).lower()
    return any(keyword.lower() in text_to_check for keyword in PAYMENT_KEYWORDS)

def get_email_details(service, message_id):
    """Obtiene los detalles completos de un email"""
    try:
        message = service.users().messages().get(userId='me', id=message_id).execute()
        
        # Extraer headers
        headers = message['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'Sin asunto')
        sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Desconocido')
        
        # Extraer contenido del email
        content = ""
        snippet = message.get('snippet', '')
        
        # Intentar obtener el body del email
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

# ============= RUTAS FLASK =============

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Maneja las notificaciones push de Gmail"""
    try:
        # Parsear el mensaje de Pub/Sub
        envelope = request.get_json()
        if not envelope:
            return jsonify({"error": "No JSON body"}), 400
        
        pubsub_message = envelope.get('message')
        if not pubsub_message:
            return jsonify({"error": "No Pub/Sub message"}), 400
        
        # Decodificar el mensaje
        data = pubsub_message.get('data')
        if data:
            decoded_data = json.loads(base64.b64decode(data).decode('utf-8'))
            email_address = decoded_data.get('emailAddress')
            history_id = decoded_data.get('historyId')
            
            print(f"📧 Notificación recibida para: {email_address}")
            print(f"🔍 History ID: {history_id}")
            
            # Procesar la notificación
            process_gmail_notification(email_address, history_id)
        
        return jsonify({"status": "success"}), 200
        
    except Exception as e:
        print(f"❌ Error procesando webhook: {e}")
        return jsonify({"error": str(e)}), 500

def process_gmail_notification(email_address, history_id):
    """Procesa una notificación de Gmail"""
    try:
        # Configurar servicio Gmail para esta cuenta
        service = setup_gmail_service(email_address)
        if not service:
            print(f"❌ No se pudo configurar servicio para {email_address}")
            return
        
        # Obtener cambios desde el history_id
        history = service.users().history().list(
            userId='me',
            startHistoryId=history_id
        ).execute()
        
        if 'history' not in history:
            print("ℹ️ No hay cambios en el historial")
            return
        
        # Procesar cada cambio
        for record in history['history']:
            if 'messagesAdded' in record:
                for message_added in record['messagesAdded']:
                    message_id = message_added['message']['id']
                    
                    # Obtener detalles del email
                    email_details = get_email_details(service, message_id)
                    if not email_details:
                        continue
                    
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
        
    except Exception as e:
        print(f"❌ Error procesando notificación de Gmail: {e}")

@app.route('/setup', methods=['POST'])
def setup_gmail_watch():
    """Configura Gmail watch para todas las cuentas"""
    results = []
    
    for email_address in GMAIL_ACCOUNTS:
        try:
            service = setup_gmail_service(email_address)
            if not service:
                results.append({
                    "email": email_address,
                    "status": "error",
                    "message": "No se pudo configurar el servicio"
                })
                continue
            
            # Configurar watch request
            request_body = {
                'topicName': f'projects/{PROJECT_ID}/topics/{TOPIC_NAME}',
                'labelIds': ['INBOX'],  # Solo emails en INBOX
                'labelFilterBehavior': 'INCLUDE'
            }
            
            # Ejecutar watch
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

@app.route('/test', methods=['GET'])
def test_endpoint():
    """Endpoint de prueba"""
    return jsonify({
        "status": "Server running",
        "timestamp": datetime.utcnow().isoformat(),
        "configured_accounts": len(GMAIL_ACCOUNTS)
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check para el servidor"""
    return jsonify({"status": "healthy"}), 200

# ============= EJECUTAR SERVIDOR =============
if __name__ == '__main__':
    print("🚀 Iniciando servidor Gmail-Discord...")
    print(f"📧 Cuentas configuradas: {len(GMAIL_ACCOUNTS)}")
    print(f"🔗 Webhook URL necesaria: /webhook")
    print(f"⚙️ Setup URL: /setup")
    
    # Ejecutar en puerto 8080 (cambiar según necesidad)
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
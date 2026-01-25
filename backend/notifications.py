import os
import requests
import smtplib
from email.message import EmailMessage
import logging
import json

logger = logging.getLogger("Indigo_MFA_Backend")

def send_alert(tenant_id, event_type, user_id, status, details, channel_config):
    """
    Sends an alert via the configured channel (Webhook or Email).
    """
    msg_body = f"Indigo MFA Alert\nTenant: {tenant_id}\nEvent: {event_type}\nUser: {user_id}\nStatus: {status}\nDetails: {details}"

    try:
        if channel_config['type'] == 'WEBHOOK':
            url = channel_config['config'].get('url')
            if url:
                 requests.post(url, json={"text": msg_body}, timeout=2)

        elif channel_config['type'] == 'EMAIL':
            config = channel_config['config']
            msg = EmailMessage()
            msg.set_content(msg_body)
            msg['Subject'] = f"Indigo Alert: {status} - {user_id}"
            msg['From'] = config.get('sender', 'alert@indigo.local')
            msg['To'] = config['email']

            enc = config.get('encryption', 'STARTTLS')
            host = config['host']
            port = int(config.get('port', 25))

            if enc == 'SSL':
                s = smtplib.SMTP_SSL(host, port)
            else:
                s = smtplib.SMTP(host, port)
                if enc == 'STARTTLS':
                    s.starttls()

            if config.get('user') and config.get('pass'):
                s.login(config['user'], config['pass'])
            s.send_message(msg)
            s.quit()

        elif channel_config['type'] == 'MAILGUN':
            config = channel_config['config']
            domain = config.get('domain')
            api_key = config.get('api_key')
            sender = config.get('sender', f"alert@{domain}")
            recipient = config.get('email')

            if domain and api_key and recipient:
                requests.post(
                    f"https://api.mailgun.net/v3/{domain}/messages",
                    auth=("api", api_key),
                    data={
                        "from": f"Indigo MFA <{sender}>",
                        "to": recipient,
                        "subject": f"Indigo Alert: {status} - {user_id}",
                        "text": msg_body
                    },
                    timeout=5
                )

    except Exception as e:
        logger.error(f"Failed to send alert: {e}")

def send_legacy_webhook(event_type, user_id, status, details):
    """
    Legacy environment variable based webhook.
    """
    webhook_url = os.environ.get("ALERT_WEBHOOK_URL")
    if webhook_url and status in ['DURESS', 'ABUSE']:
         try:
            payload = {
                "text": f"🚨 **INDIGO MFA ALERT** 🚨\n*Event:* {event_type}\n*User:* `{user_id}`\n*Status:* {status}\n*Details:* {details}"
            }
            requests.post(webhook_url, json=payload, timeout=2)
         except Exception as e:
             logger.error(f"Legacy webhook error: {e}")

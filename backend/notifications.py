import os
import requests
import logging

logger = logging.getLogger("Indigo_MFA_Backend")

def send_webhook_alert(event_type, user_id, status, details):
    """
    Sends a JSON webhook to the configured URL (e.g. Slack/Discord).
    Only triggered for high-severity events (DURESS, ABUSE).
    """
    webhook_url = os.environ.get("ALERT_WEBHOOK_URL")
    if not webhook_url:
        return

    payload = {
        "text": f"🚨 **INDIGO MFA ALERT** 🚨\n*Event:* {event_type}\n*User:* `{user_id}`\n*Status:* {status}\n*Details:* {details}"
    }

    try:
        # Timeout set to 2s to not block the main request
        requests.post(webhook_url, json=payload, timeout=2)
    except Exception as e:
        logger.error(f"Failed to send webhook: {e}")

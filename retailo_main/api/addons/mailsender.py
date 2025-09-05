import requests
import msal
from decouple import config


def _acquire_graph_token() -> str:
    tenant = config("AZURE_TENANT_ID")
    client_id = config("AZURE_CLIENT_ID")
    client_secret = config("AZURE_CLIENT_SECRET")
    scope = config("GRAPH_API_SCOPE", default="https://graph.microsoft.com/.default")

    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=f"https://login.microsoftonline.com/{tenant}",
    )

    result = app.acquire_token_silent(scopes=[scope], account=None)
    if not result:
        result = app.acquire_token_for_client(scopes=[scope])

    if "access_token" not in result:
        raise RuntimeError(f"MSAL token error: {result.get('error_description') or result}")
    return result["access_token"]


def send_mail_via_graph(
    to_email: str,
    subject: str,
    body_text: str,
    from_upn: str | None = None,
    save_to_sent_items: bool = True,
) -> None:
    token = _acquire_graph_token()
    graph_base = config("GRAPH_API_BASE", default="https://graph.microsoft.com/v1.0")
    sender = from_upn or config("GRAPH_SENDER_UPN")

    url = f"{graph_base}/users/{sender}/sendMail"
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body_text},
            "toRecipients": [{"emailAddress": {"address": to_email}}],
        },
        "saveToSentItems": bool(save_to_sent_items),
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    resp = requests.post(url, json=payload, headers=headers, timeout=15)
    if resp.status_code not in (202, 200):
        raise RuntimeError(f"Graph sendMail failed: {resp.status_code} {resp.text}")


def send_otp_email(to_email: str, code: str, purpose: str = "Login 2FA") -> None:
    ttl = config("OTP_TTL_MINUTES", cast=int, default=10)
    subject = f"Twój kod {purpose}"
    body = f"Twój kod: {code}\nKod wygaśnie za {ttl} minut."
    send_mail_via_graph(to_email, subject, body)



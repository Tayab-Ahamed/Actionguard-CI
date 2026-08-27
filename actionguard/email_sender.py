from pathlib import Path
import os
import smtplib
from email.message import EmailMessage


def send_if_configured(repo_name, score, summary, html_path):
    user = os.getenv("MAIL_USERNAME")
    password = os.getenv("MAIL_PASSWORD")
    to = os.getenv("REPORT_TO_EMAIL")
    if not all([user, password, to]):
        return {"status": "skipped", "detail": "SMTP secrets not configured"}
    try:
        host = os.getenv("MAIL_HOST", "smtp.gmail.com")
        port = int(os.getenv("MAIL_PORT", "465"))
        msg = EmailMessage()
        msg["Subject"] = f"ActionGuard AutoAudit Report - {repo_name}"
        msg["From"] = user
        msg["To"] = to
        msg.set_content(
            f'Repository: {repo_name}\nOverall score: {score}\nCritical: {summary["critical"]}\nHigh: {summary["high"]}\nReport attached.\n'
        )
        msg.add_attachment(Path(html_path).read_bytes(), maintype="text", subtype="html", filename=Path(html_path).name)
        with smtplib.SMTP_SSL(host, port, timeout=30) as s:
            s.login(user, password)
            s.send_message(msg)
        return {"status": "sent", "to": to}
    except Exception as e:
        return {"status": "failed", "detail": str(e)}

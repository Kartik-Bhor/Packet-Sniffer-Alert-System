# email_sender.py

import sys
import smtplib
from email.mime.text import MIMEText
import time

SENDER_EMAIL = "kartikbhor2478@gmail.com"
RECEIVER_EMAIL = "kartibhor007@gmail.com"
APP_PASSWORD = "cnsylfykknzypnmk"

def send_email(ip, count, timestamp, alert_type):
    subject = f"🚨 Network Alert: {alert_type.upper()} from {ip}"
    if alert_type == "FLOOD":
        body = f"⚠ Packet flood detected from {ip}\nPackets: {count} in short time\nTime: {timestamp}"
    elif alert_type == "PORTSCAN":
        body = f"⚠ Port scan/flood detected from {ip}\nPorts targeted: {count}\nTime: {timestamp}"
    else:
        body = f"⚠ Unknown alert from {ip} at {timestamp}"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.send_message(msg)
        print(f"[✓] Email sent for {ip}")
    except Exception as e:
        print(f"[✗] Email failed: {e}")
        with open("errors.log", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Email Error: {e}\n")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 email_sender.py <ip> <count> <timestamp> <type>")
    else:
        send_email(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

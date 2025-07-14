# Packet-Sniffer-Alert-System


A real-time network sniffer built with Python that:

- Captures live traffic (IP, protocol, port, length)
- Detects anomalies (packet floods & port scans)
- Shows color-coded events in a Tkinter GUI
- Sends email alerts via Gmail SMTP
- Logs every packet to SQLite for later analysis

---

## 🔧 Features

- ✅ Live packet capture using scapy
- ✅ Detection of packet floods and port scans
- ✅ GUI dashboard with color-coded traffic logs
- ✅ Automated email alerts via Gmail SMTP
- ✅ Packet logging to SQLite database
- ✅ Threaded design for smooth GUI performance

---

## 🧠 Built With AI Support

This project was developed through self-learning and with support from AI tools (ChatGPT) for guidance, debugging, and explanation of libraries like Scapy and SMTP.

---

### 📦 Requirements

| Package    | Use |
|------------|-----|
| Python 3.x | Runtime |
| scapy      | Packet sniffing |
| tkinter    | GUI (usually pre-installed) |
| sqlite3    | Logging (comes with Python) |

To install Scapy:
```bash
pip install scapy

To install Tkinter (if needed on Debian/Kali):

sudo apt install python3-tk


---

🟢 Running the Sniffer

sudo python3 sniffer_gui_trigger_email.py

> Run with sudo to allow low-level packet sniffing on Linux systems.


---

📧 Email Alerts Setup

1. Enable 2-Step Verification on your Gmail account.


2. Generate an App Password here.

---

🧪 Simulate Attacks for Testing

To test detection and alerts:

🔁 Packet Flood (DoS simulation)

sudo hping3 -S <your_IP> -p 80 --flood

🔍 Port Scan

nmap -p 1-100 <your_IP>


---

📁 Project Structure

├── sniffer_gui_trigger_email.py   # Main sniffer with GUI, SQLite, alerting
├── email_sender.py                # Email alert script (called by subprocess)
├── packets.db                     # SQLite DB (auto-created)
├── errors.log                     # Log for any runtime errors
└── README.md                      # This file


---

📚 What I Learned

Real-time packet sniffing using Scapy

TCP/UDP/IP structure and network headers

Anomaly detection patterns (DoS, port scans)

Multithreading in GUI applications

Automating Gmail alerts securely with SMTP

Using SQLite for structured data logging

Linux command-line tools (hping3, nmap)



---

👤 Author

Kartik Bhor
Cybersecurity & Networking Enthusiast
📧 [kartikbhor10@gail.com]

---

🌟 Star This Repo

If this helped you or inspired you, feel free to ⭐ the repo. Thanks!

--

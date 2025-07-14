from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import time
from collections import defaultdict
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
import subprocess

# -------------------- SQLite Setup --------------------
conn = sqlite3.connect("packets.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER
)
""")
conn.commit()

# -------------------- GUI --------------------
root = tk.Tk()
root.title("Network Packet Sniffer")
text_area = ScrolledText(root, width=100, height=30, bg="black", fg="lime", font=("Courier", 10))
text_area.pack(padx=10, pady=10)

def log_message(message, color="lime"):
    text_area.insert(tk.END, message + "\n", color)
    text_area.see(tk.END)
    text_area.tag_config("lime", foreground="lime")
    text_area.tag_config("red", foreground="red")
    text_area.tag_config("orange", foreground="orange")

log_message("✅ Sniffer started. Press Ctrl+C to stop.\n")

# -------------------- Detection Setup --------------------
ip_timestamp = defaultdict(list)
port_map = defaultdict(lambda: defaultdict(float))  # src_ip -> port -> timestamp
already_alerted_flood = set()
already_alerted_portscan = set()
FLOOD_THRESHOLD = 10
PORTSCAN_THRESHOLD = 10
TIME_WINDOW = 5

# -------------------- Packet Processor --------------------
def process_packet(packet):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            dst_port = 0
            proto = "other"

            if TCP in packet:
                proto = "TCP"
                dst_port = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                dst_port = packet[UDP].dport

            length = len(packet)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            # Save to DB
            cursor.execute("""
                INSERT INTO traffic (timestamp, src_ip, dst_ip, dst_port, protocol, length)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (timestamp, src_ip, dst_ip, dst_port, proto, length))
            conn.commit()

            log_message(f"[{proto}] {src_ip} → {dst_ip}:{dst_port} | Length: {length}")

            # Flood Detection
            ip_timestamp[src_ip].append(time.time())
            ip_timestamp[src_ip] = [t for t in ip_timestamp[src_ip] if time.time() - t <= TIME_WINDOW]

            if len(ip_timestamp[src_ip]) > FLOOD_THRESHOLD:
                if src_ip not in already_alerted_flood:
                    log_message(f"⚠ ALERT: Packet Flood from {src_ip} ({len(ip_timestamp[src_ip])} packets)", color="red")
                    already_alerted_flood.add(src_ip)
                    subprocess.Popen(["python3", "email_sender.py", src_ip, str(len(ip_timestamp[src_ip])), timestamp, "FLOOD"])

            # Port Scan Detection
            port_map[src_ip][dst_port] = time.time()
            # Remove old ports
            port_map[src_ip] = {port: t for port, t in port_map[src_ip].items() if time.time() - t <= TIME_WINDOW}

            if len(port_map[src_ip]) > PORTSCAN_THRESHOLD:
                if src_ip not in already_alerted_portscan:
                    log_message(f"⚠ ALERT: Port Flood/Scan from {src_ip} (→ {len(port_map[src_ip])} unique ports)", color="red")
                    already_alerted_portscan.add(src_ip)
                    subprocess.Popen(["python3", "email_sender.py", src_ip, str(len(port_map[src_ip])), timestamp, "PORTSCAN"])
    except Exception as e:
        log_message(f"[Error] Packet error: {e}", color="orange")
        with open("errors.log", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Packet Error: {e}\n")

# -------------------- Sniffer --------------------
def start_sniffing():
    try:
        sniff(prn=process_packet, store=False, iface="eth0", filter="ip")
    except Exception as e:
        log_message(f"[Error] Sniffer crashed: {e}", color="red")
        with open("errors.log", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Sniffer Crash: {e}\n")

sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()
root.mainloop()
conn.close()

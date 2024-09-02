import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, ICMP, UDP, ARP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest  # For HTTP requests
from datetime import datetime
import requests
import threading
import queue
import logging
#make sure to have all of the dependencies installed
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
GEMINI_API_KEY = "" #add your gemini api key (fine tuned version)
ABUSEIPDB_API_KEY = '' #add your ABUSEIPDB api key here
RAPIDAPI_KEY = ""     #add your RAPIDAPI KEY for geolocation
RAPIDAPI_HOST = ""    #add your RAPIDAPI HOST here
WHITELIST = {"192.168.0.1"}  # Whitelisted IPs

class IntrusionDetectionSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.configure(bg="#1e1e1e")
        self.root.geometry("1600x900")

        self.packet_queue = queue.Queue()
        self.detected_ips = set()
        self.setup_gui()
        self.start_sniffing_thread()
        self.start_update_thread()

    def setup_gui(self):
        # Header
        header_frame = tk.Frame(self.root, bg="#1e1e1e")
        header_frame.pack(fill='x', pady=20)

        header_label = tk.Label(header_frame, text="Real-Time Intrusion Detection System", font=("Helvetica", 24, "bold"), bg="#1e1e1e", fg="#8be9fd")
        header_label.pack()

        # Student and Supervisor Information
        info_label = tk.Label(header_frame, text="IDS Project by ABDUR REHMAN, SAAD KHALID | Supervisor: Ubaid ullah Aleem | Co.Supervisor: Mrs. Naila Nawaz", font=("Helvetica", 14), bg="#1e1e1e", fg="white")
        info_label.pack(pady=5)

        # Treeview for displaying results
        columns = ("time", "src", "dst", "type", "protocol", "src_port", "dst_port", "analysis", "indicator", "geoip")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=30, style="mystyle.Treeview")
        for col in columns:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, anchor="w", width=150 if col != "analysis" else 300)
        self.tree.pack(expand=True, fill='both', padx=10, pady=10)

        # Adding scrollbars to the Treeview
        vsb = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.tree, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side='right', fill='y')
        hsb.pack(side='bottom', fill='x')

        # Status bar
        self.status_bar = tk.Label(self.root, text="Status: Running", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#1e1e1e", fg="white")
        self.status_bar.pack(side="bottom", fill="x")

    def fetch_abuseipdb_report(self, ip):
        if not self.is_valid_ip(ip):
            return None
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Accept': 'application/json',
            'Key': ABUSEIPDB_API_KEY
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                return data
            else:
                logging.error(f"Error fetching AbuseIPDB report for {ip}: {response.status_code}")
                return None
        except Exception as e:
            logging.error(f"Exception fetching AbuseIPDB report for {ip}: {e}")
            return None

    def fetch_geoip_info(self, ip):
        if not self.is_valid_ip(ip):
            return "Unknown"
        url = "https://ip-geolocation-find-ip-location-and-ip-info.p.rapidapi.com/backend/ipinfo/"
        querystring = {"ip": ip}
        headers = {
            "X-RapidAPI-Key": RAPIDAPI_KEY,
            "X-RapidAPI-Host": RAPIDAPI_HOST
        }
        try:
            response = requests.get(url, headers=headers, params=querystring)
            if response.status_code == 200:
                data = response.json()
                country = data.get('country', 'Unknown')
                city = data.get('city', 'Unknown')
                return f"{city}, {country}"
            else:
                logging.error(f"Error fetching GeoIP info for {ip}: {response.status_code}")
                return "Unknown"
        except Exception as e:
            logging.error(f"Exception fetching GeoIP info for {ip}: {e}")
            return "Unknown"

    def fetch_gemini_analysis(self, src_ip, dst_ip, protocol, src_port, dst_port):
        if not self.is_valid_ip(src_ip) or not self.is_valid_ip(dst_ip):
            return "Invalid IP addresses"
        prompt = f"Analyze network traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port} over {protocol}. Limit to 70 words."
        headers = {
            'Content-Type': 'application/json'
        }
        data = {
            'contents': [
                {
                    'parts': [
                        {'text': prompt}
                    ]
                }
            ]
        }
        try:
            response = requests.post(f'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}', headers=headers, json=data)
            if response.status_code == 200:
                result = response.json()
                logging.info(f"Gemini API response: {result}")  # Log the full response for debugging
                if 'candidates' in result and 'content' in result['candidates'][0] and 'parts' in result['candidates'][0]['content'] and 'text' in result['candidates'][0]['content']['parts'][0]:
                    return result['candidates'][0]['content']['parts'][0]['text'].strip()
                else:
                    logging.error(f"Unexpected response structure: {result}")
                    return "Unexpected response structure"
            else:
                logging.error(f"Error fetching Gemini analysis: {response.status_code} - {response.text}")
                return "Analysis error"
        except Exception as e:
            logging.error(f"Exception fetching Gemini analysis: {e}")
            return "Analysis error"

    def analyze_packet(self, packet):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_ip = dst_ip = src_port = dst_port = "N/A"
            protocol = type_desc = "Unknown"

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = "TCP"
                if packet.haslayer(HTTPRequest):
                    protocol = "HTTP"
                    type_desc = "HTTP Packet"
                elif src_port == 21 or dst_port == 21:
                    protocol = "FTP"
                    type_desc = "FTP Packet"
                elif src_port == 22 or dst_port == 22:
                    protocol = "SSH"
                    type_desc = "SSH Packet"
                else:
                    type_desc = f"TCP Flags: {packet[TCP].sprintf('%TCP.flags%')}"

            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = "UDP"
                if packet.haslayer(DNS):
                    protocol = "DNS"
                    type_desc = "DNS Packet"
                else:
                    type_desc = "UDP Packet"

            elif ICMP in packet:
                protocol = "ICMP"
                type_desc = "ICMP Type: " + ("Echo Request" if packet[ICMP].type == 8 else "Other")

            elif ARP in packet:
                protocol = "ARP"
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
                type_desc = "ARP Packet"

            if self.is_valid_ip(src_ip) and src_ip not in WHITELIST:
                abuse_report = self.fetch_abuseipdb_report(src_ip)
                is_malicious = abuse_report and abuse_report.get('data', {}).get('abuseConfidenceScore', 0) > 50
                indicator = "Intruder" if is_malicious else "Safe"
                geoip = self.fetch_geoip_info(src_ip)
                analysis = self.fetch_gemini_analysis(src_ip, dst_ip, protocol, src_port, dst_port)
                color_tag = 'red' if is_malicious else 'green'

                packet_data = (timestamp, src_ip, dst_ip, type_desc, protocol, src_port, dst_port, analysis, indicator, geoip, color_tag)
                self.packet_queue.put(packet_data)

        except Exception as e:
            logging.error(f"Exception analyzing packet: {e}")

    def is_valid_ip(self, ip):
        parts = ip.split('.')
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def start_sniffing_thread(self):
        def packet_callback(packet):
            self.analyze_packet(packet)

        sniff_thread = threading.Thread(target=sniff, kwargs={'prn': packet_callback, 'store': 0}, daemon=True)
        sniff_thread.start()

    def start_update_thread(self):
        def update_tree():
            while True:
                try:
                    packet_data = self.packet_queue.get(timeout=1)
                    self.tree.insert("", "end", values=packet_data[:-1], tags=(packet_data[-1],))
                    self.tree.tag_configure('red', background='red')
                    self.tree.tag_configure('green', background='green')
                except queue.Empty:
                    continue

        threading.Thread(target=update_tree, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = IntrusionDetectionSystem(root)
    root.mainloop()

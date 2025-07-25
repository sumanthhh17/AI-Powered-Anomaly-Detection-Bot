from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
import datetime
import os
from slack_sdk import WebClient
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Load your trained model
model = joblib.load('anomaly_model.pkl')

# Slack notification setup
slack_token = os.getenv("SLACK_TOKEN")
slack_channel = os.getenv("SLACK_CHANNEL")
client = WebClient(token=slack_token) if slack_token else None

def extract_features(packet):
    """Extract features from a network packet for anomaly detection."""
    if IP in packet:
        pkt_size = len(packet)
        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
        proto = 6 if TCP in packet else (17 if UDP in packet else 0)
        return [pkt_size, src_port, dst_port, proto]
    return None


def alert_anomaly(features):
    """Handle anomaly alerting: print, log, and notify via Slack."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    msg = (
        f"[{timestamp}] 🚨 Anomaly detected! Features: {features}\n"
        "Suggested Action: Block source IP, check for malware, update firewall rules."
    )
    print(msg)
    # Log to file
    with open("anomaly_log.txt", "a") as f:
        f.write(msg + "\n")
    # Send Slack notification if client is set
    if client and slack_channel:
        try:
            client.chat_postMessage(channel=slack_channel, text=msg)
        except Exception as e:
            print(f"Failed to send Slack message: {e}")

def process_packet(packet):
    features = extract_features(packet)
    if features:
        try:
            features_arr = np.array(features).reshape(1, -1)
            pred = model.predict(features_arr)
            if pred[0] == -1:
                alert_anomaly(features)
        except Exception as e:
            print(f"Error processing packet: {e}")

print("Starting packet sniffing... Press Ctrl+C to stop.")
try:
    sniff(prn=process_packet, store=0)
except KeyboardInterrupt:
    print("Stopped packet sniffing.")

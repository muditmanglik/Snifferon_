# app.py
import sys
from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, get_if_addr
import threading
import datetime
import time
from collections import defaultdict, deque
import random  # For simulating confidence

# --- ML Imports ---
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.cluster import KMeans
import numpy as np

# Initialize the Flask app and SocketIO
app = Flask(__name__)
# Disable caching for development
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# --- Configuration ---
def get_active_interface():
    """Auto-detects the active network interface by matching the machine's outbound IP."""
    import socket
    from scapy.all import get_if_list, get_if_addr
    try:
        # Connect to external address to determine outbound IP (no data sent)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        for iface in get_if_list():
            try:
                if get_if_addr(iface) == local_ip:
                    print(f"[INFO] Auto-detected interface: {iface} (IP: {local_ip})")
                    return iface
            except Exception:
                continue
    except Exception as e:
        print(f"[WARN] Could not auto-detect interface: {e}")
    # Fallback
    fallback = get_if_list()[0] if get_if_list() else 'en0'
    print(f"[INFO] Falling back to interface: {fallback}")
    return fallback

INTERFACE = get_active_interface()

# --- Anomaly Detection Model Setup ---
ANOMALY_PACKET_BUFFER_SIZE = 1000 # Reduced from 5000 for faster model training
anomaly_packet_buffer = []
anomaly_model = None
anomaly_encoder = OneHotEncoder(handle_unknown='ignore')

# --- Clustering Model Setup ---
flow_data = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'start_time': time.time(), 'end_time': time.time(), 'protocols': set(), 'ports': set(), 'dest_ips': set()})
clustering_model = None
cluster_scaler = None
cluster_labels = {}
flow_to_cluster = {}

# --- Time Series Analysis Setup ---
TIME_WINDOW = 1800  # 30 minutes for baseline
packet_timestamps = deque()

# --- Heuristic Traffic Classification Setup ---
classification_counts = defaultdict(int)
classification_bytes = defaultdict(int)  # NEW: total bytes per class
CLASSIFICATION_LOG_INTERVAL = 1000 # Log class distribution every X packets
packet_count_since_last_log = 0

def train_anomaly_model():
    global anomaly_model, anomaly_encoder
    print(f"\n[ML] Collected {len(anomaly_packet_buffer)} packets. Training anomaly detection model...")
    df = pd.DataFrame(anomaly_packet_buffer)
    df.fillna(0, inplace=True)
    protocol_encoded = anomaly_encoder.fit_transform(df[['protocol']]).toarray()
    protocol_df = pd.DataFrame(protocol_encoded, columns=anomaly_encoder.get_feature_names_out(['protocol']))
    df_processed = pd.concat([df[['payload_size', 'sport', 'dport']].reset_index(drop=True), protocol_df], axis=1)
    anomaly_model = IsolationForest(contamination=0.01, random_state=42)
    anomaly_model.fit(df_processed)
    anomaly_model.feature_names_in_ = df_processed.columns.tolist()
    print("[ML] Anomaly detection model training complete. 👍")
    # Decoupled from clustering model training, which now runs periodically.

def train_clustering_model():
    """
    Trains the K-Means clustering model on aggregated flow data.
    """
    global clustering_model, cluster_scaler, cluster_labels
    
    socketio.emit('status_update', {'message': 'Training clustering model...'})
    print(f"\n[ML] Processing {len(flow_data)} flows for clustering model training...")
    if len(flow_data) < 5: # Lowered threshold from 50 to 5 for faster training
        print("[ML] Not enough flow data to train clustering model.")
        return

    flow_list = []
    for flow_key, data in flow_data.items():
        duration = data['end_time'] - data['start_time']
        if duration == 0: duration = 1
        flow_list.append({
            'flow_key': flow_key,
            'packet_rate': data['packets'] / duration,
            'byte_rate': data['bytes'] / duration,
            'avg_payload': data['bytes'] / data['packets'] if data['packets'] > 0 else 0,
            'protocol_diversity': len(data['protocols']),
            'unique_dest_ips': len(data['dest_ips'])
        })
    
    flow_df = pd.DataFrame(flow_list)
    features_to_scale = ['packet_rate', 'byte_rate', 'avg_payload', 'protocol_diversity', 'unique_dest_ips']
    cluster_scaler = StandardScaler()
    scaled_features = cluster_scaler.fit_transform(flow_df[features_to_scale])

    n_clusters = min(6, len(flow_df)) # Cannot have more clusters than samples
    clustering_model = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    flow_df['cluster'] = clustering_model.fit_predict(scaled_features)

    centroids = clustering_model.cluster_centers_
    for i in range(n_clusters):
        centroid = centroids[i]
        # Heuristic for labeling based on scaled centroid values
        if centroid[1] > 1.5: # High byte_rate
            if centroid[2] > 1.5: 
                label = "File Transfer / Bulk"
                description = "Sustained, high-volume data transfer."
            else: 
                label = "Streaming Media"
                description = "Consistent data flow, typical of video/audio."
        elif centroid[0] > 1.5 and centroid[2] < -0.5: # High packet_rate, low avg_payload
            label = "Gaming / Interactive"
            description = "Frequent, small packets for low-latency communication."
        elif centroid[4] > 1.0: # High unique_dest_ips
            label = "Scanning / Discovery"
            description = "Connecting to many different IPs, possibly scanning."
        elif centroid[0] < -0.5 and centroid[1] < -0.5: # Low everything
            label = "Background Services"
            description = "Low-intensity traffic, often for updates or syncs."
        else:
            label = "Web Browsing"
            description = "Bursty traffic with varied packet sizes."
        cluster_labels[i] = {'label': label, 'description': description}

    # Calculate distribution and average metrics for each cluster
    pattern_distribution = {}
    for i in range(n_clusters):
        cluster_flows = flow_df[flow_df['cluster'] == i]
        if not cluster_flows.empty:
            label_info = cluster_labels[i]
            percentage = (len(cluster_flows) / len(flow_df)) * 100
            avg_byte_rate = cluster_flows['byte_rate'].mean()
            
            pattern_distribution[label_info['label']] = {
                'percentage': round(percentage, 2),
                'description': label_info['description'],
                'avg_byte_rate': round(avg_byte_rate, 2) # Bytes/sec
            }

    for index, row in flow_df.iterrows():
        cluster_info = cluster_labels.get(row['cluster'])
        if cluster_info:
            flow_to_cluster[row['flow_key']] = cluster_info['label']

    print("[ML] Clustering model training complete. 👍")
    print("[ML] Detected Patterns:", pattern_distribution)
    socketio.emit('clustering_update', pattern_distribution)


def periodic_classification_updater():
    """
    Periodically calculates and emits the traffic classification distribution.
    """
    while True:
        time.sleep(10)
        if not classification_counts:
            continue

        total_packets = sum(classification_counts.values())
        total_bytes = sum(classification_bytes.values())
        if total_packets == 0 and total_bytes == 0:
            continue

        distribution = {}
        for cls, count in classification_counts.items():
            bytes_for_cls = classification_bytes.get(cls, 0)
            distribution[cls] = {
                'count': int(count),
                'count_pct': round((count / total_packets) * 100, 2) if total_packets > 0 else 0.0,
                'bytes': int(bytes_for_cls),
                'bytes_pct': round((bytes_for_cls / total_bytes) * 100, 2) if total_bytes > 0 else 0.0
            }

        socketio.emit('classification_update', distribution)


def periodic_clustering_trainer():
    """
    Periodically retrains the clustering model every 30 seconds.
    """
    while True:
        time.sleep(30)
        print("\n[ML] Triggering periodic clustering model update...")
        socketio.start_background_task(train_clustering_model)

def classify_traffic(packet_features, src_ip, dst_ip, flow_key):
    """
    Heuristically classifies traffic based on packet features and flow context.
    Returns (traffic_class, class_confidence).
    """
    protocol = packet_features['protocol']
    sport = packet_features['sport']
    dport = packet_features['dport']
    payload_size = packet_features['payload_size']

    traffic_class = "Normal"
    class_confidence = 0.7 # Default confidence

    # Rule 1: DNS traffic
    if protocol == 'DNS':
        traffic_class = "DNS Query/Response"
        class_confidence = 0.9
    # Rule 2: Web traffic
    elif protocol in ['HTTP', 'HTTPS']:
        traffic_class = "Web Browsing"
        class_confidence = 0.85
    # Rule 3: Streaming (high payload, common streaming ports)
    elif (protocol == 'UDP' and dport in [1935, 5000, 8000]) or (protocol == 'TCP' and dport in [1935, 5000, 8000] and payload_size > 1000):
        traffic_class = "Streaming"
        class_confidence = 0.8
    # Rule 4: Potential Port Scan (many unique destination ports from one source)
    elif flow_key in flow_data and flow_data[flow_key]['unique_dest_ips'] > 5 and flow_data[flow_key]['packets'] < 100:
        traffic_class = "Port Scan"
        class_confidence = 0.95
    # Rule 5: Large File Transfer (high payload size over sustained period - simplified)
    elif payload_size > 5000 and protocol == 'TCP':
        traffic_class = "File Transfer"
        class_confidence = 0.75
    # Rule 6: Background/System Services (low activity, specific ports)
    elif (sport in [5353, 1900] or dport in [5353, 1900]) and payload_size < 100:
        traffic_class = "Background Service"
        class_confidence = 0.6

    return traffic_class, class_confidence

def update_temporal_insights():
    last_rate = 0
    while True:
        now = time.time()
        while packet_timestamps and packet_timestamps[0] < now - TIME_WINDOW:
            packet_timestamps.popleft()

        one_minute_ago = now - 60
        current_packets = [ts for ts in packet_timestamps if ts > one_minute_ago]
        current_rate = len(current_packets)
        baseline_rate = len(packet_timestamps) / (TIME_WINDOW / 60)

        if current_rate > last_rate: trend = 'increasing'
        elif current_rate < last_rate: trend = 'decreasing'
        else: trend = 'stable'
        last_rate = current_rate

        socketio.emit('time_series_update', {
            'current_rate': current_rate,
            'baseline_rate': round(baseline_rate, 2),
            'trend': trend
        })
        time.sleep(5)

def packet_callback(packet):
    global anomaly_model, anomaly_packet_buffer, flow_data, clustering_model, packet_timestamps, packet_count_since_last_log
    try:
        if IP not in packet:
            return

        packet_timestamps.append(time.time())

        timestamp = datetime.datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')[:-3]
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        protocol, qname, sport, dport = "Unknown", None, None, None
        payload_size = len(packet.payload)

        if TCP in packet:
            sport, dport, payload_size, protocol = packet[TCP].sport, packet[TCP].dport, len(packet[TCP].payload), 'TCP'
            if dport == 443 or sport == 443: protocol = 'HTTPS'
            elif dport == 80 or sport == 80: protocol = 'HTTP'
        elif UDP in packet:
            sport, dport, payload_size, protocol = packet[UDP].sport, packet[UDP].dport, len(packet[UDP].payload), 'UDP'
            if DNS in packet:
                protocol = 'DNS'
                if packet[DNS].qr == 0 and packet[DNS].qd: qname = packet[DNS].qd.qname.decode().rstrip('.')
                elif packet[DNS].qr == 1 and packet[DNS].an: qname = packet[DNS].qd.qname.decode().rstrip('.')
        elif ICMP in packet:
            protocol = 'ICMP'

        packet_features = {'protocol': protocol, 'payload_size': payload_size, 'sport': sport, 'dport': dport}
        
        # Anomaly Detection
        is_anomaly = False
        if anomaly_model:
            df_live = pd.DataFrame([packet_features])
            df_live.fillna(0, inplace=True)
            protocol_encoded_live = anomaly_encoder.transform(df_live[['protocol']]).toarray()
            protocol_df_live = pd.DataFrame(protocol_encoded_live, columns=anomaly_encoder.get_feature_names_out(['protocol']))
            df_live_processed = pd.concat([df_live[['payload_size', 'sport', 'dport']].reset_index(drop=True), protocol_df_live], axis=1)
            X_live = df_live_processed.reindex(columns=anomaly_model.feature_names_in_, fill_value=0)
            prediction = anomaly_model.predict(X_live)
            is_anomaly = True if prediction[0] == -1 else False
        elif len(anomaly_packet_buffer) < ANOMALY_PACKET_BUFFER_SIZE:
            anomaly_packet_buffer.append(packet_features)
            socketio.emit('buffer_update', {'count': len(anomaly_packet_buffer), 'total': ANOMALY_PACKET_BUFFER_SIZE})
            if len(anomaly_packet_buffer) == ANOMALY_PACKET_BUFFER_SIZE:
                socketio.emit('status_update', {'message': 'Buffer full. Starting model training...'})
                socketio.start_background_task(train_anomaly_model)

        # Clustering / Flow Analysis
        flow_key = tuple(sorted((src_ip, dst_ip)))
        flow_data[flow_key]['packets'] += 1
        flow_data[flow_key]['bytes'] += payload_size
        flow_data[flow_key]['end_time'] = time.time()
        flow_data[flow_key]['protocols'].add(protocol)
        if sport: flow_data[flow_key]['ports'].add(sport)
        if dport: flow_data[flow_key]['ports'].add(dport)
        flow_data[flow_key]['dest_ips'].add(dst_ip) # For port scan detection

        traffic_pattern = "Unknown"
        if clustering_model: traffic_pattern = flow_to_cluster.get(flow_key, "Learning...")

        # Heuristic Traffic Classification
        traffic_class, class_confidence = classify_traffic(packet_features, src_ip, dst_ip, flow_key)
        
        if traffic_class:
            classification_counts[traffic_class] += 1
            classification_bytes[traffic_class] += payload_size

        packet_count_since_last_log += 1
        if packet_count_since_last_log >= CLASSIFICATION_LOG_INTERVAL:
            print("\n[ML] Traffic Class Distribution:")
            total_classified = sum(classification_counts.values())
            for cls, count in classification_counts.items():
                print(f"  - {cls}: {count} packets ({count/total_classified:.2%})")
            packet_count_since_last_log = 0
            classification_counts.clear()

        data = { 'timestamp': timestamp, 'source': src_ip, 'target': dst_ip, 'protocol': protocol, 'sport': sport, 'dport': dport, 'payload_size': payload_size, 'is_anomaly': is_anomaly, 'traffic_pattern': traffic_pattern, 'traffic_class': traffic_class, 'class_confidence': round(class_confidence * 100) }
        if qname: data['domain'] = qname

        socketio.emit('network_data', data)

    except Exception as e:
        pass

def run_sniffer(stop_event):
    """
    This function runs the Scapy sniffer.
    """
    print("-" * 50)
    print(f"Starting Scapy sniffer on interface '{INTERFACE}'...")
    print(f"Applying filter: None (capturing all traffic)")
    print("NOTE: You will likely need to run this with 'sudo' for it to work.")
    print("-" * 50)
    try:
        # The sniff function captures packets and calls the packet_callback function for each one.
        sniff(iface=INTERFACE, store=False, prn=packet_callback, stop_filter=lambda p: stop_event.is_set())
    except OSError as e:
        print(f"\n[ERROR] Scapy could not access the interface '{INTERFACE}'.")
        print("Please ensure it is correct and that you are running the script with root privileges (e.g., 'sudo python3 app.py').")
        print(f"Details: {e}")
    except Exception as e:
        print(f"\n[CRITICAL SNIFFER ERROR] {e}")

@socketio.on('connect')
def handle_connect():
    try:
        local_ip = get_if_addr(INTERFACE)
        socketio.emit('init', {'ip': local_ip})
        print(f"Client connected. Sent local IP: {local_ip}")
    except Exception as e:
        print(f"Could not determine local IP for {INTERFACE}: {e}")

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    stop_sniffing = threading.Event()
    sniffer_thread = threading.Thread(target=run_sniffer, args=(stop_sniffing,))
    sniffer_thread.daemon = True
    sniffer_thread.start()
    socketio.start_background_task(update_temporal_insights)
    socketio.start_background_task(periodic_clustering_trainer)
    socketio.start_background_task(periodic_classification_updater)
    print("Starting Flask-SocketIO server on http://127.0.0.1:5001")
    socketio.run(app, host='127.0.0.1', port=5001, allow_unsafe_werkzeug=True)
    print("\nServer shutting down. Stopping sniffer...")
    stop_sniffing.set()
    sniffer_thread.join()
    print("Sniffer stopped. Goodbye.")
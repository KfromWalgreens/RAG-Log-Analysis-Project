import os
import json
import csv
from collections import defaultdict
from datetime import datetime

# Load IPs from the anomaly CSV that are linked to heuristic "20"
def load_anomalous_ips(csv_path):
    ip_set = set()
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("heuristic") != "20":
                continue
            if row["srcIP"] and row["srcIP"].lower() != "none":
                ip_set.add(row["srcIP"])
            if row["dstIP"] and row["dstIP"].lower() != "none":
                ip_set.add(row["dstIP"])
    return ip_set

# Parse Zeek conn.log file into a list of relevant connection entries
def parse_zeek_conn_log(file_path):
    entries = []
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#") or not line.strip():  # Skip headers and empty lines
                continue
            fields = line.strip().split('\t')
            if len(fields) < 22:
                continue
            entry = {
                "ts": float(fields[0]),      # timestamp
                "src_ip": fields[2],         # source IP
                "dst_ip": fields[4],         # destination IP
                "dst_port": fields[5],       # destination port
                "proto": fields[6],          # protocol (e.g., TCP, ICMP)
            }
            entries.append(entry)
    return entries

# Convert UNIX timestamp to human-readable format
def to_readable(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

# Detect ICMP ping flood patterns in conn.log entries
def detect_ping_flood(entries, threshold=5, time_window=5):
    # Filter for ICMP echo requests (type 8)
    icmp_echoes = [e for e in entries if e['proto'] == 'icmp' and e['dst_port'] == '8']
    icmp_echoes.sort(key=lambda x: x['ts'])

    floods = {
        "many_to_one": [],  # many different src_ips to one dst_ip
        "one_to_many": []   # one src_ip to many different dst_ips
    }

    # Detect many-to-one pattern
    dst_groups = defaultdict(list)
    for e in icmp_echoes:
        dst_groups[e['dst_ip']].append(e)

    for dst_ip, packets in dst_groups.items():
        start_idx = 0
        for end_idx in range(len(packets)):
            while packets[end_idx]['ts'] - packets[start_idx]['ts'] > time_window:
                start_idx += 1
            window = packets[start_idx:end_idx+1]
            src_ips = set(p['src_ip'] for p in window)
            if len(window) >= threshold and len(src_ips) >= 3:
                floods["many_to_one"].append({
                    "type": "many_to_one",
                    "dst_ip": dst_ip,
                    "unique_src_ips": list(src_ips),
                    "src_ip_count": len(src_ips),
                    "packet_count": len(window),
                    "start_time": to_readable(window[0]['ts']),
                    "end_time": to_readable(window[-1]['ts'])
                })
                break  # Stop after first match for this IP

    # Detect one-to-many pattern
    src_groups = defaultdict(list)
    for e in icmp_echoes:
        src_groups[e['src_ip']].append(e)

    for src_ip, packets in src_groups.items():
        start_idx = 0
        for end_idx in range(len(packets)):
            while packets[end_idx]['ts'] - packets[start_idx]['ts'] > time_window:
                start_idx += 1
            window = packets[start_idx:end_idx+1]
            dst_ips = set(p['dst_ip'] for p in window)
            if len(window) >= threshold and len(dst_ips) >= 3:
                floods["one_to_many"].append({
                    "type": "one_to_many",
                    "src_ip": src_ip,
                    "unique_dst_ips": list(dst_ips),
                    "dst_ip_count": len(dst_ips),
                    "packet_count": len(window),
                    "start_time": to_readable(window[0]['ts']),
                    "end_time": to_readable(window[-1]['ts'])
                })
                break  # Stop after first match for this IP

    return floods

# Main labeling function that processes all log files in a directory
def label_logs_in_directory(input_folder, anomaly_csv=None, output_file="ping_flood_labels.json", threshold=5, time_window=5):
    anomaly_ips = load_anomalous_ips(anomaly_csv) if anomaly_csv else set()
    results = {}

    for fname in os.listdir(input_folder):
        if not fname.endswith(".log"):
            continue
        fpath = os.path.join(input_folder, fname)
        try:
            entries = parse_zeek_conn_log(fpath)
            floods = detect_ping_flood(entries, threshold=threshold, time_window=time_window)

            matched_ips = set()
            for entry in entries:
                if entry["proto"] != "icmp":
                    continue
                if entry["src_ip"] in anomaly_ips:
                    matched_ips.add(entry["src_ip"])
                if entry["dst_ip"] in anomaly_ips:
                    matched_ips.add(entry["dst_ip"])
            ip_match = bool(matched_ips)

            reason = []
            if floods["many_to_one"]:
                reason.append("many-to-one pattern")
            if floods["one_to_many"]:
                reason.append("one-to-many pattern")
            if ip_match:
                reason.append("anomalous IP with heuristic 20")

            detected = bool(reason)

            # Save results for this file
            results[fname] = {
                "ping_flood_detected": detected,
                "num_floods": len(floods["many_to_one"]) + len(floods["one_to_many"]),
                "flood_details": floods,
                "anomaly_ip_match": ip_match,
                "detection_reason": reason,
                "flagged_ips": list(matched_ips)
            }

            # Print summary to console
            if detected:
                flagged_str = ", ".join(matched_ips) if matched_ips else "None"
                print(f"Processed {fname} - Ping Flood: YES ({', '.join(reason)}) - Flagged IPs: {flagged_str}")
            else:
                print(f"Processed {fname} - Ping Flood: NO")
        except Exception as e:
            print(f"Error processing {fname}: {e}")
            results[fname] = {"error": str(e)}

    # Save all detection results to JSON
    output_path = os.path.join(input_folder, output_file)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved labels to {output_path}")

# Run the script on a specified folder and anomaly file
if __name__ == "__main__":
    log_folder = "C:/Users/Keek Windows/PyCharmMiscProject/fc110split"
    anomaly_csv_path = "C:/Users/Keek Windows/Downloads/20220110_anomalous_suspicious - 20220110_anomalous_suspicious1.csv"
    label_logs_in_directory(log_folder, anomaly_csv=anomaly_csv_path)

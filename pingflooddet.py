from collections import defaultdict
from datetime import datetime

from chromadb import PersistentClient
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction


def parse_zeek_conn_log(file_path):
    entries = []
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue  # Skip header/comments/empty lines
            fields = line.strip().split('\t')
            if len(fields) < 22:
                continue  # Malformed line
            entry = {
                "ts": float(fields[0]),
                "src_ip": fields[2],
                "dst_ip": fields[4],
                "dst_port": fields[5],
                "proto": fields[6],
            }
            entries.append(entry)
    return entries


def detect_ping_flood(entries, threshold=5, time_window=5):
    """
    Detect ping floods:
    - ICMP echo requests (proto='icmp', dst_port='8')
    - Threshold = number of pings within time_window (seconds)
    """
    icmp_echoes = [e for e in entries if e['proto'] == 'icmp' and e['dst_port'] == '8']
    icmp_echoes.sort(key=lambda x: x['ts'])

    suspicious = []
    dst_ip_times = defaultdict(list)
    for e in icmp_echoes:
        dst_ip_times[e['dst_ip']].append(e['ts'])

    for dst_ip, times in dst_ip_times.items():
        start_idx = 0
        for end_idx in range(len(times)):
            while times[end_idx] - times[start_idx] > time_window:
                start_idx += 1
            window_count = end_idx - start_idx + 1
            if window_count >= threshold:
                suspicious.append({
                    "dst_ip": dst_ip,
                    "start_time": times[start_idx],
                    "end_time": times[end_idx],
                    "count": window_count
                })
                break
    return suspicious


def count_icmp_echo_requests(entries):
    counts = defaultdict(int)
    for e in entries:
        if e['proto'] == 'icmp' and e['dst_port'] == '8':
            counts[e['dst_ip']] += 1
    return counts


def to_readable(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def format_ping_flood_doc(pf, total_count):
    start = to_readable(pf['start_time'])
    end = to_readable(pf['end_time'])
    dst_ip = pf['dst_ip']
    return (
        f"Ping flood detected targeting destination IP {dst_ip}. "
        f"{total_count} ICMP Echo Requests received between {start} and {end}."
    )


def ingest_ping_floods_to_chroma(ping_floods, icmp_counts, collection):
    for idx, pf in enumerate(ping_floods):
        dst_ip = pf['dst_ip']
        total_count = icmp_counts.get(dst_ip, pf['count'])
        doc = format_ping_flood_doc(pf, total_count)
        metadata = {
            "dst_ip": dst_ip,
            "start_time": pf['start_time'],
            "end_time": pf['end_time'],
            "count_in_window": pf['count'],
            "total_icmp_requests": total_count
        }
        collection.upsert(
            documents=[doc],
            metadatas=[metadata],
            ids=[f"ping_flood_{idx}"]
        )


if __name__ == "__main__":
    zeek_file = "/Users/Keek Windows/zeek_analysis/filtered_conn110.log"
    entries = parse_zeek_conn_log(zeek_file)

    threshold = 5
    time_window = 5
    ping_floods = detect_ping_flood(entries, threshold=threshold, time_window=time_window)
    icmp_counts = count_icmp_echo_requests(entries)

    if not ping_floods:
        print("No ping floods detected.")
    else:
        print("Ping floods detected with ICMP Echo Request counts:\n")
        for pf in ping_floods:
            dst_ip = pf['dst_ip']
            total_count = icmp_counts.get(dst_ip, 0)
            start_time = to_readable(pf['start_time'])
            end_time = to_readable(pf['end_time'])
            print(f"- Destination IP {dst_ip} received {total_count} ICMP echo requests "
                  f"from {start_time} to {end_time}.")

        # Initialize embedding model
        embedding_model = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")

        # Connect to ChromaDB and get collection
        chroma_client = PersistentClient(path="./chroma_db")
        collection = chroma_client.get_or_create_collection(
            name="ping_flood_alerts2",
            embedding_function=embedding_model
        )

        # Ingest to Chroma
        ingest_ping_floods_to_chroma(ping_floods, icmp_counts, collection)
        print(f"\nIngested {len(ping_floods)} ping flood alerts into ChromaDB.")

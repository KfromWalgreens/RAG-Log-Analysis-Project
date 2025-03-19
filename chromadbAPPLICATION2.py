import chromadb
from scapy.all import rdpcap, IP, TCP, UDP
from sentence_transformers import SentenceTransformer
from collections import defaultdict

# Initialize ChromaDB (Persistent Storage)
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="network_logs2")

# Load Sentence Transformer for Embeddings
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

# PCAP File
PCAP_FILE = "/Users/kennedymarsh/Desktop/test1.pcap"

# Step 1: Extract Features and Chunk by Time

def extract_and_chunk_by_time(pcap_file, packet_limit=50):
    packets = rdpcap(pcap_file, count=packet_limit)  # Read first x packets
    time_logs = defaultdict(list)  # 
    
    for pkt in packets:
        print(pkt.summary())
        try:
            if IP in pkt:
                timestamp = round(pkt.time)  
                time_bucket = timestamp // 5  # Group packets into 10-second intervals
                protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
                
                # Extract additional details
                if TCP in pkt:
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    flags = pkt[TCP].flags
                    seq = pkt[TCP].seq
                    ack = pkt[TCP].ack
                    win_size = pkt[TCP].window
                    ts_val = pkt[TCP].options[0][1] if pkt[TCP].options and pkt[TCP].options[0][0] == 'Timestamp' else None
                    ts_ecr = pkt[TCP].options[1][1] if pkt[TCP].options and len(pkt[TCP].options) > 1 and pkt[TCP].options[1][0] == 'Timestamp' else None
                    extra_info = (f"SrcPort: {src_port}, DstPort: {dst_port}, Flags: {flags}, Seq: {seq}, Ack: {ack}, "
                                  f"WinSize: {win_size}, TSval: {ts_val}, TSecr: {ts_ecr}")
                    
                    # Check for HTTP/HTTPS traffic
                    if hasattr(pkt, 'http'):
                        http_method = pkt.http.get('request_method', 'N/A')
                        http_uri = pkt.http.get('request_uri', 'N/A')
                        http_host = pkt.http.get('host', 'N/A')
                        extra_info += f", HTTP Method: {http_method}, URI: {http_uri}, Host: {http_host}"
                        
                        
                elif UDP in pkt:
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    length = pkt[UDP].len
                    extra_info = f"SrcPort: {src_port}, DstPort: {dst_port}, Length: {length}"
                else:
                    extra_info = "No TCP/UDP details"
                
                log_entry = (f"At {pkt.time:.6f}, {pkt[IP].src} → {pkt[IP].dst} using {protocol}, "
                             f"size: {len(pkt)} bytes. {extra_info}")
                time_logs[time_bucket].append(log_entry)
        except AttributeError:
            continue  # Skip packets without necessary fields
    
    # Print the grouped logs
    #print("Grouped Logs by Time Window:")
    #for time_bucket, logs in time_logs.items():
        #print(f"{time_bucket * 10}s to {(time_bucket + 1) * 10}s: {logs}")
    
    return time_logs

# Step 2: Generate Embeddings based on Time Chunks

def embed_time_chunks(time_logs):
    chunked_logs = []
    
    for time_bucket, logs in time_logs.items():
        start_time = time_bucket * 5
        end_time = (time_bucket + 1) * 5
        chunk_text = f"Logs ({start_time}-{end_time}s):\n" + "\n".join(logs)
        chunked_logs.append(chunk_text)
    
    embeddings = [embedding_model.encode(chunk).tolist() for chunk in chunked_logs]
    
    print(f"Generated {len(chunked_logs)} chunks")
    return chunked_logs, embeddings

# Step 3: Store Logs in ChromaDB

def store_in_chromadb(logs, embeddings):
    if not logs:
        print("No logs to store.")
        return
    
    ids = [str(i) for i in range(len(logs))]
    collection.add(ids=ids, documents=logs, embeddings=embeddings)
    print(f"Stored {len(logs)} logs in ChromaDB.")

# Run the Process
chunked_logs_by_time = extract_and_chunk_by_time(PCAP_FILE, packet_limit=50)
logs_to_store, embeddings_to_store = embed_time_chunks(chunked_logs_by_time)
store_in_chromadb(logs_to_store, embeddings_to_store)

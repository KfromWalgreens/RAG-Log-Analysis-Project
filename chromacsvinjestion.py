import chromadb
import pandas as pd
from sentence_transformers import SentenceTransformer
import os

# === Initialize ChromaDB ===
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection_csv = chroma_client.get_or_create_collection(name="anomaly_csv_logs4")

# === Embedding Model ===
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

# === File Path ===
CSV_PATH = "/Users/Keek Windows/Downloads/20220110_anomalous_suspicious - 20220110_anomalous_suspicious1.csv"

# === Load and Summarize Anomaly CSV (Per Row) ===
def load_logs_from_csv(file_path):
    df = pd.read_csv(file_path).fillna("unknown")
    summaries = []
    ids = []

    for idx, row in df.iterrows():
        src_ip = row.get("srcIP", "unknown")
        src_port = row.get("srcPort", "unknown")
        dst_ip = row.get("dstIP", "unknown")
        dst_port = row.get("dstPort", "unknown")
        taxonomy = row.get("taxonomy", "unknown")
        heuristic = row.get("heuristic", "unknown")
        label = row.get("label", "unknown")

        summary = (
            f"Anomaly ID anomaly_{idx}: A {label} connection was detected from source IP {src_ip} "
            f"on port {src_port} to destination IP {dst_ip} on port {dst_port}. "
            f"This anomaly is categorized as '{taxonomy}' based on heuristic {heuristic}."
        )

        summaries.append(summary)
        ids.append(f"anomaly_{idx}")  # use unique ID

    return summaries, ids

# === Ingest Anomaly CSV into ChromaDB ===
def ingest_csv_to_chromadb(file_path, collection):
    summaries, ids = load_logs_from_csv(file_path)
    embeddings = embedding_model.encode(summaries).tolist()

    existing = collection.get(ids=ids)
    if existing["ids"]:
        collection.delete(ids=existing["ids"])
        print(f"Deleted {len(existing['ids'])} existing anomaly rows.")

    collection.add(documents=summaries, embeddings=embeddings, ids=ids)
    print(f"Ingested {len(summaries)} anomalies into '{collection.name}'.")

    # Print collection contents
    full_collection = collection.get()
    print("\nCollection Contents:")
    for i, doc in enumerate(full_collection["documents"]):
        print(f"{full_collection['ids'][i]}: {doc}")

# === Run Ingestion ===
ingest_csv_to_chromadb(CSV_PATH, collection_csv)

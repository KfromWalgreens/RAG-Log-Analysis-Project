# Ingest anomaly CSV data into ChromaDB with sentence-transformer embeddings
import chromadb
import pandas as pd
from sentence_transformers import SentenceTransformer
import os

# Initialize a persistent Chroma client database
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# Create or load a collection to store the anomaly CSV logs
collection_csv = chroma_client.get_or_create_collection(name="anomaly_csv_logs4")

# Load the embedding model from HuggingFace's sentence-transformers
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

# Define path to the anomaly CSV file
CSV_PATH = "/Users/Keek Windows/Downloads/20220110_anomalous_suspicious - 20220110_anomalous_suspicious1.csv"

# Read CSV data, build natural-language summaries, and return them with unique IDs
def load_logs_from_csv(file_path):
    # Load CSV into a pandas DataFrame and fill missing fields with 'unknown'
    df = pd.read_csv(file_path).fillna("unknown")
    summaries = []
    ids = []

    # Iterate through each row in the CSV to construct summaries
    for idx, row in df.iterrows():
        src_ip = row.get("srcIP", "unknown")
        src_port = row.get("srcPort", "unknown")
        dst_ip = row.get("dstIP", "unknown")
        dst_port = row.get("dstPort", "unknown")
        taxonomy = row.get("taxonomy", "unknown")
        heuristic = row.get("heuristic", "unknown")
        label = row.get("label", "unknown")

        # Build a human-readable summary string for each row
        summary = (
            f"Anomaly ID anomaly_{idx}: A {label} connection was detected from source IP {src_ip} "
            f"on port {src_port} to destination IP {dst_ip} on port {dst_port}. "
            f"This anomaly is categorized as '{taxonomy}' based on heuristic {heuristic}."
        )

        summaries.append(summary)
        ids.append(f"anomaly_{idx}")  # Use a unique ID for each entry

    return summaries, ids

# Ingests the summaries and embeddings into ChromaDB
def ingest_csv_to_chromadb(file_path, collection):
    # Generate summaries and their corresponding IDs
    summaries, ids = load_logs_from_csv(file_path)

    # Generate vector embeddings for each summary using the sentence-transformer
    embeddings = embedding_model.encode(summaries).tolist()

    # Check for and delete existing documents with the same IDs
    existing = collection.get(ids=ids)
    if existing["ids"]:
        collection.delete(ids=existing["ids"])
        print(f"Deleted {len(existing['ids'])} existing anomaly rows.")

    # Add the new summaries, embeddings, and IDs to the Chroma collection
    collection.add(documents=summaries, embeddings=embeddings, ids=ids)
    print(f"Ingested {len(summaries)} anomalies into '{collection.name}'.")

    # Print all documents currently in the collection for verification
    full_collection = collection.get()
    print("\nCollection Contents:")
    for i, doc in enumerate(full_collection["documents"]):
        print(f"{full_collection['ids'][i]}: {doc}")

# Run the ingestion process
ingest_csv_to_chromadb(CSV_PATH, collection_csv)

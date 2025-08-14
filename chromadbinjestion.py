# Loads anomaly CSV logs, converts them into descriptive text summaries with
# unique IDs, embeds them using a sentence-transformer,
# and stores them in a persistent ChromaDB collection for later retrieval

import chromadb
import pandas as pd
from sentence_transformers import SentenceTransformer
import os
import re

# Initialize a persistent Chroma client database
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# Create or load a collection to store the anomaly CSV logs
collection_csv = chroma_client.get_or_create_collection(name="anomaly_csv_logsc01")

# Load the embedding model from HuggingFace's sentence-transformers
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")


def make_unique_ids(new_ids, existing_ids_set):
    unique_ids = []
    for _id in new_ids:
        candidate = _id
        suffix = 1
        while candidate in existing_ids_set:
            candidate = f"{_id}{suffix}"
            suffix += 1
        unique_ids.append(candidate)
        existing_ids_set.add(candidate)
    return unique_ids


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
        ids.append(f"anomaly_{idx}")

    return summaries, ids


def ingest_csv_to_chromadb(file_path, collection):
    print(f"\nStarting ingestion for file: {file_path}")
    summaries, ids = load_logs_from_csv(file_path)
    print(f"Loaded {len(summaries)} rows from CSV.")

    # Get all existing IDs from collection to avoid collisions
    all_existing = collection.get()
    existing_ids = set(all_existing["ids"])

    # Adjust new IDs to avoid collisions
    unique_ids = make_unique_ids(ids, existing_ids)

    # Update summaries to reflect the unique IDs instead of the original idx-based IDs
    updated_summaries = []
    for original_summary, unique_id in zip(summaries, unique_ids):
        # Replace first occurrence of anomaly_<num> (and optional suffix) with unique_id
        updated_summary = re.sub(r"anomaly_\d+(_\d+)*", unique_id, original_summary, count=1)
        updated_summaries.append(updated_summary)

    embeddings = embedding_model.encode(updated_summaries).tolist()

    try:
        collection.add(documents=updated_summaries, embeddings=embeddings, ids=unique_ids)
        print(f"Ingested {len(updated_summaries)} anomalies with unique IDs into '{collection.name}'.")
    except Exception as e:
        print("ChromaDB add failed:", e)
        print(f"Trying to add {len(updated_summaries)} items")

    # Print all docs in collection for verification
    full_collection = collection.get()
    print("\nCollection Contents:")
    for i, doc in enumerate(full_collection["documents"]):
        print(f"{full_collection['ids'][i]}: {doc}")

    # Print total number of entries in the collection after ingestion
    print(f"\n Total entries in collection '{collection.name}': {len(full_collection['ids'])}")


# Example usage: ingest multiple CSV files manually by adding paths here
csv_files_to_ingest = [
    # "C:/Users/Keek Windows/Downloads/20220110_anomalous_suspicious - 20220110_anomalous_suspicious1.csv",
    # "C:/Users/Keek Windows/Downloads/20220109_anomalous_suspicious - 20220109_anomalous_suspicious.csv",
    "C:/Users/Keek Windows/Downloads/20220101_anomalous_suspicious - 20220101_anomalous_suspicious.csv"
]

for csv_path in csv_files_to_ingest:
    ingest_csv_to_chromadb(csv_path, collection_csv)


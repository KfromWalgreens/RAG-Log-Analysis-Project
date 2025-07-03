# import chromadb
# from chromadb.config import Settings
#
# # === CONFIGURATION ===
# collection_name = "anomaly_csv_logs"
# confirm = True  # Set to False to skip confirmation prompt
#
# # === SETUP ===
# client = chromadb.Client(Settings(anonymized_telemetry=False))
# collection_names = [c.name for c in client.list_collections()]
#
# # === DELETE LOGIC ===
# if collection_name not in collection_names:
#     print(f"Collection '{collection_name}' does not exist.")
# else:
#     if confirm:
#         response = input(f"Are you sure you want to delete '{collection_name}'? [y/N]: ").lower()
#         if response != 'y':
#             print("Deletion canceled.")
#             exit(0)
#
#     client.delete_collection(name=collection_name)
#     print(f"Collection '{collection_name}' has been deleted.")



import chromadb

# Connect to existing ChromaDB and collections
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection_conn = chroma_client.get_collection(name="zeek_conn_logs")
collection_csv = chroma_client.get_collection(name="anomaly_csv_logs3")
collection_txt = chroma_client.get_collection(name="heuristic_info_txt")
collection_ping = chroma_client.get_collection(name="ping_flood_alerts")

def print_collection_samples(collection, sample_size=3):
    results = collection.get(limit=sample_size)
    documents = results.get("documents", [])
    ids = results.get("ids", [])
    print(f"\n--- Sample documents from collection '{collection.name}' ---")
    for i, doc in enumerate(documents):
        print(f"ID: {ids[i]}")
        # print(doc[:500])  # first 500 chars
        print(doc)
        print("-----")

if __name__ == "__main__":
    #print_collection_samples(collection_conn)
    # print_collection_samples(collection_csv)
    # print_collection_samples(collection_txt)
    print_collection_samples(collection_ping)

#injest heuristic info into chroma

import os
import re
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Chroma

#Initialize ChromaDB and Embeddings
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
heuristic_txt_store4 = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="heuristic_info_txt4"
)

#Ingestion Function
def ingest_heuristics_and_taxonomy(file_path, chroma_collection):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    #Heuristic Entries
    heuristic_section = content.split("Anomaly taxonomy")[0]
    heuristic_entries = re.findall(r"\* (\d+):(.+)", heuristic_section)

    print(f"Ingesting {len(heuristic_entries)} heuristic entries...")

    for code, label in heuristic_entries:
        code_int = int(code)
        if code_int < 500:
            desc = "Suspicious traffic: abnormal TCP flags or well-known malware ports."
        elif 500 <= code_int < 900:
            desc = "Normal protocol traffic seen on well-known ports."
        else:
            desc = "Traffic anomaly observed on unknown or uncommon ports."

        doc_text = (
            f"Heuristic ID: {code}\n"
            f"Label: {label.strip()}\n"
            f"Category: {desc}"
        )

        chroma_collection.add_texts(
            [doc_text],
            metadatas=[{"type": "heuristic", "id": code}]
        )

    #Taxonomy Group Prefixes
    taxonomy_groups = {
        "Unknown": ["unk", "empty"],
        "Other": ["ttl_error", "hostout", "netout", "icmp_error"],
        "HTTP": ["alphflHTTP", "ptmpHTTP", "mptpHTTP", "ptmplaHTTP", "mptplaHTTP"],
        "MultiPoints": ["ptmp", "mptp", "mptmp"],
        "AlphaFlow": ["alphfl", "malphfl", "salphfl", "point_to_point", "heavy_hitter"],
        "IPv6Tunneling": ["ipv4gretun", "ipv46tun"],
        "PortScan": ["posca", "ptpposca"],
        "NetworkScanICMP": ["ntscIC", "dntscIC"],
        "NetworkScanUDP": ["ntscUDP", "ptpposcaUDP"],
        "NetworkScanTCP": [
            "ntscACK", "ntscSYN", "sntscSYN", "ntscTCP", "ntscnull", "ntscXmas", "ntscFIN", "dntscSYN"
        ],
        "DoS": ["DoS", "distributed_dos", "ptpDoS", "sptpDoS", "DDoS", "rflat"],
    }

    print(f"Ingesting {len(taxonomy_groups)} taxonomy group entries...")

    for category, prefixes in taxonomy_groups.items():
        doc_text = f"Category: {category}\nPrefixes: {', '.join(prefixes)}"
        chroma_collection.add_texts(
            [doc_text],
            metadatas=[{"type": "taxonomy_group", "category": category, "prefixes": ", ".join(prefixes)}]
        )

    print("Ingestion complete.\n")

    #Print all stored content
    print("🔍 All stored documents in 'heuristic_info_txt4':\n")
    results = chroma_collection.get()
    for i, doc in enumerate(results["documents"]):
        print(f"--- Document {i+1} ---")
        print(doc)
        print()


#Run Script
if __name__ == "__main__":
    file_path = "C:/Users/Keek Windows/Downloads/csv info.txt"
    ingest_heuristics_and_taxonomy(file_path, heuristic_txt_store4)

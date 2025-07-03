# import pandas as pd
# from io import StringIO
# import os
#
# # === Config ===
# CONN_LOG_PATH = "/Users/Keek Windows/zeek_analysis/jan102022/conn.log"
# ANOMALY_CSV_PATH = "/Users/Keek Windows/Downloads/20220110_anomalous_suspicious - 20220110_anomalous_suspicious.csv"
# OUTPUT_PATH = "/Users/Keek Windows/zeek_analysis/filtered_conn.log"
# CHUNK_SIZE = 100_000  # Tune based on available RAM
#
# # === Load anomaly rules from CSV ===
# def load_anomaly_rules(path):
#     df = pd.read_csv(path).fillna("None").astype(str)
#     rules = []
#     for _, row in df.iterrows():
#         rules.append({
#             "srcIP": row["srcIP"],
#             "srcPort": row["srcPort"],
#             "dstIP": row["dstIP"],
#             "dstPort": row["dstPort"]
#         })
#     return rules
#
# # === Check if connection row matches any anomaly rule ===
# def conn_matches_any_rule(row, rules):
#     for rule in rules:
#         if (
#             (rule["srcIP"] == "None" or row["id.orig_h"] == rule["srcIP"]) and
#             (rule["dstIP"] == "None" or row["id.resp_h"] == rule["dstIP"]) and
#             (rule["srcPort"] == "None" or str(row["id.orig_p"]) == rule["srcPort"]) and
#             (rule["dstPort"] == "None" or str(row["id.resp_p"]) == rule["dstPort"])
#         ):
#             return True
#     return False
#
# # === Generator to stream cleaned conn.log lines ===
# def stream_conn_log_lines(file_path):
#     with open(file_path, "r", encoding="utf-8") as f:
#         for line in f:
#             if not line.startswith("#"):
#                 yield line
#
# # === Process conn.log in chunks directly from the file stream ===
# def process_conn_log(conn_path, rules, output_path):
#     print("🔁 Processing in chunks...")
#
#     # Read the first non-comment line with '#fields' to get header
#     header = None
#     with open(conn_path, "r", encoding="utf-8") as f:
#         for line in f:
#             if line.startswith("#fields"):
#                 header = line.strip().split("\t")[1:]
#                 break
#     if not header:
#         raise RuntimeError("No #fields header found in conn.log")
#
#     # Stream lines generator (excluding comment lines)
#     line_gen = stream_conn_log_lines(conn_path)
#
#     # Buffer to hold lines for chunk processing
#     buffer = []
#     lines_read = 0
#
#     # Remove output file if it exists to start fresh
#     if os.path.exists(output_path):
#         os.remove(output_path)
#
#     while True:
#         try:
#             while len(buffer) < CHUNK_SIZE:
#                 buffer.append(next(line_gen))
#                 lines_read += 1
#         except StopIteration:
#             # No more lines to read
#             pass
#
#         if not buffer:
#             break  # End of file
#
#         # Create DataFrame chunk from buffered lines
#         chunk_str = '\t'.join(header) + '\n' + ''.join(buffer)
#         chunk = pd.read_csv(StringIO(chunk_str), sep="\t", low_memory=False).fillna("")
#
#         # Filter rows by matching rules
#         matched_rows = chunk[chunk.apply(lambda row: conn_matches_any_rule(row, rules), axis=1)]
#
#         if not matched_rows.empty:
#             mode = 'a' if os.path.exists(output_path) else 'w'
#             header_write = not os.path.exists(output_path)
#             matched_rows.to_csv(output_path, sep="\t", index=False, mode=mode, header=header_write)
#
#         print(f"🔹 Processed {lines_read} lines, wrote {len(matched_rows)} matching rows.")
#
#         buffer = []  # Clear buffer for next chunk
#
#     print(f"✅ Done. Filtered logs written to: {output_path}")
#
# # === Main ===
# def main():
#     if not os.path.exists(CONN_LOG_PATH):
#         print(f"❌ Conn log not found: {CONN_LOG_PATH}")
#         return
#     if not os.path.exists(ANOMALY_CSV_PATH):
#         print(f"❌ Anomaly CSV not found: {ANOMALY_CSV_PATH}")
#         return
#
#     print("📥 Loading anomaly rules...")
#     rules = load_anomaly_rules(ANOMALY_CSV_PATH)
#
#     process_conn_log(CONN_LOG_PATH, rules, OUTPUT_PATH)
#
# if __name__ == "__main__":
#     main()






# import chromadb
# import pandas as pd
# from sentence_transformers import SentenceTransformer
# from datetime import datetime
# from io import StringIO
# import tempfile
# import os
#
# # === Initialize ChromaDB ===
# chroma_client = chromadb.PersistentClient(path="./chroma_db")
# collection_conn = chroma_client.get_or_create_collection(name="zeek_conn_logs")
# collection_csv = chroma_client.get_or_create_collection(name="anomaly_csv_logs")
# collection_txt = chroma_client.get_or_create_collection(name="heuristic_info_txt")
#
# # === Embedding Model ===
# embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
#
# # === File Paths ===
# CONN_LOG_PATH = "/Users/Keek Windows/zeek_analysis/filtered_conn.log"
# CSV_PATH = "/Users/Keek Windows/Downloads/20220110_anomalous_suspicious - 20220110_anomalous_suspicious.csv"
# TXT_PATH = "/Users/Keek Windows/Downloads/csv info.txt"
#
# # === Fields to Keep in Zeek conn.log ===
# NEEDED_COLUMNS = {
#     "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
#     "proto", "service", "duration", "orig_bytes", "orig_pkts",
#     "resp_bytes", "conn_state", "history"
# }
#
# # === Load Zeek conn.log into DataFrame ===
# def load_zeek_conn_log(file_path):
#     with open(file_path, "r", encoding="utf-8") as f:
#         lines = f.readlines()
#
#     header_line = next((line for line in lines if line.startswith("#fields")), None)
#     if not header_line:
#         raise ValueError("No #fields line found in conn.log")
#
#     headers = header_line.strip().split("\t")[1:]
#     data_lines = [line for line in lines if not line.startswith("#")]
#
#     with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8", newline='') as tmp:
#         tmp.write('\t'.join(headers) + '\n')
#         tmp.writelines(data_lines)
#         tmp_path = tmp.name
#
#     df = pd.read_csv(tmp_path, sep='\t', low_memory=False)
#     df = df[[col for col in df.columns if col in NEEDED_COLUMNS]]
#     return df
#
# # === Chunk Zeek logs by 1-minute intervals ===
# def chunk_conn_log_by_time(df, interval_minutes=1):
#     df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
#     df = df[df["ts"].notna()].copy()
#     df["ts_datetime"] = pd.to_datetime(df["ts"], unit='s')
#     df["time_bin"] = df["ts_datetime"].dt.floor(f'{interval_minutes}min')
#     return df.groupby("time_bin")
#
# # === Create natural language summary of connection ===
# def process_conn_log(df):
#     documents = []
#     ids = []
#     embeddings = []
#
#     for idx, row in df.iterrows():
#         try:
#             ts_raw = row.get("ts", None)
#             if pd.notna(ts_raw):
#                 ts = datetime.utcfromtimestamp(float(ts_raw)).strftime('%Y-%m-%d %H:%M:%S')
#             else:
#                 ts = "unknown"
#
#             uid = row.get("uid", "unknown")
#             src_ip = row.get("id.orig_h", "unknown")
#             src_port = row.get("id.orig_p", "unknown")
#             dst_ip = row.get("id.resp_h", "unknown")
#             dst_port = row.get("id.resp_p", "unknown")
#             proto = str(row.get("proto", "unknown")).upper()
#             service = row.get("service", "unknown")
#             duration = row.get("duration", "unknown")
#             orig_bytes = row.get("orig_bytes", "unknown")
#             orig_pkts = row.get("orig_pkts", "unknown")
#             resp_bytes = row.get("resp_bytes", "unknown")
#             conn_state = row.get("conn_state", "unknown")
#             history = row.get("history", "none")
#
#             log_entry = (
#                 f"At {ts}, connection UID {uid} was initiated from SOURCE IP {src_ip} on SOURCE PORT {src_port} "
#                 f"to DESTINATION IP {dst_ip} on DESTINATION PORT {dst_port} using protocol {proto} with service '{service}'. "
#                 f"The connection lasted {duration} seconds with {orig_pkts} packets ({orig_bytes} bytes) sent from the source, "
#                 f"and {resp_bytes} bytes sent from the destination. "
#                 f"Connection state was '{conn_state}', with history flags '{history}'."
#             )
#
#             log_id = f"{uid}_{ts_raw}"
#             embedding = embedding_model.encode(log_entry).tolist()
#
#             documents.append(log_entry)
#             embeddings.append(embedding)
#             ids.append(log_id)
#         except Exception as e:
#             print(f"Skipping row {idx} due to error: {e}")
#             continue
#
#     return documents, embeddings, ids
#
# # === Store Zeek conn.log entries chunked by 1-minute interval ===
# def store_conn_logs_in_chromadb(file_path, collection):
#     df = load_zeek_conn_log(file_path)
#     grouped = chunk_conn_log_by_time(df, interval_minutes=1)
#
#     total_added = 0
#     for time_bin, group_df in grouped:
#         documents, embeddings, ids = process_conn_log(group_df)
#
#         if not documents:
#             continue
#
#         chunk_id_prefix = time_bin.strftime('%Y-%m-%dT%H:%M')
#         ids = [f"{chunk_id_prefix}_{id}" for id in ids]
#
#         existing = collection.get(ids=ids)
#         if existing["ids"]:
#             collection.delete(ids=existing["ids"])
#             print(f"Deleted {len(existing['ids'])} existing Zeek entries in {chunk_id_prefix}.")
#
#         collection.add(documents=documents, embeddings=embeddings, ids=ids)
#         print(f"[{chunk_id_prefix}] Stored {len(documents)} entries.")
#         total_added += len(documents)
#
#     print(f"\n✅ Total Zeek conn.log entries added: {total_added}")
#
# # === Load Anomaly CSV into natural language ===
# def load_logs_from_csv(file_path):
#     df = pd.read_csv(file_path)
#
#     summaries = []
#
#     for idx, row in df.iterrows():
#         anomaly_id = row.get("anomalyID", "unknown")
#         src_ip = row.get("srcIP", "unknown")
#         src_port = row.get("srcPort", "unknown") if pd.notna(row.get("srcPort")) else "unknown"
#         dst_ip = row.get("dstIP", "unknown")
#         dst_port = row.get("dstPort", "unknown") if pd.notna(row.get("dstPort")) else "unknown"
#         taxonomy = row.get("taxonomy", "unknown")
#         heuristic = row.get("heuristic", "unknown")
#         label = row.get("label", "unknown")
#
#         summary = (
#             f"Anomaly ID {anomaly_id}: A {label} connection was detected from source IP {src_ip} "
#             f"on port {src_port} to destination IP {dst_ip} on port {dst_port}. "
#             f"This anomaly is categorized as '{taxonomy}' based on heuristic {heuristic}."
#         )
#
#         summaries.append(summary)
#
#     return "\n\n".join(summaries)
#
# # === Load Heuristic Info from TXT ===
# def load_logs_from_txt(file_path):
#     with open(file_path, "r", encoding="utf-8") as file:
#         return file.read()
#
# # === Generic Ingest for CSV or TXT ===
# def ingest_logs(file_path, collection):
#     file_extension = os.path.splitext(file_path)[1].lower()
#
#     if file_extension == ".csv":
#         logs = load_logs_from_csv(file_path)
#     elif file_extension == ".txt":
#         logs = load_logs_from_txt(file_path)
#     else:
#         print(f"Unsupported file type: {file_extension}")
#         return
#
#     existing_docs = collection.get(ids=[file_path])
#     if existing_docs["ids"]:
#         collection.delete(ids=existing_docs["ids"])
#         print(f"Deleted existing log for {file_path}")
#
#     log_embedding = embedding_model.encode(logs).tolist()
#     collection.add(documents=[logs], embeddings=[log_embedding], ids=[file_path])
#     print(f"Ingested logs from {file_path} into '{collection.name}'.")
#
# # === Run Ingestions ===
# store_conn_logs_in_chromadb(CONN_LOG_PATH, collection_conn)
# ingest_logs(CSV_PATH, collection_csv)
# ingest_logs(TXT_PATH, collection_txt)
#
# # === Show Sizes ===
# print(f"\nNumber of documents in 'zeek_conn_logs': {len(collection_conn.get()['documents'])}")
# print(f"Number of documents in 'anomaly_csv_logs': {len(collection_csv.get()['documents'])}")
# print(f"Number of documents in 'heuristic_info_txt': {len(collection_txt.get()['documents'])}")
import os
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Chroma
from langchain.chat_models import ChatOpenAI
from langchain.retrievers import EnsembleRetriever
from langchain.prompts import PromptTemplate

# API Key and environment settings
os.environ["OPENAI_API_KEY"] = ""
os.environ["TOKENIZERS_PARALLELISM"] = "false"
# Embeddings
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# Initialize Chroma Collections
anomaly_csv_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="anomaly_csv_logs4"
)

heuristic_txt_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="heuristic_info_txt"
)

# Create retrievers
anomaly_csv_retriever = anomaly_csv_store.as_retriever(search_kwargs={"k": 5})
heuristic_txt_retriever = heuristic_txt_store.as_retriever(search_kwargs={"k": 1})

# Combine retrievers into an ensemble
retriever = EnsembleRetriever(
    retrievers=[anomaly_csv_retriever, heuristic_txt_retriever]
)

# Prompt Template
network_log_prompt = PromptTemplate(
    input_variables=["anomaly_csv", "heuristic_context"],
    template="""
You are a specialized AI cybersecurity analyst with expert-level understanding of network security and anomaly detection.

Your core role is to:
- Interpret structured anomalies from a CSV file and correlate them with known threats.
- Leverage context from heuristic and taxonomy documentation to justify conclusions.
- Generate high-confidence, actionable summaries that can inform network defense operations or policy changes.

You are given:
- `anomaly_csv`: Structured list of known anomalies, including `srcIP`, `dstIP`, ports, heuristic ID, and taxonomy.
- `heuristic_context`: Brief descriptions of each heuristic and taxonomy term.

Your tasks:
1. Identify confirmed threats based on the anomaly data.
2. Cross-reference anomalies with heuristic and taxonomy descriptions.
3. Summarize all findings as assertive, concise bullets with actionable next steps.

Use this exact format for each entry:
- Matched anomaly ID [ID]: src [IP]:[port] → dst [IP]:[port].
  Matched heuristic [ID] ([heuristic description]); taxonomy: [taxonomy] ([taxonomy description]).
  → Action: [Concise and specific security action].

Avoid vague language like "possible", "may be", or "likely". Write with confidence.  
Return only bulleted entries — no summaries or extra commentary.
------------
Anomaly CSV:
{anomaly_csv}

Heuristic & Taxonomy Descriptions:
{heuristic_context}
------------
"""
)

# AI Analysis Function
def generate_ai_insights(query_text):
    docs = retriever.get_relevant_documents(query_text)
    if not docs:
        return "No relevant anomalies or heuristics found."

    # Separate documents by collection content hints
    anomaly_csv_docs = [doc.page_content for doc in docs if "anomaly" in doc.page_content.lower()]
    heuristic_docs = [doc.page_content for doc in docs if "heuristic" in doc.page_content.lower() or "taxonomy" in doc.page_content.lower()]

    anomaly_csv = "\n".join(anomaly_csv_docs) if anomaly_csv_docs else "No anomaly data found."
    heuristic_context = "\n".join(heuristic_docs) if heuristic_docs else "No heuristic data found."

    prompt = network_log_prompt.format(
        anomaly_csv=anomaly_csv,
        heuristic_context=heuristic_context
    )

    llm = ChatOpenAI(model_name="gpt-4", temperature=0)
    response = llm.invoke([{"role": "user", "content": prompt}])
    return response.content

# User Input Loop
if __name__ == "__main__":
    while True:
        query_text = input("\nEnter your question (or type 'exit' to quit): ")
        if query_text.lower() == "exit":
            print("Exiting RAG assistant.")
            break

        ai_response = generate_ai_insights(query_text)
        print(f"\nAI Analysis:\n{ai_response}")

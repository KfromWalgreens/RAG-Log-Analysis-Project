# Does Retrieval-Augmented Generation analysis on Zeek conn.log files to detect and explain
# ICMP ping flood attacks by extracting relevant IPs, matching them with stored anomaly
# and heuristic data in Chroma vector databases, and generating a structured security assessment

import os
import re
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Chroma
from langchain.retrievers import EnsembleRetriever
from langchain.prompts import PromptTemplate
from langchain.schema import Document
from langchain_openai import ChatOpenAI

# Set API key and tokenizer setting
os.environ["OPENAI_API_KEY"] = ""
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Load sentence transformer for embeddings
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# Load vector stores from Chroma
ping_flood_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="ping_flood_alerts2"
)

anomaly_csv_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    # collection_name="anomaly_csv_logs8"
    collection_name="anomaly_csv_logsc01"
)

heuristic_txt_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="heuristic_info_txt5"
)

# Define prompt template for LLM
ping_flood_prompt = PromptTemplate(
    input_variables=["conn_log_snippet", "anomaly_csv", "heuristic_context"],
    template="""
You are a cybersecurity analyst AI trained to detect, interpret, and explain ICMP ping flood attacks.

You are given:
- `conn_log_snippet`: Raw Zeek conn.log entries (tab-separated fields) related to network connections, including ICMP traffic.
- `anomaly_csv`: Structured anomaly records related to suspicious IPs or ports.
- `heuristic_context`: Documentation on heuristics and taxonomies used in labeling anomalies.

You know that: 
- If the ICMP type is not 8, it is not a ping flood.
- At least 10 instances of ICMP type 8 should be present, unless known anomalous src or dst IPs that match heuristic 20 are present in the instance.

Your tasks:
1. Analyze the Zeek conn.log snippet and determine **if a ping flood attack is occurring**. Format as: "Based on the current log, a ping flooding attack [is/ is not] happening."
2. If a ping flood is detected:
   Respond in this format:
   - Explain how the traffic matches known ping flood patterns.
   - Reference relevant heuristics and anomaly taxonomy from `anomaly_csv`. Assign the most likely heuristic number and taxonomy class if none are explicitly found.
   - Identify involved IP addresses and ports.
   - Recommend a **specific** security response plan.
3. If no ping flood is detected:
    Respond in this format:
    - Clearly state that no attack is present.
    - If it matches another type of attack, state the reasoning clearly.
    - State specifically what the heuristic and taxonomy stand for.
    - If something should be investigated further, be specific on next steps.

Be confident and avoid vague language. Support your conclusions with the provided data. Do not include a summary at the end, keep answers concise.
-----------------
Zeek conn.log snippet:
{conn_log_snippet}

Anomaly CSV Records:
{anomaly_csv}

Heuristic & Taxonomy Context:
{heuristic_context}
-----------------
"""
)

# Extract IPs from input text
def extract_ips(text):
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

# Match anomaly records using IPs
def match_anomaly_docs(ip_list, store, k=7):
    matched_docs = []
    for ip in ip_list:
        results = store.similarity_search(ip, k=k)
        for doc in results:
            if ip in doc.page_content:
                matched_docs.append(doc.page_content)
    return list(set(matched_docs))

# Extract prefix-category mappings from heuristic docs
def parse_heuristic_docs_for_prefixes(store):
    docs = store.similarity_search("prefixes", k=5)
    prefix_map = {}
    for doc in docs:
        content = doc.page_content if isinstance(doc, Document) else str(doc)
        category_match = re.search(r"Category:\s*(.+)", content)
        prefixes_match = re.search(r"Prefixes:\s*(.+)", content)
        if category_match and prefixes_match:
            category = category_match.group(1).strip()
            prefixes = [p.strip() for p in prefixes_match.group(1).split(",")]
            for prefix in prefixes:
                prefix_map[prefix] = category
    return prefix_map

# Match heuristic documents based on anomaly data
def match_heuristic_docs(anomaly_docs, store, k=3):
    heuristic_ids = set()
    taxonomy_prefixes = set()
    for doc in anomaly_docs:
        found_ids = re.findall(r'heuristic(?: id)? (\d{1,4})', doc, re.IGNORECASE)
        heuristic_ids.update(found_ids)
        taxonomy_prefixes.update(re.findall(r'\b[a-zA-Z]{4,}\b', doc))
    matched_docs = []
    for hid in heuristic_ids:
        results = store.similarity_search(hid, k=k)
        matched_docs.extend([doc.page_content for doc in results if hid in doc.page_content])
    prefix_map = parse_heuristic_docs_for_prefixes(store)
    for prefix in taxonomy_prefixes:
        if prefix in prefix_map:
            entry = f"Category: {prefix_map[prefix]}\nPrefix: {prefix}"
            matched_docs.append(entry)
    return list(set(matched_docs))

# Prepare conn.log data for the LLM
def prepare_conn_log_for_llm(file_path):
    try:
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f if not line.startswith("#")]
        # Filter lines to those with proto field == 'icmp'
        icmp_lines = [line for line in lines if len(line.split('\t')) > 6 and line.split('\t')[6].lower() == 'icmp']
        # If no ICMP lines, fallback to all lines
        return "\n".join(icmp_lines) if icmp_lines else "\n".join(lines)
    except Exception as e:
        return f"Error reading file: {e}"

# Limit text by character count, keeping complete lines
def cap_text(text, max_chars):
    """Truncate text cleanly at max_chars, preserving whole lines if possible."""
    if len(text) <= max_chars:
        return text
    lines = text.split('\n')
    capped = []
    current_len = 0
    for line in lines:
        if current_len + len(line) + 1 > max_chars:
            break
        capped.append(line)
        current_len += len(line) + 1
    return "\n".join(capped)

# Generate LLM analysis output using RAG
def generate_rag_analysis(conn_log_text):
    alert_ips = extract_ips(conn_log_text)
    anomaly_contents = match_anomaly_docs(alert_ips, anomaly_csv_store)
    heuristic_contents = match_heuristic_docs(anomaly_contents, heuristic_txt_store)

    # Limit each section to reduce total tokens (GPT-4 max = 8192)
    context = {
        "conn_log_snippet": cap_text(conn_log_text, 2500),
        "anomaly_csv": "\n".join(anomaly_contents) if anomaly_contents else "No anomaly data found.",
        "heuristic_context": "\n".join(heuristic_contents) if heuristic_contents else "No heuristic context available."
    }

    prompt = ping_flood_prompt.format(**context)
    llm = ChatOpenAI(model_name="gpt-4.1-mini", temperature=0)
    response = llm.invoke([{"role": "user", "content": prompt}])
    return response.content

# Run RAG analysis over a user-inputted conn.log file
# if __name__ == "__main__":
#     while True:
#         user_input = input("Enter file path to your log snippet (or 'exit'): ").strip()
#         if user_input.lower() == "exit":
#             print("Exiting RAG agent.")
#             break
#
#         conn_log_text = prepare_conn_log_for_llm(user_input)
#         if conn_log_text.startswith("Error reading file"):
#             print(conn_log_text)
#             continue
#
#         print("\nSending your log file snippet to LLM for detection and analysis...\n")
#         rag_result = generate_rag_analysis(conn_log_text)
#         print(rag_result)
#
#         output_path = "rag_snippet_analysis.txt"
#         with open(output_path, "w", encoding="utf-8") as f:
#             f.write(rag_result)
#
#         print(f"\nLLM response saved to: {output_path}")

# Run RAG analysis over a folder of conn.log files
def run_folder_analysis(input_folder, output_folder):
    os.makedirs(output_folder, exist_ok=True)
    log_files = [f for f in os.listdir(input_folder) if f.endswith(".log")]

    for fname in log_files:
        full_path = os.path.join(input_folder, fname)
        print(f"Processing {fname}...")
        log_text = prepare_conn_log_for_llm(full_path)

        if log_text.startswith("Error"):
            print(f"Skipping {fname} due to read error.")
            continue

        rag_response = generate_rag_analysis(log_text)
        out_path = os.path.join(output_folder, fname.rsplit(".", 1)[0] + ".txt")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(rag_response)

    print("\nAll files processed. Output saved to:", output_folder)

# Set input and output folders for batch processing
if __name__ == "__main__":
    # input_folder = "C:/Users/Keek Windows/PyCharmMiscProject/c101split/test3" # Folder with conn.log files
    # output_folder = "C:/Users/Keek Windows/PyCharmMiscProject/rag_outputs_c101split3withanom" # Where to save .txts
    # input_folder = "C:/Users/Keek Windows/PyCharmMiscProject/fc110split"  # Folder with conn.log files
    # output_folder = "C:/Users/Keek Windows/PyCharmMiscProject/rag_outputs_fc110split" # Where to save .txts
    input_folder = "C:/Users/Keek Windows/PyCharmMiscProject/inragsplit/test1"  # Folder with conn.log files
    output_folder = "C:/Users/Keek Windows/PyCharmMiscProject/rag_outputs_inragsplit2/test1" # Where to save .txts

    run_folder_analysis(input_folder, output_folder)

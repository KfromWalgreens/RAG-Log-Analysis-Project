# import os
# from langchain.embeddings import HuggingFaceEmbeddings
# from langchain.vectorstores import Chroma
# from langchain.chat_models import ChatOpenAI
# from langchain.retrievers import EnsembleRetriever
# from langchain.prompts import PromptTemplate
#
# # API Key and environment settings
# os.environ["OPENAI_API_KEY"] = ""
# os.environ["TOKENIZERS_PARALLELISM"] = "false"
# # Embeddings
# embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
#
# # Load Chroma Collections
# ping_flood_store = Chroma(
#     persist_directory="./chroma_db",
#     embedding_function=embedding_model,
#     collection_name="ping_flood_alerts2"
# )
#
# anomaly_csv_store = Chroma(
#     persist_directory="./chroma_db",
#     embedding_function=embedding_model,
#     collection_name="anomaly_csv_logs4"
# )
#
# heuristic_txt_store = Chroma(
#     persist_directory="./chroma_db",
#     embedding_function=embedding_model,
#     collection_name="heuristic_info_txt"
# )
#
# # Create retrievers
# ping_flood_retriever = ping_flood_store.as_retriever(search_kwargs={"k": 6})
# anomaly_csv_retriever = anomaly_csv_store.as_retriever(search_kwargs={"k": 6})
# heuristic_txt_retriever = heuristic_txt_store.as_retriever(search_kwargs={"k": 1})
#
# # Combine retrievers
# retriever = EnsembleRetriever(
#     retrievers=[ping_flood_retriever, anomaly_csv_retriever, heuristic_txt_retriever]
# )
#
# # Prompt Template
# ping_flood_prompt = PromptTemplate(
#     input_variables=["ping_flood_alerts2", "anomaly_csv", "heuristic_context"],
#     template="""
# You are a cybersecurity analyst AI trained to detect, interpret, and explain ICMP ping flood attacks.
#
# You are given:
# - `ping_flood_alerts2`: Natural-language summaries of potential ping flood events.
# - `anomaly_csv`: Structured anomaly records related to suspicious IPs or ports.
# - `heuristic_context`: Documentation on the heuristics and taxonomies used in labeling anomalies.
#
# Your goals:
# 1. Confirm whether each ping flood detection is consistent with known anomaly patterns.
# 2. Use heuristic context to explain why this behavior is considered a threat.
# 3. Recommend a concise, confident security action.
#
# Respond in this format:
# - Ping flood alert: [summary]
#   Justified by anomaly: Matched anomaly ID [ID], heuristic [ID] ([desc]), taxonomy [name] ([desc]).
#   → Action: [specific action like block IP, investigate source, rate-limit ICMP, etc.]
#
# Be assertive — avoid vague words like “might” or “possibly”. Justify your answer with retrieved evidence.
#
# ------------
# Ping Flood Alerts:
# {ping_flood_alerts2}
#
# Anomaly CSV Records:
# {anomaly_csv}
#
# Heuristic & Taxonomy Context:
# {heuristic_context}
# ------------
# """
# )
#
# # RAG Analysis Function
# def generate_rag_analysis(query_text):
#     docs = retriever.get_relevant_documents(query_text)
#     if not docs:
#         return "No matching context found."
#
#     ping_flood_docs = [doc.page_content for doc in docs if "ping flood" in doc.page_content.lower()]
#     anomaly_docs = [doc.page_content for doc in docs if "anomaly" in doc.page_content.lower()]
#     heuristic_docs = [doc.page_content for doc in docs if "heuristic" in doc.page_content.lower() or "taxonomy" in doc.page_content.lower()]
#
#     context = {
#         "ping_flood_alerts2": "\n".join(ping_flood_docs) or "No alerts found.",
#         "anomaly_csv": "\n".join(anomaly_docs) or "No anomaly data found.",
#         "heuristic_context": "\n".join(heuristic_docs) or "No heuristic context available."
#     }
#
#     prompt = ping_flood_prompt.format(**context)
#
#     llm = ChatOpenAI(model_name="gpt-4", temperature=0)
#     response = llm.invoke([{"role": "user", "content": prompt}])
#     return response.content
#
# # CLI Interaction
# if __name__ == "__main__":
#     while True:
#         query = input("\nEnter a ping flood summary or type 'exit': ")
#         if query.strip().lower() == "exit":
#             print("Exiting RAG assistant.")
#             break
#
#         result = generate_rag_analysis(query)
#         print("\nRAG Justification:\n", result)


#--------------------------------------------------------

# import os
# import re
# from langchain.embeddings import HuggingFaceEmbeddings
# from langchain.vectorstores import Chroma
# from langchain.chat_models import ChatOpenAI
# from langchain.retrievers import EnsembleRetriever
# from langchain.prompts import PromptTemplate
#
# # API Key and environment settings
# os.environ["OPENAI_API_KEY"] = ""
# os.environ["TOKENIZERS_PARALLELISM"] = "false"
#
# # Embeddings
# embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
#
# # Load Chroma Collections
# ping_flood_store = Chroma(
#     persist_directory="./chroma_db",
#     embedding_function=embedding_model,
#     collection_name="ping_flood_alerts2"
# )
#
# anomaly_csv_store = Chroma(
#     persist_directory="./chroma_db",
#     embedding_function=embedding_model,
#     collection_name="anomaly_csv_logs4"
# )
#
# heuristic_txt_store = Chroma(
#     persist_directory="./chroma_db",
#     embedding_function=embedding_model,
#     collection_name="heuristic_info_txt"
# )
#
# # Create retrievers
# ping_flood_retriever = ping_flood_store.as_retriever(search_kwargs={"k": 6})
# anomaly_csv_retriever = anomaly_csv_store.as_retriever(search_kwargs={"k": 6})
# heuristic_txt_retriever = heuristic_txt_store.as_retriever(search_kwargs={"k": 1})
#
# # Prompt Template
# ping_flood_prompt = PromptTemplate(
#     input_variables=["ping_flood_alerts2", "anomaly_csv", "heuristic_context"],
#     template="""
# You are a cybersecurity analyst AI trained to detect, interpret, and explain ICMP ping flood attacks.
#
# You are given:
# - `ping_flood_alerts2`: Natural-language summaries of potential ping flood events.
# - `anomaly_csv`: Structured anomaly records related to suspicious IPs or ports.
# - `heuristic_context`: Documentation on the heuristics and taxonomies used in labeling anomalies.
#
# Your goals:
# 1. Confirm whether each ping flood detection is consistent with known anomaly patterns.
# 2. Use heuristic context to explain why this behavior is considered a threat.
# 3. Recommend a concise, confident security action.
#
# Respond in this format:
# - Ping flood alert: [summary]
#   Justified by anomaly: Matched anomaly ID [ID], heuristic [ID] ([desc]), taxonomy [name] ([desc]).
#   → Action: [specific action like block IP, investigate source, rate-limit ICMP, etc.]
#
# Be assertive — avoid vague words like “might” or “possibly”. Justify your answer with retrieved evidence.
#
# ------------
# Ping Flood Alerts:
# {ping_flood_alerts2}
#
# Anomaly CSV Records:
# {anomaly_csv}
#
# Heuristic & Taxonomy Context:
# {heuristic_context}
# ------------
# """
# )
#
# # Utility: Extract IPs from ping flood text
# def extract_ips(text):
#     return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
#
# # Utility: Match anomalies using IPs
# def match_anomaly_docs(ip_list, store, k=6):
#     matched_docs = []
#     for ip in ip_list:
#         results = store.similarity_search(ip, k=k)
#         for doc in results:
#             if ip in doc.page_content:
#                 matched_docs.append(doc.page_content)
#     return list(set(matched_docs))
#
# # Utility: Match heuristic/taxonomy context based on numeric heuristic IDs in anomaly docs
# def match_heuristic_docs(anomaly_docs, store, k=3):
#     heuristic_ids = set()
#     for doc in anomaly_docs:
#         matches = re.findall(r'\b\d{3,4}\b', doc)  # heuristic ID pattern
#         heuristic_ids.update(matches)
#
#     matched_docs = []
#     for hid in heuristic_ids:
#         results = store.similarity_search(hid, k=k)
#         for doc in results:
#             if hid in doc.page_content:
#                 matched_docs.append(doc.page_content)
#     return list(set(matched_docs))
#
# # RAG Analysis Function
# def generate_rag_analysis(query_text):
#     alert_ips = extract_ips(query_text)
#     anomaly_contents = match_anomaly_docs(alert_ips, anomaly_csv_store)
#     heuristic_contents = match_heuristic_docs(anomaly_contents, heuristic_txt_store)
#
#     ping_flood_contents = [query_text]
#
#     context = {
#         "ping_flood_alerts2": "\n".join(ping_flood_contents) or "No alerts found.",
#         "anomaly_csv": "\n".join(anomaly_contents) or "No anomaly data found.",
#         "heuristic_context": "\n".join(heuristic_contents) or "No heuristic context available."
#     }
#
#     prompt = ping_flood_prompt.format(**context)
#
#     llm = ChatOpenAI(model_name="gpt-4", temperature=0)
#     response = llm.invoke([{"role": "user", "content": prompt}])
#     return response.content
#
# # CLI Interaction
# if __name__ == "__main__":
#     while True:
#         query = input("\nEnter a ping flood summary or type 'exit': ")
#         if query.strip().lower() == "exit":
#             print("Exiting RAG assistant.")
#             break
#
#         result = generate_rag_analysis(query)
#         print("\nRAG Justification:\n", result)

import os
import re
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Chroma
from langchain.chat_models import ChatOpenAI
from langchain.retrievers import EnsembleRetriever
from langchain.prompts import PromptTemplate
from langchain.schema import Document

# API Key and environment settings
os.environ["OPENAI_API_KEY"] = ""
os.environ["TOKENIZERS_PARALLELISM"] = "false"


# Embeddings
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# === Load Chroma Collections ===
ping_flood_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="ping_flood_alerts2"
)

anomaly_csv_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="anomaly_csv_logs4"
)

heuristic_txt_store = Chroma(
    persist_directory="./chroma_db",
    embedding_function=embedding_model,
    collection_name="heuristic_info_txt4"
)

# === Prompt Template ===
ping_flood_prompt = PromptTemplate(
    input_variables=["ping_flood_alerts2", "anomaly_csv", "heuristic_context"],
    template="""
You are a cybersecurity analyst AI trained to detect, interpret, and explain ICMP ping flood attacks.

You are given:
- `ping_flood_alerts2`: Natural-language summaries of potential ping flood events.
- `anomaly_csv`: Structured anomaly records related to suspicious IPs or ports.
- `heuristic_context`: Documentation on the heuristics and taxonomies used in labeling anomalies.

Your goals:
1. Confirm whether each ping flood detection is consistent with known anomaly patterns.
2. Use heuristic context to explain why this behavior is considered a threat.
3. Recommend a concise, confident security action.

Respond in this format:
- Ping flood alert: [summary]
  Justified by anomaly: Matched anomaly ID [ID], heuristic [ID] ([desc]), taxonomy [name] ([desc]).
  → Action: [specific action like block IP, investigate source, rate-limit ICMP, etc.]

Be assertive — avoid vague words like “might” or “possibly”. Justify your answer with retrieved evidence.

------------
Ping Flood Alerts:
{ping_flood_alerts2}

Anomaly CSV Records:
{anomaly_csv}

Heuristic & Taxonomy Context:
{heuristic_context}
------------
"""
)

# === Utility: Extract IPs ===
def extract_ips(text):
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

# === Utility: Match anomalies using IPs ===
def match_anomaly_docs(ip_list, store, k=6):
    matched_docs = []
    for ip in ip_list:
        results = store.similarity_search(ip, k=k)
        for doc in results:
            if ip in doc.page_content:
                matched_docs.append(doc.page_content)
    return list(set(matched_docs))

# === Utility: Get prefix → taxonomy category map ===
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

# === Utility: Match heuristic/taxonomy context ===
def match_heuristic_docs(anomaly_docs, store, k=3):
    heuristic_ids = set()
    taxonomy_prefixes = set()

    for doc in anomaly_docs:
        heuristic_ids.update(re.findall(r'\b\d{3,4}\b', doc))
        taxonomy_prefixes.update(re.findall(r'\b[a-zA-Z]{4,}\b', doc))

    matched_docs = []

    for hid in heuristic_ids:
        results = store.similarity_search(hid, k=k)
        matched_docs.extend([doc.page_content for doc in results if hid in doc.page_content])

    # Add taxonomy descriptions based on prefixes
    prefix_map = parse_heuristic_docs_for_prefixes(store)
    for prefix in taxonomy_prefixes:
        if prefix in prefix_map:
            entry = f"Category: {prefix_map[prefix]}\nPrefix: {prefix}"
            matched_docs.append(entry)

    return list(set(matched_docs))

# === RAG Analysis ===
def generate_rag_analysis(query_text):
    alert_ips = extract_ips(query_text)
    anomaly_contents = match_anomaly_docs(alert_ips, anomaly_csv_store)
    heuristic_contents = match_heuristic_docs(anomaly_contents, heuristic_txt_store)

    ping_flood_contents = [query_text]

    context = {
        "ping_flood_alerts2": "\n".join(ping_flood_contents) or "No alerts found.",
        "anomaly_csv": "\n".join(anomaly_contents) or "No anomaly data found.",
        "heuristic_context": "\n".join(heuristic_contents) or "No heuristic context available."
    }

    prompt = ping_flood_prompt.format(**context)

    llm = ChatOpenAI(model_name="gpt-4", temperature=0)
    response = llm.invoke([{"role": "user", "content": prompt}])
    return response.content

# === CLI Interface ===
if __name__ == "__main__":
    while True:
        query = input("\nEnter a ping flood summary or type 'exit': ")
        if query.strip().lower() == "exit":
            print("Exiting RAG assistant.")
            break

        result = generate_rag_analysis(query)
        print("\nRAG Justification:\n", result)
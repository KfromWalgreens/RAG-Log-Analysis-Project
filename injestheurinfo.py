# Parses a heuristic/taxonomy text file into distinct “Simple heuristic” and “Anomaly taxonomy” sections,
# splits long sections into smaller chunks, and ingests them into a ChromaDB collection
# with sentence-transformer embeddings for later semantic search and retrieval

import os
import re
from chromadb import PersistentClient
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

# Function to extract and split the text into sections based on headers like 'Simple heuristic' or 'Anomaly taxonomy'
def split_by_sections(text):
    pattern = r"(?m)^\s*(Simple heuristic|Anomaly taxonomy)\s*\n+([\s\S]*?)(?=^\s*(?:Simple heuristic|Anomaly taxonomy)|\Z)"
    matches = re.findall(pattern, text)

    print(f"\nFound {len(matches)} sections:")
    for m in matches:
        print(f" - {m[0]}")

    # Store each section as a tuple of (section_name, section_content)
    sections = []
    for match in matches:
        section_name = match[0].strip()
        content = match[1].strip()
        sections.append((section_name, content))
    return sections

# Optional helper to break long sections into smaller chunks of ~300 tokens
def subchunk_text(text, max_tokens=300):
    """Optional: Break long text into smaller chunks."""
    lines = text.split("\n")
    chunks = []
    current = []
    token_est = lambda s: len(s.split())  # rough token estimate

    total = 0
    for line in lines:
        total += token_est(line)
        current.append(line)
        if total >= max_tokens:
            chunks.append("\n".join(current).strip())
            current = []
            total = 0
    if current:
        chunks.append("\n".join(current).strip())
    return chunks

# Ingest the extracted sections (and their chunks) into ChromaDB
def ingest_sections_to_chroma(sections, collection):
    for idx, (title, content) in enumerate(sections):
        print(f"\n--- Section {idx+1}: {title} ---")
        print(content[:500], "\n...")  # print preview

        chunks = subchunk_text(content)
        for j, chunk in enumerate(chunks):
            doc_id = f"{title.replace(' ', '_').lower()}_{idx}_{j}"  # create unique doc ID
            metadata = {"section": title}
            collection.upsert(
                documents=[chunk],
                metadatas=[metadata],
                ids=[doc_id]
            )
            print(f"Ingested chunk {j} of section '{title}'.")

if __name__ == "__main__":
    # Load the raw text from the heuristic/taxonomy text file
    path_to_text_file = "C:/Users/Keek Windows/Downloads/csv info2.txt"
    with open(path_to_text_file, "r", encoding="utf-8-sig") as f:
        text = f.read()

    # Split text into named sections
    sections = split_by_sections(text)

    # Set up ChromaDB persistent client and embedding model
    embedding_model = SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    chroma_client = PersistentClient(path="./chroma_db")
    collection = chroma_client.get_or_create_collection(
        name="heuristic_info_txt5",
        embedding_function=embedding_model
    )

    # Ingest sections and their chunks into the vector database
    ingest_sections_to_chroma(sections, collection)
    print(f"\nFinished ingesting {len(sections)} main sections.")

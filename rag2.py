import chromadb
from sentence_transformers import SentenceTransformer
import openai  

# Initialize ChromaDB and Embedding Model
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="network_logs2")
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

openai.api_key = "" #input api key here

# Get Relevant Logs from ChromaDB
def retrieve_relevant_logs(query_text, n_results=5):
    query_embedding = embedding_model.encode(query_text).tolist()
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results
    )
    return results["documents"][0] if results else []

def generate_ai_insights(query_text):
    # Get logs relevant to the user’s question
    retrieved_logs = retrieve_relevant_logs(query_text)

    if not retrieved_logs:
        return "No relevant logs found."

    # Format logs as context for the LLM
    context = "\n".join(retrieved_logs)
    prompt = f"""
    You are a cybersecurity expert analyzing network logs.
    Given the following logs:

    {context}

    Answer the following user query based on the logs: {query_text}
    """

    # New OpenAI API format
    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are an expert in network security."},
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message["content"]

# User Input
while True:
    query_text = input("\n Enter your network security question (or type 'exit' to quit): ")
    if query_text.lower() == "exit":
        print("Exiting RAG assistant.")
        break

    ai_response = generate_ai_insights(query_text)
    print(f"\n AI Analysis:\n{ai_response}")

import os
import json

def load_ground_truth(json_path):
    with open(json_path, "r") as f:
        data = json.load(f)
    # Strip ".log" extension from keys for matching filenames without extension
    return {k.rsplit(".", 1)[0]: v.get("ping_flood_detected", False) for k, v in data.items()}


def extract_prediction(text):
    text = text.strip()
    if not text:
        return None  # Handle empty text

    # Protect "conn.log" from splitting
    protected_text = text.replace("conn.log", "conn_log")

    # Split into sentences
    sentences = protected_text.split(".")

    # Restore the original conn.log if needed (not used here but can be if needed downstream)
    first_sentence = sentences[0].replace("conn_log", "conn.log").lower()

    # If 'no' appears in the first sentence, assume no attack
    if "no" in first_sentence or "not" in first_sentence:
        return False
    else:
        return True


# Evaluate RAG output predictions against ground truth labels
def evaluate(ground_truth, rag_folder):
    # Initialize counts for TP, TN, FP, FN
    tp = tn = fp = fn = 0
    missing = []  # files not found
    undecided = []  # predictions not extractable

    # Loop through each ground truth label
    for fname_no_ext, true_label in ground_truth.items():
        rag_path = os.path.join(rag_folder, fname_no_ext + ".txt")

        # If the RAG output file doesn't exist
        if not os.path.exists(rag_path):
            missing.append(fname_no_ext)
            continue

        # Read the RAG-generated output
        with open(rag_path, "r", encoding="utf-8") as f:
            rag_output = f.read()

        # Extract the predicted label
        pred = extract_prediction(rag_output)

        # If prediction could not be extracted
        if pred is None:
            undecided.append(fname_no_ext)
            continue

        # Compare prediction to ground truth
        if pred == true_label:
            if pred:  # both are True
                tp += 1
            else:  # both are False
                tn += 1
        else:
            if true_label and not pred:  # missed a true case
                fn += 1
            elif not true_label and pred:  # incorrectly flagged
                fp += 1

    # Calculate metrics
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # Return detailed metrics
    return {
        "total_evaluated": total,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "missing_files": missing,
        "undecided_outputs": undecided
    }


# Run evaluation with specified file paths
if __name__ == "__main__":
    # Path to ground truth JSON
    gt_json_path = "C:/Users/Keek Windows/PyCharmMiscProject/c101split/test2/ping_flood_labels.json"

    # Folder containing RAG-generated text outputs
    rag_outputs_folder = "C:/Users/Keek Windows/PyCharmMiscProject/rag_outputs_c101split"

    # Load ground truth and evaluate
    ground_truth = load_ground_truth(gt_json_path)
    results = evaluate(ground_truth, rag_outputs_folder)

    # Print summary of evaluation metrics
    print("=== Evaluation Results ===")
    print(f"Total evaluated: {results['total_evaluated']}")
    print(f"Accuracy: {results['accuracy']:.2%}")
    print(f"Precision: {results['precision']:.2%}")
    print(f"Recall: {results['recall']:.2%}")
    print(f"F1 Score: {results['f1_score']:.2%}")
    print(f"True Positives: {results['true_positives']}")
    print(f"True Negatives: {results['true_negatives']}")
    print(f"False Positives: {results['false_positives']}")
    print(f"False Negatives: {results['false_negatives']}")

    # Print info about missing or undecided predictions
    if results["missing_files"]:
        print(f"\nMissing RAG output files for: {results['missing_files']}")
    if results["undecided_outputs"]:
        print(f"\nUndecided RAG outputs for: {results['undecided_outputs']}")

# Processes a large Zeek conn.log file in memory-efficient chunks, filtering for connections
# matching IP/port patterns from an anomaly CSV, and writes only the matching rows to a new filtered log file

import pandas as pd
from io import StringIO
import os

# Config
CONN_LOG_PATH = "/Users/Keek Windows/zeek_analysis/jan82022/conn.log"
ANOMALY_CSV_PATH = "/Users/Keek Windows/Downloads/20220108_anomalous_suspicious - 20220108_anomalous_suspicious.csv"
OUTPUT_PATH = "/Users/Keek Windows/zeek_analysis/filtered_conn108.log"
CHUNK_SIZE = 100_000  # Tune based on available RAM

# Load anomaly rules from CSV
def load_anomaly_rules(path):
    df = pd.read_csv(path).fillna("None").astype(str)
    rules = []
    for _, row in df.iterrows():
        rules.append({
            "srcIP": row["srcIP"],
            "srcPort": row["srcPort"],
            "dstIP": row["dstIP"],
            "dstPort": row["dstPort"]
        })
    return rules

# Check if connection row matches any anomaly rule
def conn_matches_any_rule(row, rules):
    for rule in rules:
        if (
            (rule["srcIP"] == "None" or row["id.orig_h"] == rule["srcIP"]) and
            (rule["dstIP"] == "None" or row["id.resp_h"] == rule["dstIP"]) and
            (rule["srcPort"] == "None" or str(row["id.orig_p"]) == rule["srcPort"]) and
            (rule["dstPort"] == "None" or str(row["id.resp_p"]) == rule["dstPort"])
        ):
            return True
    return False

# Generator to stream cleaned conn.log lines
def stream_conn_log_lines(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.startswith("#"):
                yield line

# Process conn.log in chunks directly from the file stream
def process_conn_log(conn_path, rules, output_path):
    print("Processing in chunks...")

    # Read the first non-comment line with '#fields' to get header
    header = None
    with open(conn_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#fields"):
                header = line.strip().split("\t")[1:]
                break
    if not header:
        raise RuntimeError("No #fields header found in conn.log")

    # Streamlines generator (excluding comment lines)
    line_gen = stream_conn_log_lines(conn_path)

    # Buffer to hold lines for chunk processing
    buffer = []
    lines_read = 0

    # Remove output file if it exists to start fresh
    if os.path.exists(output_path):
        os.remove(output_path)

    while True:
        try:
            while len(buffer) < CHUNK_SIZE:
                buffer.append(next(line_gen))
                lines_read += 1
        except StopIteration:
            # No more lines to read
            pass

        if not buffer:
            break  # End of file

        # Create DataFrame chunk from buffered lines
        chunk_str = '\t'.join(header) + '\n' + ''.join(buffer)
        chunk = pd.read_csv(StringIO(chunk_str), sep="\t", low_memory=False).fillna("")

        # Filter rows by matching rules
        matched_rows = chunk[chunk.apply(lambda row: conn_matches_any_rule(row, rules), axis=1)]

        if not matched_rows.empty:
            mode = 'a' if os.path.exists(output_path) else 'w'
            header_write = not os.path.exists(output_path)
            matched_rows.to_csv(output_path, sep="\t", index=False, mode=mode, header=header_write)

        print(f"🔹 Processed {lines_read} lines, wrote {len(matched_rows)} matching rows.")

        buffer = []  # Clear buffer for next chunk

    print(f"Done. Filtered logs written to: {output_path}")


def main():
    if not os.path.exists(CONN_LOG_PATH):
        print(f"Conn log not found: {CONN_LOG_PATH}")
        return
    if not os.path.exists(ANOMALY_CSV_PATH):
        print(f"Anomaly CSV not found: {ANOMALY_CSV_PATH}")
        return

    print("Loading anomaly rules...")
    rules = load_anomaly_rules(ANOMALY_CSV_PATH)

    process_conn_log(CONN_LOG_PATH, rules, OUTPUT_PATH)

if __name__ == "__main__":
    main()

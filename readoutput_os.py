import pandas as pd
import json
import glob
import os

# Path to Excel output
output_file = "vt_relations_output.xlsx"

# Load existing Excel file if it exists
if os.path.exists(output_file):
    df_existing = pd.read_excel(output_file)
else:
    df_existing = pd.DataFrame()

# Path to JSON files
folder = r""

rows = []

for file in glob.glob(folder):
    with open(file, "r", encoding="utf-8") as f:
        data = json.load(f)

    rel = data.get("relations", {})

    rows.append({
        "filename": os.path.basename(file),
        "hash": data.get("hash"),
        "first_submission_date": data.get("first_submission_date"),
        "domains": rel.get("domains", []),
        "ips": rel.get("ips", []),
    })

df_new = pd.DataFrame(rows)

# Combine old + new
df_combined = pd.concat([df_existing, df_new], ignore_index=True)

# Remove duplicates — safest to use the file hash
df_combined = df_combined.drop_duplicates(subset=["hash"], keep="first")

# Save updated Excel
df_combined.to_excel(output_file, index=False)

print("Excel updated:", output_file)

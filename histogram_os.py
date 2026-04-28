import os
import glob
import json
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
from publicsuffix2 import PublicSuffixList

# -----------------------------------------
# 1. Load Data Directly from JSON Reports [cite: 33, 34]
# -----------------------------------------
VT_REPORTS_DIR = r"" 
json_files = glob.glob(os.path.join(VT_REPORTS_DIR, "*.json"))

if not json_files:
    raise SystemExit(f"💀 No JSON files found in '{VT_REPORTS_DIR}'.")

print(f"Found {len(json_files)} JSON reports. Digging through the trash... [cite: 34]")

data = []
for file_path in json_files:
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            report = json.load(f)
            sub_date = report.get("first_submission_date")
            domains = report.get("relations", {}).get("domains", []) # [cite: 35]
            
            for d in domains:
                data.append({
                    "first_submission_date": sub_date,
                    "domain": d # [cite: 36]
                })
        except Exception as e:
            print(f"⚠️ Skipping cursed file {file_path}: {e}")

vt = pd.DataFrame(data)

if vt.empty:
    raise SystemExit("💀 DataFrame is empty. RIP. [cite: 37]")

# -----------------------------------------
# 2. Clean and Format Dates [cite: 37]
# -----------------------------------------
vt['first_submission_date'] = pd.to_datetime(vt['first_submission_date'], errors='coerce')
vt = vt.dropna(subset=['first_submission_date'])
vt['month'] = vt['first_submission_date'].dt.to_period('M')

# -----------------------------------------
# 3. Extract eTLD+1 [cite: 37]
# -----------------------------------------
psl = PublicSuffixList()
def extract_etld(domain):
    if pd.isna(domain): return None
    return psl.get_sld(str(domain).lower().strip())

print("Extracting eTLD+1...")
vt['domain_clean'] = vt['domain'].apply(extract_etld)

# -----------------------------------------
# 4. Load Tranco & Alexa (Top 200 ONLY) [cite: 38]
# -----------------------------------------
print("Loading Tranco and Alexa lists...")
tranco = pd.read_csv(r"C:\Users\kfirg\Downloads\tranco_JL38Y.csv", header=None, names=['rank', 'domain'])
tranco_domains = set(tranco.sort_values('rank').head(200)['domain'].str.lower().str.strip()) # [cite: 38]

alexa = pd.read_csv(r"C:\Users\kfirg\Downloads\top-1m.csv", header=None, names=['rank', 'domain'])
alexa_domains = set(alexa.sort_values('rank').head(200)['domain'].str.lower().str.strip())

# -----------------------------------------
# 5. Match and Count [cite: 39]
# -----------------------------------------
vt_tranco = vt[vt['domain_clean'].isin(tranco_domains)]
vt_alexa = vt[vt['domain_clean'].isin(alexa_domains)]

df_counts = pd.DataFrame({
    'Tranco (Top 200)': vt_tranco.groupby('month')['domain_clean'].count(),
    'Alexa (Top 200)': vt_alexa.groupby('month')['domain_clean'].count()
}).fillna(0)

# -----------------------------------------
# 6. Plot the Graph (Poster-Quality Export) [cite: 40, 41]
# -----------------------------------------
print("Drawing high-quality timeline...")
df_counts.index = df_counts.index.to_timestamp()
all_months = pd.date_range(start=df_counts.index.min(), end=df_counts.index.max(), freq='MS')
df_counts = df_counts.reindex(all_months, fill_value=0) # 

sns.set_theme(style="darkgrid", context="talk")
plt.figure(figsize=(16, 8)) # Slightly taller for clarity

# Plotting with professional palette
plt.plot(df_counts.index, df_counts['Tranco (Top 200)'], color='#2ecc71', label='Tranco (Modern)', linewidth=3, marker='o', markersize=5)
plt.fill_between(df_counts.index, df_counts['Tranco (Top 200)'], color='#2ecc71', alpha=0.15)

plt.plot(df_counts.index, df_counts['Alexa (Top 200)'], color='#f39c12', label='Alexa (Legacy)', linewidth=3, marker='s', markersize=5)
plt.fill_between(df_counts.index, df_counts['Alexa (Top 200)'], color='#f39c12', alpha=0.15)

# Formatting axes [cite: 41]
plt.gca().xaxis.set_major_locator(mdates.YearLocator())
plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y'))
plt.title("Malware Infrastructure Evolution: Tranco vs. Alexa (Top 200 Abused)", fontsize=20, fontweight='bold', pad=25)
plt.xlabel("Year of First Submission", fontsize=14)
plt.ylabel("Unique Domain Count", fontsize=14)
plt.legend(loc="upper left", frameon=True, shadow=True, fontsize=12)

plt.tight_layout()

# --- NEW: SAVE AS HIGH-QUALITY PDF ---
out_dir = os.path.join(os.getcwd(), "graph_outputs")
os.makedirs(out_dir, exist_ok=True)
pdf_path = os.path.join(out_dir, "Malware_Timeline_Timeline_Final.pdf")

# Saving with 300 DPI for print quality
plt.savefig(pdf_path, format='pdf', dpi=300, bbox_inches='tight')
print(f"✅ High-quality PDF saved to: {pdf_path} ")

plt.show()

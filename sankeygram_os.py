import pandas as pd
import networkx as nx
import matplotlib
matplotlib.use('Agg') # Non-interactive backend for server/script use
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
import seaborn as sns
import numpy as np
import os
import glob
import json
import tldextract
import plotly.graph_objects as go
from itertools import product
from collections import Counter
from scipy.spatial import distance
from publicsuffix2 import PublicSuffixList

# -----------------------------
# 1. CONFIGURATION & PATHS
# -----------------------------
# CSV Data Paths [cite: 1]
VT_CSV_PATH = r""
TRANCO_PATH = r""
ALEXA_PATH  = r""

# JSON Report Path [cite: 33, 34]
VT_REPORTS_DIR = r""

# Visual Theme [cite: 15, 27]
POSTER_BG = "#0A192F"
POSTER_BLOCK = "#112240"
CYBER_ACCENT = "#64FFDA" 
COLOR_MALWARE = "#e74c3c"
COLOR_TRANCO = "#2ecc71"
COLOR_ALEXA = "#f39c12"

# -----------------------------
# 2. HELPER FUNCTIONS
# -----------------------------
tld_extractor = tldextract.TLDExtract(cache_dir=True)
psl = PublicSuffixList()

def parse_ip_list(val):
    """Parses semicolon-separated IP strings[cite: 2]."""
    if not isinstance(val, str): return []
    return [ip.strip() for ip in val.split(";") if ip.strip()]

def base_domain(domain):
    """Reduces domains to eTLD+1 using tldextract[cite: 3]."""
    ext = tld_extractor(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None

def extract_etld_psl(domain):
    """Extracts eTLD+1 using PublicSuffixList[cite: 37]."""
    if pd.isna(domain): return None
    return psl.get_sld(str(domain).lower().strip())

# -----------------------------
# 3. DATA LOADING & PREPROCESSING
# -----------------------------
print("Loading CSV Datasets...")
vt_df = pd.read_csv(VT_CSV_PATH, dtype=str)
tranco_df = pd.read_csv(TRANCO_PATH, header=None, names=["rank", "domain"])
alexa_df  = pd.read_csv(ALEXA_PATH, header=None, names=["rank", "domain"])

# Sets for fast lookup [cite: 1, 38]
tranco_set = set(tranco_df["domain"].str.lower().str.strip())
alexa_set  = set(alexa_df["domain"].str.lower().str.strip())
tranco_top200 = set(tranco_df.sort_values('rank').head(200)['domain'].str.lower().str.strip())
alexa_top200 = set(alexa_df.sort_values('rank').head(200)['domain'].str.lower().str.strip())

# Process main VT CSV [cite: 2, 3]
vt_df["ip_list"] = vt_df["reported_ips"].apply(parse_ip_list)
vt_df["domain"] = vt_df["domain"].str.lower().str.strip().apply(base_domain)
vt_df = vt_df.dropna(subset=["domain"])
exploded = vt_df.explode("ip_list").dropna(subset=["ip_list", "domain"])

# Process JSON Reports for Timeline [cite: 35, 36]
print("Loading VT JSON Reports...")
json_files = glob.glob(os.path.join(VT_REPORTS_DIR, "*.json"))
json_data = []
for file_path in json_files:
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            report = json.load(f)
            sub_date = report.get("first_submission_date")
            rel_domains = report.get("relations", {}).get("domains", [])
            for d in rel_domains:
                json_data.append({"first_submission_date": sub_date, "domain": d})
        except Exception: continue

vt_timeline_df = pd.DataFrame(json_data)
vt_timeline_df['first_submission_date'] = pd.to_datetime(vt_timeline_df['first_submission_date'], errors='coerce')
vt_timeline_df = vt_timeline_df.dropna(subset=['first_submission_date'])

# -----------------------------
# 4. VISUALIZATION FUNCTIONS
# -----------------------------

def generate_three_layer_sankey_pdf(exploded_df, t_set, a_set, filename="Three_Layer_Sankey.pdf", top_m=40, top_ip=10, top_b=20):
    """Creates a 3-layer Sankey: Malware -> Shared IPs -> Benign."""
    exploded_df['type'] = exploded_df['domain'].apply(lambda x: 'benign' if (x in t_set or x in a_set) else 'malware')
    
    # Filter for IPs shared by both malware and benign domains
    ip_stats = exploded_df.groupby('ip_list')['type'].nunique()
    shared_ips = ip_stats[ip_stats == 2].index.tolist()
    filtered = exploded_df[exploded_df['ip_list'].isin(shared_ips)]
    
    # Select top nodes
    t_malware = filtered[filtered['type'] == 'malware']['domain'].value_counts().head(top_m).index.tolist()
    t_ips = filtered['ip_list'].value_counts().head(top_ip).index.tolist()
    t_benign = filtered[filtered['type'] == 'benign']['domain'].value_counts().head(top_b).index.tolist()
    
    all_nodes = t_malware + t_ips + t_benign
    node_indices = {node: i for i, node in enumerate(all_nodes)}
    node_colors = ([COLOR_MALWARE] * len(t_malware)) + (["#bdc3c7"] * len(t_ips)) + ([COLOR_TRANCO] * len(t_benign))
    
    sources, targets, values, link_colors = [], [], [], []
    
    # Layer 1: Malware -> IP
    m_to_ip = filtered[(filtered['domain'].isin(t_malware)) & (filtered['ip_list'].isin(t_ips))]
    for (m, ip), group in m_to_ip.groupby(['domain', 'ip_list']):
        sources.append(node_indices[m]); targets.append(node_indices[ip])
        values.append(len(group)); link_colors.append("rgba(231, 76, 60, 0.2)")
        
    # Layer 2: IP -> Benign
    ip_to_b = filtered[(filtered['ip_list'].isin(t_ips)) & (filtered['domain'].isin(t_benign))]
    for (ip, b), group in ip_to_b.groupby(['ip_list', 'domain']):
        sources.append(node_indices[ip]); targets.append(node_indices[b])
        values.append(len(group)); link_colors.append("rgba(46, 204, 113, 0.2)")

    fig = go.Figure(data=[go.Sankey(
        node=dict(pad=10, thickness=15, label=all_nodes, color=node_colors, line=dict(color="white", width=0.5)),
        link=dict(source=sources, target=targets, value=values, color=link_colors)
    )])
    fig.update_layout(title_text="Infrastructure Flow: Malware → Shared IPs → Benign", font=dict(size=12, color="white"),
                      paper_bgcolor=POSTER_BG, width=1400, height=900)
    
    out_dir = os.path.join(os.getcwd(), "graph_outputs")
    os.makedirs(out_dir, exist_ok=True)
    fig.write_image(os.path.join(out_dir, filename), engine="kaleido")
    print(f"Sankey PDF saved: {filename}")

def generate_timeline_pdf(df, t_200, a_200, filename="Malware_Timeline_Final.pdf"):
    """Generates high-quality PDF timeline."""
    df['domain_clean'] = df['domain'].apply(extract_etld_psl)
    df['month'] = df['first_submission_date'].dt.to_period('M')
    
    vt_tranco = df[df['domain_clean'].isin(t_200)]
    vt_alexa = df[df['domain_clean'].isin(a_200)]
    
    counts = pd.DataFrame({
        'Tranco (Top 200)': vt_tranco.groupby('month')['domain_clean'].count(),
        'Alexa (Top 200)': vt_alexa.groupby('month')['domain_clean'].count()
    }).fillna(0)
    
    counts.index = counts.index.to_timestamp()
    all_months = pd.date_range(start=counts.index.min(), end=counts.index.max(), freq='MS')
    counts = counts.reindex(all_months, fill_value=0) # 
    
    sns.set_theme(style="darkgrid", context="talk")
    plt.figure(figsize=(16, 8), facecolor='white')
    plt.plot(counts.index, counts['Tranco (Top 200)'], color=COLOR_TRANCO, label='Tranco', linewidth=3, marker='o')
    plt.plot(counts.index, counts['Alexa (Top 200)'], color=COLOR_ALEXA, label='Alexa', linewidth=3, marker='s')
    
    plt.gca().xaxis.set_major_locator(mdates.YearLocator())
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y'))
    plt.title("Malware Domain Activity Timeline (Top 200)", fontsize=20, fontweight='bold')
    plt.ylabel("Unique Domain Count")
    plt.legend()
    
    out_dir = os.path.join(os.getcwd(), "graph_outputs")
    os.makedirs(out_dir, exist_ok=True)
    plt.savefig(os.path.join(out_dir, filename), format='pdf', dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Timeline PDF saved: {filename}")

# -----------------------------
# 5. EXECUTION
# -----------------------------
if __name__ == '__main__':
    print("\nStarting Unified Analysis Pipeline...")
    
    # 1. Timeline Visualization
    generate_timeline_pdf(vt_timeline_df, tranco_top200, alexa_top200)
    
    # 2. Three-Layer Sankey
    generate_three_layer_sankey_pdf(exploded, tranco_set, alexa_set)
    
    # 3. Statistical JSD Analysis [cite: 25-28]
    print("\nCalculating Jensen-Shannon Divergence...")
    ip_to_domains = exploded.groupby("ip_list")["domain"].apply(lambda x: set(x))
    global_edge_counter = Counter()
    for domains in ip_to_domains:
        malware = [d for d in domains if d not in tranco_set and d not in alexa_set]
        benign  = [d for d in domains if d in tranco_set or d in alexa_set]
        for m, b in product(malware, benign):
            global_edge_counter[(m, b)] += 1

    all_malware = sorted(list(set(m for (m, b), w in global_edge_counter.items())))
    t_counts, a_counts = np.zeros(len(all_malware)), np.zeros(len(all_malware))
    for i, m in enumerate(all_malware):
        for (mal, ben), w in global_edge_counter.items():
            if mal == m:
                if ben in tranco_set: t_counts[i] += w
                elif ben in alexa_set: a_counts[i] += w
    
    t_prob = (t_counts + 1e-10) / np.sum(t_counts + 1e-10)
    a_prob = (a_counts + 1e-10) / np.sum(a_counts + 1e-10)
    js_dist = distance.jensenshannon(t_prob, a_prob)
    
    print(f"==================================================")
    print(f"JSD: {js_dist**2:.4f} (Perfect Stability = 0.0)")
    print(f"==================================================")
    print("\n✅ All processes complete. Check the 'graph_outputs' folder.")

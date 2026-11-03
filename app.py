# app.py
import os
import sys
import json
import time
import pandas as pd
import altair as alt
import streamlit as st

# 1. Configure Windows liboqs DLL path
dll_dir = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install", "bin"))
if os.path.exists(dll_dir):
    os.environ["OQS_DIR"] = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install"))
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(dll_dir)

from pqc_swap_mechanism import CryptoSwapRouter


# --- Page Configuration ---
st.set_page_config(
    page_title="PQC Agility Migration Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom Styling ---
st.markdown("""
<style>
    .metric-card {
        background-color: #1E222B;
        border: 1px solid #2E3440;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 10px;
    }
    .header-style {
        font-size: 26px;
        font-weight: 700;
        margin-bottom: 5px;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_data
def load_prioritized_data():
    """Job 1: Ingests prioritized CBOM inventory."""
    json_path = "prioritized_cbom.json"
    if not os.path.exists(json_path):
        return pd.DataFrame()
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return pd.DataFrame(data)


@st.cache_data
def load_benchmark_metrics():
    """Job 5: Ingests empirical benchmark metrics."""
    csv_path = "pqc_benchmark_metrics.csv"
    if not os.path.exists(csv_path):
        return pd.DataFrame()
    return pd.read_csv(csv_path)


# --- Application Header ---
st.title("🛡️ Automated, Risk-Aware Crypto-Agility Framework")
st.caption("Post-Quantum Cryptography Migration, Risk Prioritization & Benchmarking Dashboard")
st.markdown("---")

df_cbom = load_prioritized_data()

if df_cbom.empty:
    st.error("[-] prioritized_cbom.json not found! Please run pqc_risk_prioritization.py first.")
    st.stop()

# --- Sidebar Controls ---
st.sidebar.header("Framework Navigation")
view_mode = st.sidebar.radio("Navigation View:", ["Risk Inventory & Heatmap", "Remediation Simulation & Benchmarks"])

urgency_filter = st.sidebar.multiselect(
    "Filter by Urgency:",
    options=df_cbom["migration_urgency"].unique().tolist(),
    default=df_cbom["migration_urgency"].unique().tolist()
)

filtered_df = df_cbom[df_cbom["migration_urgency"].isin(urgency_filter)].reset_index(drop=True)

# Top KPI Summary Cards
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Cryptographic Assets", len(df_cbom))
with col2:
    critical_count = (df_cbom["migration_urgency"] == "Critical").sum()
    st.metric("Critical Urgency Assets", critical_count)
with col3:
    mosca_violators = df_cbom["mosca_violation"].sum()
    st.metric("Mosca Violations (D+T ≥ Q)", f"{mosca_violators} / {len(df_cbom)}")
with col4:
    avg_mps = round(df_cbom["MPS"].mean(), 1)
    st.metric("Average Priority Score (MPS)", avg_mps)

st.markdown("---")

# =====================================================================
# VIEW 1: RISK INVENTORY & HEATMAP (Jobs 1 & 2)
# =====================================================================
if view_mode == "Risk Inventory & Heatmap":
    st.subheader("📋 Cryptographic Asset Inventory & Migration Prioritization")
    
    # Job 1: Clean, readable data table
    display_cols = [
        "bom_ref", "component_name", "algorithm", "key_size_or_curve",
        "migration_urgency", "mosca_sum", "Q_threat_horizon", "mosca_violation", "MPS"
    ]
    st.dataframe(
        filtered_df[display_cols].style.highlight_max(subset=["MPS"], color="#8B0000"),
        use_container_width=True
    )

    st.markdown("---")
    st.subheader("📊 Job 2: Risk Matrix Heatmap (Vulnerability vs Criticality)")

    # Job 2: Altair Heatmap based on MPS values
    heatmap_chart = alt.Chart(df_cbom).mark_rect().encode(
        x=alt.X('crit_weight:O', title='Business Criticality Weight (1-10)', sort='ascending'),
        y=alt.Y('vuln_weight:O', title='Quantum Vulnerability Weight (1-10)', sort='descending'),
        color=alt.Color('MPS:Q', scale=alt.Scale(scheme='redyellowgreen', reverse=True), title='MPS Score'),
        tooltip=[
            alt.Tooltip('component_name:N', title='Asset'),
            alt.Tooltip('algorithm:N', title='Algorithm'),
            alt.Tooltip('migration_urgency:N', title='Urgency'),
            alt.Tooltip('MPS:Q', title='MPS Score'),
            alt.Tooltip('mosca_violation:N', title='Mosca Violated')
        ]
    ).properties(
        width=700,
        height=380,
        title="Cryptographic Asset Migration Risk Distribution"
    )

    text_overlay = heatmap_chart.mark_text(baseline='middle').encode(
        text='algorithm:N',
        color=alt.value('white')
    )

    st.altair_chart(heatmap_chart + text_overlay, use_container_width=True)

# =====================================================================
# VIEW 2: REMEDIATION SIMULATION & BENCHMARKING (Jobs 3, 4 & 5)
# =====================================================================
else:
    st.subheader("⚡ Job 3 & 4: Interactive Remediation & PQC Swap Mechanism")
    st.write("Select an identified vulnerable asset from the prioritized list to trigger the backend PQC simulation.")

    col_select, col_action = st.columns([3, 1])

    with col_select:
        asset_options = {
            f"{row['bom_ref']} | {row['component_name']} (MPS: {row['MPS']})": row['bom_ref']
            for _, row in df_cbom.iterrows()
        }
        selected_label = st.selectbox("Select Target Cryptographic Asset:", list(asset_options.keys()))
        selected_ref = asset_options[selected_label]

    with col_action:
        st.write("") # spacing
        st.write("")
        trigger_migration = st.button("🚀 Simulate PQC Migration", type="primary", use_container_width=True)

    # Job 4: Link button click to Phase 4 CryptoSwapRouter backend
    if trigger_migration:
        st.info(f"[*] Dispatching swap mechanism for **{selected_ref}** to liboqs backend...")
        
        with st.spinner("Executing NIST PQC Key Encapsulation / Signature generation..."):
            router = CryptoSwapRouter()
            t_start = time.perf_counter()
            result = router.dispatch_swap(selected_ref)
            elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)

        st.success(f"Remediation Simulation Completed in **{elapsed_ms} ms**!")
        
        # Display Execution Payload Details
        st.json(result)

    st.markdown("---")
    st.subheader("📈 Job 5: Post-Simulation Empirical Benchmarks")

    df_bench = load_benchmark_metrics()
    if not df_bench.empty:
        tab1, tab2, tab3 = st.tabs(["⚡ Latency Comparisons (ms)", "📦 Size Overheads (Bytes)", "💾 Memory Footprint (KB)"])

        with tab1:
            st.markdown("##### Execution Latency (Key Generation, Encap/Sign, Decap/Verify)")
            latency_chart = alt.Chart(df_bench).transform_fold(
                ['keygen_latency_ms', 'encap_latency_ms', 'decap_latency_ms'],
                as_=['Operation', 'Latency_ms']
            ).mark_bar().encode(
                x=alt.X('primitive:N', title='Cryptographic Primitive'),
                y=alt.Y('Latency_ms:Q', title='Latency (ms)', scale=alt.Scale(type='log')),
                color=alt.Color('Operation:N', title='Operation Phase'),
                tooltip=['primitive:N', 'Operation:N', 'Latency_ms:Q']
            ).properties(height=350)
            st.altair_chart(latency_chart, use_container_width=True)

        with tab2:
            st.markdown("##### Public Key & Ciphertext / Signature Sizes")
            size_chart = alt.Chart(df_bench).transform_fold(
                ['public_key_bytes', 'ciphertext_or_sig_bytes'],
                as_=['Payload_Type', 'Bytes']
            ).mark_bar().encode(
                x=alt.X('primitive:N', title='Cryptographic Primitive'),
                y=alt.Y('Bytes:Q', title='Size (Bytes)'),
                color=alt.Color('Payload_Type:N', title='Artifact Type'),
                tooltip=['primitive:N', 'Payload_Type:N', 'Bytes:Q']
            ).properties(height=350)
            st.altair_chart(size_chart, use_container_width=True)

        with tab3:
            st.markdown("##### Process RAM Delta & System Footprint")
            st.dataframe(df_bench[["primitive", "standard", "ram_delta_kb", "cpu_time_total_ms"]], use_container_width=True)
    else:
        st.warning("[-] Benchmarking dataset (pqc_benchmark_metrics.csv) not found. Run pqc_benchmarking.py first.")
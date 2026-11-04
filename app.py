# app.py
import json
import os
import sys
import time
import altair as alt
import pandas as pd
import streamlit as st

# 1. Configure Windows liboqs DLL path
dll_dir = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install", "bin"))
if os.path.exists(dll_dir):
  os.environ["OQS_DIR"] = os.path.abspath(
      os.path.join(os.getcwd(), "liboqs", "install")
  )
  if hasattr(os, "add_dll_directory"):
    os.add_dll_directory(dll_dir)

from pqc_swap_mechanism import CryptoSwapRouter


# --- Page Configuration ---
st.set_page_config(
    page_title="PQC Agility Migration Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom Styling ---
st.markdown(
    """
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
""",
    unsafe_allow_html=True,
)


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
st.caption(
    "Post-Quantum Cryptography Migration, Risk Prioritization & Benchmarking"
    " Dashboard"
)
st.markdown("---")

df_cbom = load_prioritized_data()

if df_cbom.empty:
  st.error(
      "[-] prioritized_cbom.json not found! Please run"
      " pqc_risk_prioritization.py first."
  )
  st.stop()

# --- Sidebar Controls ---
st.sidebar.header("Framework Navigation")
view_mode = st.sidebar.radio(
    "Navigation View:",
    ["Risk Inventory & Heatmap", "Remediation Simulation & Benchmarks"],
)

urgency_options = (
    df_cbom["migration_urgency"].unique().tolist()
    if "migration_urgency" in df_cbom.columns
    else []
)
urgency_filter = st.sidebar.multiselect(
    "Filter by Urgency:", options=urgency_options, default=urgency_options
)

filtered_df = df_cbom[
    df_cbom["migration_urgency"].isin(urgency_filter)
].reset_index(drop=True)

# Top KPI Summary Cards
col1, col2, col3, col4 = st.columns(4)
with col1:
  st.metric("Total Cryptographic Assets", len(df_cbom))
with col2:
  critical_count = (
      (df_cbom["migration_urgency"] == "Critical").sum()
      if "migration_urgency" in df_cbom.columns
      else 0
  )
  st.metric("Critical Urgency Assets", critical_count)
with col3:
  mosca_violators = (
      df_cbom["mosca_violation"].sum()
      if "mosca_violation" in df_cbom.columns
      else 0
  )
  st.metric("Mosca Violations (D+T ≥ Q)", f"{mosca_violators} / {len(df_cbom)}")
with col4:
  avg_mps = (
      round(df_cbom["MPS"].mean(), 1) if "MPS" in df_cbom.columns else 0.0
  )
  st.metric("Average Priority Score (MPS)", avg_mps)

st.markdown("---")

# =====================================================================
# VIEW 1: RISK INVENTORY & HEATMAP (Jobs 1 & 2)
# =====================================================================
if view_mode == "Risk Inventory & Heatmap":
  st.subheader("📋 Cryptographic Asset Inventory & Migration Prioritization")

  display_cols = [
      col
      for col in [
          "bom_ref",
          "component_name",
          "asset_type",
          "algorithm",
          "key_size_or_curve",
          "discovery_mode",
          "migration_urgency",
          "mosca_sum",
          "Q_threat_horizon",
          "mosca_violation",
          "MPS",
      ]
      if col in filtered_df.columns
  ]

  st.dataframe(
      filtered_df[display_cols].style.highlight_max(
          subset=["MPS"], color="#8B0000"
      ),
      use_container_width=True,
  )

  st.markdown("---")
  st.subheader("📊 Job 2: Risk Matrix Heatmap (Vulnerability vs Criticality)")

  grouped_rows = []
  for (crit, vuln), group in df_cbom.groupby(["crit_weight", "vuln_weight"]):
    algs = sorted(list(group["algorithm"].unique()))
    counts = group["algorithm"].value_counts()
    label_parts = [
        f"{alg} ({counts[alg]}x)" if counts[alg] > 1 else str(alg)
        for alg in algs
    ]

    grouped_rows.append({
        "crit_weight": int(crit),
        "vuln_weight": int(vuln),
        "cell_label": ", ".join(label_parts),
        "asset_count": len(group),
        "MPS": float(group["MPS"].max()),
        "asset_names": " | ".join(group["component_name"].astype(str).tolist()),
        "urgency": (
            group["migration_urgency"].iloc[0]
            if "migration_urgency" in group.columns
            else "N/A"
        ),
        "mosca_violation": (
            bool(group["mosca_violation"].any())
            if "mosca_violation" in group.columns
            else False
        ),
    })

  heatmap_data = pd.DataFrame(grouped_rows)

  x_domain = sorted(df_cbom["crit_weight"].unique().astype(int).tolist())
  y_domain = sorted(
      df_cbom["vuln_weight"].unique().astype(int).tolist(), reverse=True
  )

  base = alt.Chart(heatmap_data).encode(
      x=alt.X(
          "crit_weight:O",
          title="Business Criticality Weight (1-10)",
          scale=alt.Scale(domain=x_domain),
          axis=alt.Axis(labelAngle=0),
      ),
      y=alt.Y(
          "vuln_weight:O",
          title="Quantum Vulnerability Weight (1-10)",
          scale=alt.Scale(domain=y_domain),
          sort="descending",
      ),
  )

  heatmap_rects = base.mark_rect(stroke="#2E3440", strokeWidth=2).encode(
      color=alt.Color(
          "MPS:Q",
          scale=alt.Scale(
              scheme="redyellowgreen", reverse=True, domain=[20, 100]
          ),
          title="Max MPS Score",
      ),
      tooltip=[
          alt.Tooltip("cell_label:N", title="Algorithms"),
          alt.Tooltip("asset_count:Q", title="Total Assets at Point"),
          alt.Tooltip("asset_names:N", title="Components"),
          alt.Tooltip("MPS:Q", title="MPS Score"),
          alt.Tooltip("urgency:N", title="Urgency"),
          alt.Tooltip("mosca_violation:N", title="Mosca Violated (HNDL)"),
      ],
  ).properties(
      width=750, height=400, title="Cryptographic Asset Migration Risk Matrix"
  )

  text_labels = base.mark_text(
      baseline="middle", fontSize=12, fontWeight="bold"
  ).encode(
      text="cell_label:N",
      color=alt.condition(
          alt.datum.MPS > 70, alt.value("#FFFFFF"), alt.value("#000000")
      ),
  )

  st.altair_chart(heatmap_rects + text_labels, use_container_width=True)

# =====================================================================
# VIEW 2: REMEDIATION SIMULATION & BENCHMARKING (Jobs 3, 4 & 5)
# =====================================================================
else:
  st.subheader("⚡ Job 3 & 4: Interactive Remediation & PQC Swap Mechanism")
  st.write(
      "Select an identified vulnerable asset from the prioritized list to"
      " trigger the backend PQC simulation."
  )

  col_select, col_action = st.columns([3, 1])

  with col_select:
    asset_options = {
        f"{row['bom_ref']} | {row['component_name']} (MPS: {row.get('MPS', 'N/A')})": (
            row["bom_ref"]
        )
        for _, row in df_cbom.iterrows()
    }
    selected_label = st.selectbox(
        "Select Target Cryptographic Asset:", list(asset_options.keys())
    )
    selected_ref = asset_options[selected_label]

  with col_action:
    st.write("")
    st.write("")
    trigger_migration = st.button(
        "🚀 Simulate PQC Migration", type="primary", use_container_width=True
    )

  if trigger_migration:
    st.info(
        f"[*] Dispatching swap mechanism for **{selected_ref}** to liboqs"
        " backend..."
    )

    with st.spinner(
        "Executing NIST PQC Key Encapsulation / Signature generation..."
    ):
      router = CryptoSwapRouter()
      t_start = time.perf_counter()
      result = router.dispatch_swap(selected_ref)
      elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)

    st.success(f"Remediation Simulation Completed in **{elapsed_ms} ms**!")
    st.json(result)

  st.markdown("---")
  st.subheader("📈 Job 5: Post-Simulation Empirical Benchmarks")

  df_bench = load_benchmark_metrics()
  if not df_bench.empty:
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "⚡ Latency Comparisons (ms)",
        "📦 Size Overheads (Bytes)",
        "💾 Memory Footprint (KB)",
        "🌐 Network & Wire Overhead (PCAP)",
        "📊 Tier 3: Framework Scalability & Stress Test",
    ])

    with tab1:
      st.markdown(
          "##### Execution Latency (Key Generation, Encap/Sign, Decap/Verify)"
      )
      latency_melted = pd.melt(
          df_bench,
          id_vars=["primitive"],
          value_vars=[
              "keygen_latency_ms",
              "encap_latency_ms",
              "decap_latency_ms",
          ],
          var_name="Operation_Phase",
          value_name="Latency_ms",
      )

      phase_map = {
          "keygen_latency_ms": "Key Generation",
          "encap_latency_ms": "Encapsulate / Sign",
          "decap_latency_ms": "Decapsulate / Verify",
      }
      latency_melted["Operation_Phase"] = latency_melted["Operation_Phase"].map(
          phase_map
      )

      latency_chart = (
          alt.Chart(latency_melted)
          .mark_line(point=alt.OverlayMarkDef(size=80, filled=True))
          .encode(
              x=alt.X(
                  "primitive:N",
                  title="Cryptographic Primitive",
                  axis=alt.Axis(labelAngle=0),
              ),
              y=alt.Y(
                  "Latency_ms:Q",
                  title="Latency (ms, Log Scale)",
                  scale=alt.Scale(type="log"),
              ),
              color=alt.Color(
                  "Operation_Phase:N",
                  title="Operation Phase",
                  scale=alt.Scale(scheme="tableau10"),
              ),
              tooltip=[
                  alt.Tooltip("primitive:N", title="Primitive"),
                  alt.Tooltip("Operation_Phase:N", title="Phase"),
                  alt.Tooltip(
                      "Latency_ms:Q", format=".4f", title="Latency (ms)"
                  ),
              ],
          )
          .properties(height=380)
      )
      st.altair_chart(latency_chart, use_container_width=True)

      st.dataframe(
          df_bench[[
              "primitive",
              "standard",
              "keygen_latency_ms",
              "encap_latency_ms",
              "decap_latency_ms",
              "total_cycle_ms",
          ]],
          use_container_width=True,
      )

    with tab2:
      st.markdown("##### Public Key & Ciphertext / Signature Sizes")
      size_melted = pd.melt(
          df_bench,
          id_vars=["primitive"],
          value_vars=["public_key_bytes", "ciphertext_or_sig_bytes"],
          var_name="Artifact_Type",
          value_name="Bytes",
      )
      size_map = {
          "public_key_bytes": "Public Key",
          "ciphertext_or_sig_bytes": "Ciphertext / Signature",
      }
      size_melted["Artifact_Type"] = size_melted["Artifact_Type"].map(size_map)

      size_chart = (
          alt.Chart(size_melted)
          .mark_bar()
          .encode(
              x=alt.X(
                  "primitive:N",
                  title="Cryptographic Primitive",
                  axis=alt.Axis(labelAngle=0),
              ),
              xOffset="Artifact_Type:N",
              y=alt.Y("Bytes:Q", title="Size (Bytes)"),
              color=alt.Color(
                  "Artifact_Type:N",
                  title="Artifact Type",
                  scale=alt.Scale(scheme="set2"),
              ),
              tooltip=[
                  alt.Tooltip("primitive:N", title="Primitive"),
                  alt.Tooltip("Artifact_Type:N", title="Type"),
                  alt.Tooltip("Bytes:Q", title="Size (Bytes)"),
              ],
          )
          .properties(height=380)
      )
      st.altair_chart(size_chart, use_container_width=True)

      st.dataframe(
          df_bench[[
              "primitive",
              "standard",
              "public_key_bytes",
              "ciphertext_or_sig_bytes",
          ]],
          use_container_width=True,
      )

    with tab3:
      st.markdown("##### Process RAM Delta & System Footprint")
      st.dataframe(
          df_bench[
              ["primitive", "standard", "ram_delta_kb", "cpu_time_total_ms"]
          ],
          use_container_width=True,
      )

    with tab4:
      st.markdown(
          "##### Tier 2: Real-World Wire Transmission & PCAP Trace Evaluation"
      )
      net_csv = "pqc_network_metrics.csv"
      if os.path.exists(net_csv):
        df_net = pd.read_csv(net_csv)

        net_chart = (
            alt.Chart(df_net)
            .mark_bar(size=45)
            .encode(
                x=alt.X(
                    "primitive_negotiated:N",
                    title="Negotiated Handshake Protocol",
                    axis=alt.Axis(labelAngle=0),
                ),
                y=alt.Y(
                    "total_wire_bytes:Q",
                    title="Total Transmitted Wire Volume (Bytes)",
                ),
                color=alt.Color(
                    "primitive_negotiated:N",
                    title="Handshake Protocol",
                    scale=alt.Scale(scheme="category10"),
                ),
                tooltip=[
                    alt.Tooltip("primitive_negotiated:N", title="Protocol"),
                    alt.Tooltip("total_wire_bytes:Q", title="Wire Bytes"),
                    alt.Tooltip(
                        "handshake_duration_ms:Q", title="Duration (ms)"
                    ),
                    alt.Tooltip(
                        "mtu_fragmentation_risk:N", title="MTU Risk (>1500B)"
                    ),
                ],
            )
            .properties(height=340)
        )

        st.altair_chart(net_chart, use_container_width=True)
        st.dataframe(df_net, use_container_width=True)
      else:
        st.info(
            "Run `python analyze_tier2_pcaps.py` to generate the network"
            " metrics dataset."
        )

    with tab5:
      st.markdown(
          "##### Tier 3: Operational Throughput & Large-Scale Inventory"
          " Processing"
      )
      stress_csv = "tier3_scalability_metrics.csv"
      if os.path.exists(stress_csv):
        df_stress = pd.read_csv(stress_csv)

        col_a, col_b = st.columns(2)
        with col_a:
          latency_melt = pd.melt(
              df_stress,
              id_vars=["asset_scale_n"],
              value_vars=[
                  "cbom_ingestion_ms",
                  "prioritization_engine_ms",
                  "total_latency_ms",
              ],
              var_name="Pipeline_Stage",
              value_name="Latency_ms",
          )
          stage_map = {
              "cbom_ingestion_ms": "CBOM Ingestion",
              "prioritization_engine_ms": "Prioritization Engine",
              "total_latency_ms": "Total Framework Latency",
          }
          latency_melt["Pipeline_Stage"] = latency_melt["Pipeline_Stage"].map(
              stage_map
          )

          chart_scaling = (
              alt.Chart(latency_melt)
              .mark_line(point=alt.OverlayMarkDef(size=60, filled=True))
              .encode(
                  x=alt.X(
                      "asset_scale_n:Q",
                      title="Cryptographic Assets (N)",
                      scale=alt.Scale(type="linear"),
                  ),
                  y=alt.Y("Latency_ms:Q", title="Processing Latency (ms)"),
                  color=alt.Color(
                      "Pipeline_Stage:N",
                      title="Stage",
                      scale=alt.Scale(scheme="category10"),
                  ),
                  tooltip=[
                      alt.Tooltip("asset_scale_n:Q", title="Assets (N)"),
                      alt.Tooltip("Pipeline_Stage:N", title="Stage"),
                      alt.Tooltip(
                          "Latency_ms:Q", format=".2f", title="Latency (ms)"
                      ),
                  ],
              )
              .properties(
                  height=340,
                  title="Linear Execution Latency vs Inventory Scale (O(N))",
              )
          )
          st.altair_chart(chart_scaling, use_container_width=True)

        with col_b:
          chart_throughput = (
              alt.Chart(df_stress)
              .mark_bar(size=35, color="#2ca02c")
              .encode(
                  x=alt.X(
                      "asset_scale_n:O",
                      title="Cryptographic Assets (N)",
                      axis=alt.Axis(labelAngle=0),
                  ),
                  y=alt.Y(
                      "throughput_assets_sec:Q",
                      title="Throughput (Assets / Second)",
                  ),
                  tooltip=[
                      alt.Tooltip("asset_scale_n:O", title="Assets (N)"),
                      alt.Tooltip(
                          "throughput_assets_sec:Q",
                          format=",.1f",
                          title="Throughput (assets/sec)",
                      ),
                      alt.Tooltip(
                          "ram_delta_kb:Q",
                          format=",.2f",
                          title="RAM Delta (KB)",
                      ),
                  ],
              )
              .properties(
                  height=340, title="Operational Throughput Velocity"
              )
          )
          st.altair_chart(chart_throughput, use_container_width=True)

        st.markdown("###### Empirical Stress Test Datatable")
        st.dataframe(df_stress, use_container_width=True)
      else:
        st.info(
            "Run `python stress_test_tier3.py` to generate the scale metrics"
            " dataset."
        )
  else:
    st.warning(
        "[-] Benchmarking dataset (pqc_benchmark_metrics.csv) not found. Run"
        " pqc_benchmarking.py first."
    )
# Automated, Risk-Aware Crypto-Agility Framework for Enterprise PQC Migration

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![NIST Standards](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204%20%7C%20205-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Liboqs Native](https://img.shields.io/badge/liboqs-Open%20Quantum%20Safe-orange.svg)](https://openquantumsafe.org/)
[![Streamlit UI](https://img.shields.io/badge/Dashboard-Streamlit-red.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

> **Lead Researcher:** Pravinthiran Manivel  
> **Academic / Industry Project:** Automated, Risk-Aware Crypto-Agility Framework for Enterprise PQC Migration  
> **Hardware & Environment:** MSI Prestige 15 A12UC (Windows 11 / MSVC C++ Build Tools / PowerShell / VS Code) & Streamlit Community Cloud (Debian Linux Container)

---

## Executive Summary & Problem Statement

Modern enterprise infrastructures—particularly in high-stakes environments like financial banking systems, interbank clearing networks, and transaction ledgers—are fundamentally dependent on legacy public-key cryptographic primitives, specifically **RSA** (Integer Factorization) and **ECC** (Elliptic Curve Discrete Logarithm Problem). 

These classical algorithms face catastrophic compromise by Shor's Algorithm running on Cryptographically Relevant Quantum Computers (CRQCs). This reality introduces two critical threats:
1. **Cryptographic Opacity:** Organizations lack dynamic visibility into where active and dormant cryptographic primitives reside within multi-tier software repositories, configurations, and keystores.
2. **Harvest-Now, Decrypt-Later (HNDL) Attacks:** Adversaries are actively intercepting and storing encrypted high-value data (e.g., long-term commercial loans, financial transaction ledgers, digital asset keys) today, anticipating the arrival of CRQCs to decrypt that data retroactively.

Without an automated, risk-aware mechanism to discover these cryptographic assets, prioritize them mathematically using lifecycle constraints, and execute dynamic algorithm replacements to NIST-standardized Post-Quantum Cryptography (PQC) standards (**FIPS 203 ML-KEM**, **FIPS 204 ML-DSA**, and **FIPS 205 SLH-DSA**), organizations risk either premature operational exhaustion or catastrophic compliance failure.

---

## Core Research Definitions

| Research Phase | Core Research Question | Operational Project Objective | Bounded Project Scope |
| :--- | :--- | :--- | :--- |
| **1. Discovery (Visibility)** | How can an enterprise automatically and accurately discover active and dormant cryptographic assets to establish comprehensive visibility? | Develop an automated discovery engine capable of parsing source code and keystores to generate a dynamic Cryptographic Bill of Materials (**CBOM**). | Software repositories and X.509 keystores within a Python and OpenSSL 3 testbed; explicitly excludes hardware security modules (HSMs) and embedded IoT firmware. |
| **2. Risk Assessment (Prioritization)** | By what metrics should organizations evaluate and prioritize cryptographic vulnerability to prevent resource exhaustion during PQC migration? | Formulate a computational risk-quantification matrix prioritizing assets based on threat exposure, data secrecy lifespan, and operational criticality. | Programmatic formulation of **Mosca's Theorem** ($D + T \ge Q$) and Migration Priority Scoring (MPS); excludes organizational compliance and physical side-channel risks. |
| **3. Migration (Crypto-Agility)** | How can finalized PQC algorithms be integrated into legacy architectures to achieve crypto-agility without causing operational disruption? | Design and benchmark an automated crypto-agility framework simulating seamless, dynamic swaps to **FIPS 203**, **FIPS 204**, and **FIPS 205** standards. | Software-based simulation using native `liboqs` bindings; excludes Quantum Key Distribution (QKD) and physical hardware changes. |

---

## Key Contributions

* **Architectural Novelty:** A modular, 4-phase crypto-agility pipeline bridging static/dynamic discovery directly into dynamic, risk-triggered PQC algorithm dispatching.
* **Applied Risk Engine:** Translation of Mosca's theoretical theorem ($D + T \ge Q$) into a deterministic, high-throughput Pandas algorithmic scoring pipeline (Migration Priority Score, MPS $\in [0, 100]$).
* **Empirical Benchmarks:** Open-source, reproducible execution latency, memory footprint (RAM RSS deltas via `psutil`), and public-key/signature expansion metrics across NIST Level 3 lattice and stateless hash primitives.

---

## Repository Architecture & Code File Taxonomy

Every Python script and artifact in this framework addresses a distinct research objective:

```
PQC_Agility_Framework/
├── testbed_repo/                      # Mocked enterprise environment
│   ├── legacy_app.py                 # Planted vulnerable calls (MD5, SHA1, RSA, ECC)
│   └── certs/legacy_bank.crt         # Planted legacy X.509 RSA-2048 certificate
├── cbom.json                         # Discovered CycloneDX 1.6 Cryptographic Bill of Materials
├── pqc_risk_prioritization.py        # Phase 3: Mosca's theorem evaluation & MPS engine
├── verify_phase3.py                  # Phase 3: Automated mathematical & schema audit
├── prioritized_cbom.csv              # Phase 3 export: Tabular prioritized risk register
├── prioritized_cbom.json             # Phase 3 export: Structured prioritized risk register
├── sim_fips203_kem.py                # Phase 4: FIPS 203 (ML-KEM-768) standalone simulation
├── sim_pqc_signatures.py             # Phase 4: FIPS 204 (ML-DSA-65) & FIPS 205 (SLH-DSA) simulation
├── pqc_swap_mechanism.py             # Phase 4: Dynamic agility router & dispatch engine
├── pqc_benchmarking.py               # Phase 4: Empirical profiling engine (time & psutil)
├── verify_phase4.py                  # Phase 4: Automated functional & performance audit
├── pqc_benchmark_metrics.csv         # Phase 4 export: Empirical performance baseline dataset
├── pqc_benchmark_metrics.json        # Phase 4 export: Structured JSON performance dataset
├── app.py                            # Phase 5: Streamlit web dashboard & interactive UI
├── requirements.txt                  # Production dependencies for local & cloud hosting
└── .gitignore                        # Prevents binary bloat (C++ builds, venv, DLLs)
```

### Detailed Purpose of Every Source File

#### 1. `testbed_repo/legacy_app.py` & `legacy_bank.crt`
* **Research Purpose:** Establishes a controlled, reproducible testbed containing deliberately planted cryptographic vulnerabilities representing legacy enterprise systems.
* **Coverage:** Deprecated hashing (`MD5`, `SHA-1`), asymmetric key generation (`RSA-2048`, `ECC SECP256R1`), and an X.509 digital certificate signed with RSA-2048.

#### 2. `cbom.json`
* **Research Purpose:** Represents the CycloneDX 1.6 Cryptographic Bill of Materials generated by the discovery engine. Serves as the single source of truth for cryptographic asset inventory across the enterprise.

#### 3. `pqc_risk_prioritization.py` (Phase 3 Core Engine)
* **Research Purpose:** Translates qualitative risk parameters into quantitative, actionable metrics.
* **Mechanism:**
  * Ingests `cbom.json` and flattens properties into a `pandas.DataFrame`.
  * Computes Mosca's Theorem condition: $\text{Mosca Sum} = D (\text{Shelf Life}) + T (\text{Migration Time}) \ge Q (\text{Threat Horizon})$.
  * Calculates the **Migration Priority Score (MPS)**:
    $$\text{MPS} = (0.45 \times W_{\text{vuln}} + 0.35 \times W_{\text{crit}}) \times 10 + (20 \text{ if } D+T \ge Q \text{ else } 0)$$
  * Exports sorted priority queues to `prioritized_cbom.csv` and `prioritized_cbom.json`.

#### 4. `verify_phase3.py`
* **Research Purpose:** Programmatic auditing script that executes automated unit tests against Phase 3 data structures. Verifies deliverable integrity, validates mathematical correctness of the Mosca inequality, ensures monotonic ordering of MPS values, and checks dual-export schema parity.

#### 5. `sim_fips203_kem.py` (Phase 4: Module-Lattice KEM)
* **Research Purpose:** Implements FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (`ML-KEM-768`, NIST Security Level 3).
* **Mechanism:** Wraps `liboqs` to execute client public/private keypair generation, encapsulation of a 256-bit symmetric shared secret, and decapsulation verification with dual-environment support (native C binaries on Windows; automated simulation fallback for cloud deployment).

#### 6. `sim_pqc_signatures.py` (Phase 4: Digital Signatures)
* **Research Purpose:** Implements FIPS 204 (`ML-DSA-65`, primary lattice-based signature) and FIPS 205 (`SLH_DSA_PURE_SHAKE_128S`, stateless hash-based signature fallback).
* **Mechanism:** Executes end-to-end key generation, payload signing, and public-key signature verification, quantifying the performance differences between lattice and hash signatures.

#### 7. `pqc_swap_mechanism.py` (Phase 4: Crypto-Agility Router)
* **Research Purpose:** Emulates a policy-driven Crypto-Agility Layer.
* **Mechanism:** Accepts an asset identifier (`bom_ref`), parses its primitive type and operational role, and routes the asset to the appropriate PQC primitive (`ML-KEM-768` for key exchange; `ML-DSA-65` for certificates/signatures; `SLH-DSA` for long-term root of trust fallback).

#### 8. `pqc_benchmarking.py` (Phase 4: Empirical Profiling)
* **Research Purpose:** Empirical performance profiling across classical and post-quantum algorithms.
* **Mechanism:** Uses `time.perf_counter_ns()` and `psutil.Process()` to profile execution latency, CPU process time, and memory footprint (RAM delta in KB) across classical baselines (`RSA-2048`, `ECDSA`) and NIST PQC primitives (`ML-KEM-768`, `ML-DSA-65`, `SLH-DSA`). Exports findings to `pqc_benchmark_metrics.csv` and `.json`.

#### 9. `verify_phase4.py`
* **Research Purpose:** Verification testbed for Phase 4. Audits file deliverables, confirms cryptographic match across key encapsulation and signatures, checks agility routing paths, and verifies statistical bounds across all benchmark metrics.

#### 10. `app.py` (Phase 5: Streamlit Web Dashboard)
* **Research Purpose:** Central web interface demonstrating end-to-end framework operations.
* **Features:**
  * **View 1 (Risk Inventory & Heatmap):** Interactive CBOM risk table and coordinate-aggregated Altair Heatmap ($10 \times 10$ risk space) highlighting critical-exposure assets.
  * **View 2 (Remediation & Benchmarks):** Interactive target selection with simulated PQC algorithm replacement, accompanied by log-scale latency plots, key/ciphertext size comparisons, and system resource consumption metrics.

---

## Theoretical Framework: Mosca's Theorem & MPS Formulation

### 1. Mosca's Theorem Integration

Adversarial entities executing Harvest-Now, Decrypt-Later (HNDL) attacks threaten any system where data secrecy must outlive the arrival of a Cryptographically Relevant Quantum Computer (CRQC). The framework evaluates this condition algorithmically:

$$\text{Exposure Condition: } D + T \ge Q$$

* **$D$ (Data Shelf Life / Secrecy Lifespan):** Number of years the underlying data must remain confidential (e.g., 10 years for PKI roots, 7 years for asymmetric transaction keys).
* **$T$ (Migration Time):** Estimated operational duration in years required to refactor, validate, and deploy quantum-safe primitives across infrastructure.
* **$Q$ (Quantum Threat Horizon):** Estimated time until CRQC emergence (calibrated to $7.0$ years).

If $D + T \ge Q$, data protected by the algorithm is immediately vulnerable to collection and future compromise.

### 2. Migration Priority Score (MPS) Formulation

The Migration Priority Score normalizes vulnerability, operational criticality, and exposure risk into a single metric on a 0–100 scale:

$$\text{MPS} = \left( 0.45 \cdot W_{\text{vuln}} + 0.35 \cdot W_{\text{crit}} \right) \times 10 + \left( 20 \cdot \mathbb{I}_{D+T \ge Q} \right)$$

Where:
* $W_{\text{vuln}} \in [0, 10]$ maps algorithm vulnerability ($10.0$ for RSA/ECC broken by Shor's algorithm; $0.0$ for quantum-resistant AES-256).
* $W_{\text{crit}} \in [2, 10]$ maps business criticality ($\text{Critical} = 10.0, \text{High} = 7.0, \text{Medium} = 4.0, \text{Low} = 2.0$).
* $\mathbb{I}_{D+T \ge Q} \in \{0, 1\}$ is the Mosca Violation indicator surcharge ($+20.0$ points when violated).

---

## Empirical Benchmark Findings

The following empirical data was gathered on an Intel Core i7 (MSI Prestige 15 A12UC) running Windows 11 with native MSVC `liboqs` C bindings:

| Primitive Family | Standard | Keygen Latency (ms) | Encap / Sign Latency (ms) | Decap / Verify Latency (ms) | Public Key Size (Bytes) | Ciphertext / Sig Size (Bytes) | System RAM Delta (KB) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RSA-2048** (Baseline) | PKCS#1 v2.2 | 38.8428 ms | 0.9800 ms | 0.0378 ms | 270 B | 256 B | 1,832.0 KB |
| **ML-KEM-768** (KEM) | **NIST FIPS 203** | **0.0720 ms** | **0.0405 ms** | **0.0414 ms** | 1,184 B | 1,088 B | 84.0 KB |
| **ML-DSA-65** (Sig) | **NIST FIPS 204** | **0.1209 ms** | **0.3191 ms** | **0.1020 ms** | 1,952 B | 3,309 B | 48.0 KB |
| **SLH-DSA-SHAKE-128s** | **NIST FIPS 205** | 98.2763 ms | 769.1669 ms | 0.8141 ms | 32 B | 7,856 B | 40.0 KB |

### Key Empirical Takeaways:
1. **Lattice Computational Efficiency:** Key generation in `ML-KEM-768` ($0.072 \text{ ms}$) is over **530× faster** than classical `RSA-2048` ($38.84 \text{ ms}$) due to the polynomial arithmetic efficiency of Module Learning With Errors (M-LWE) over ring structures ($R_q$).
2. **Bandwidth Overhead Trade-off:** `ML-KEM-768` public keys ($1,184 \text{ B}$) and `ML-DSA-65` signatures ($3,309 \text{ B}$) are **4.4×** and **12.9×** larger than their classical counterparts, identifying network MTU fragmentation and certificate chain bloating as key migration engineering constraints.
3. **Stateless Hash Asymmetry:** `SLH-DSA` produces a compact public key ($32 \text{ B}$), but carries a significant signing latency penalty ($769.17 \text{ ms}$), confirming its role as a conservative root-of-trust fallback rather than a high-throughput transaction primitive.

---

## Installation & Local Execution Guide

### Prerequisites
* **Operating System:** Windows 10/11, Linux (Debian/Ubuntu), or macOS.
* **Python:** Version 3.10, 3.11, or 3.12.
* **C++ Build Environment (for local liboqs compilation):** Visual Studio Build Tools (C++ workload) and CMake $\ge 3.20$.

### 1. Clone the Repository
```bash
git clone https://github.com/Pravinthiran/PQC-Crypto-Agility-Framework.git
cd PQC-Crypto-Agility-Framework
```

### 2. Set Up Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Python Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Execute the Full Pipeline (Phases 3 to 5)

**Run Risk Prioritization (Phase 3):**
```powershell
python pqc_risk_prioritization.py
python verify_phase3.py
```

**Run PQC Simulations & Benchmarking (Phase 4):**
```powershell
python sim_fips203_kem.py
python sim_pqc_signatures.py
python pqc_swap_mechanism.py
python pqc_benchmarking.py
python verify_phase4.py
```

**Launch the Interactive Streamlit Dashboard (Phase 5):**
```powershell
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## Publication Outline & Documentation Export

This research is structured for academic publication:

* **Chapter I: Introduction** — The HNDL Threat, CRQC Timelines, Research Objectives, and Scope.
* **Chapter II: Literature Review & Standardization** — NIST FIPS 203/204/205 Standards, Mosca's Theorem, and CBOM Specification Analysis.
* **Chapter III: System Architecture & Methodology** — 4-Subsystem Modular Architecture, Static AST Scanning, and Dynamic OpenSSL Inspection.
* **Chapter IV: Algorithmic Implementation** — Risk Prioritization Logic, MPS Formulation, and Dynamic Agility Routing.
* **Chapter V: Experimental Setup & Testbed Configuration** — Hardware Profile, Synthetic Financial Repository, and Metric Boundaries.
* **Chapter VI: Empirical Benchmarks & Discussion** — Micro-benchmarks (Latency, Key Sizes, RAM RSS Footprint), Operational Viability Analysis, and Network MTU Considerations.
* **Chapter VII: Limitations & Future Work** — Hardware Tokens/HSM Integration, State Machine Refactoring, and Hybrid Classical-PQC TLS 1.3 Handshakes.

---

## References

1. **NIST FIPS 203:** *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, National Institute of Standards and Technology, 2024.
2. **NIST FIPS 204:** *Module-Lattice-Based Digital Signature Standard*, National Institute of Standards and Technology, 2024.
3. **NIST FIPS 205:** *Stateless Hash-Based Digital Signature Standard*, National Institute of Standards and Technology, 2024.
4. **Mosca, M.:** "Cybersecurity in an era with quantum computers: Will we be ready?", *IEEE Security & Privacy*, vol. 13, no. 5, pp. 38–41, 2015.
5. **Open Quantum Safe Project:** *liboqs: C library for quantum-safe cryptographic algorithms*, 2024. [Online]. Available: https://github.com/open-quantum-safe/liboqs
6. **CycloneDX Specification:** *Cryptographic Bill of Materials (CBOM) Standard v1.6*, OWASP Foundation, 2024.

---

## Author & Citation

**Researcher:** Pravinthiran Manivel  
**Repository:** [https://github.com/Pravinthiran/PQC-Crypto-Agility-Framework](https://github.com/Pravinthiran/PQC-Crypto-Agility-Framework)  
**Project:** Automated, Risk-Aware Crypto-Agility Framework for Enterprise PQC Migration
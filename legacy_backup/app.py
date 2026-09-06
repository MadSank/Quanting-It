"""
Quantum-Inspired Cyber Threat Detection for Teleportation-Based Quantum Digital Signatures
Streamlit Interactive Dashboard Application.
"""

import streamlit as st
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import qiskit

from src.teleportation import build_teleportation_circuit
from src.qds_verifier import run_qds_teleportation_experiment
from src.detector import detect_threat
from src.visualization import (
    plot_measurement_distribution,
    plot_attack_sensitivity_curves,
    plot_alice_measurement_distribution
)

# Page Configuration
st.set_page_config(
    page_title="Quantum Threat Detection PoC",
    page_icon="⚛️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS styling for high-end aesthetic
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #3B82F6 0%, #8B5CF6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1.1rem;
        color: #64748B;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0,0,0,0.03);
    }
    .badge-legit {
        background-color: #D1FAE5;
        color: #065F46;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: bold;
        font-size: 1.2rem;
        display: inline-block;
        border: 1px solid #34D399;
    }
    .badge-attack {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: bold;
        font-size: 1.2rem;
        display: inline-block;
        border: 1px solid #F87171;
    }
    .disclaimer-box {
        background-color: #EFF6FF;
        border-left: 4px solid #3B82F6;
        padding: 0.8rem;
        margin-bottom: 1rem;
        border-radius: 4px;
        font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)

# Header Section
st.markdown('<div class="main-title">Quantum-Inspired Cyber Threat Detection</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Teleportation-Based Quantum Digital Signature (QDS) Verification Simulator</div>', unsafe_allow_html=True)

# Disclaimer Box
st.markdown("""
<div class="disclaimer-box">
    <b>ℹ️ Educational Simulation Prototype:</b> This PoC executes on Qiskit Aer quantum simulator.
    No physical quantum hardware is used. The authentication layer uses reference state verification to compute Quantum Bit Error Rates (QBER) and perform statistical hypothesis testing against cyber attacks.
</div>
""", unsafe_allow_html=True)

# Sidebar Controls
st.sidebar.header("⚙️ Simulation Parameters")

# 1. Input State Selection
state_option = st.sidebar.selectbox(
    "Alice's Input Signature State (|ψ⟩):",
    options=["0 (|0⟩ Computational)", "1 (|1⟩ Computational)", "+ (|+⟩ Hadamard)", "- (|-> Hadamard)", "Custom (|ψ(θ,φ)⟩)"],
    index=2
)

# Parse state selection
state_key = state_option.split()[0]
theta, phi = 0.0, 0.0

if state_key == "Custom":
    state_key = "custom"
    col_t, col_p = st.sidebar.columns(2)
    with col_t:
        theta_deg = st.slider("Theta θ (°)", 0, 180, 60)
        theta = np.radians(theta_deg)
    with col_p:
        phi_deg = st.slider("Phi φ (°)", 0, 360, 45)
        phi = np.radians(phi_deg)

# 2. Shot Count
shots = st.sidebar.select_slider(
    "Quantum Measurement Shots (N):",
    options=[100, 250, 500, 1000, 2500, 5000, 10000],
    value=1000
)

# 3. Adversary Attack Configuration
st.sidebar.subheader("🚨 Adversary Eve Configuration")
attack_type = st.sidebar.selectbox(
    "Channel Attack Type:",
    options=[
        "none (Legitimate Operation)",
        "bit_flip (Pauli-X Error)",
        "phase_flip (Pauli-Z Error)",
        "bit_phase_flip (Pauli-Y Error)",
        "depolarizing (Uniform Pauli Noise)",
        "intercept_resend (Measurement Disturbance)"
    ],
    index=1
)

attack_key = attack_type.split()[0]

attack_strength = st.sidebar.slider(
    "Attack Probability / Strength (p):",
    min_value=0.0,
    max_value=1.0,
    value=0.30,
    step=0.05
)

# 4. Statistical Detector Configuration
st.sidebar.subheader("🛡️ Statistical Threat Detector")
alpha = st.sidebar.select_slider(
    "Significance Level (α):",
    options=[0.001, 0.01, 0.05, 0.10],
    value=0.01
)
baseline_noise = st.sidebar.number_input(
    "Baseline Channel Noise Floor (p₀):",
    min_value=0.0,
    max_value=0.10,
    value=0.0,
    step=0.005,
    format="%.3f"
)

# Run Simulation Button
run_btn = st.sidebar.button("🚀 Run Quantum Simulation", type="primary", use_container_width=True)

# Main Navigation Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Live Pipeline Execution",
    "📈 Sensitivity & Threat Curves",
    "🔌 Quantum Circuit Diagram",
    "📚 Math & Protocol Blueprint"
])

# -----------------------------------------------------------------------------
# TAB 1: Live Pipeline Execution
# -----------------------------------------------------------------------------
with tab1:
    # Run simulation automatically or on button click
    legit_res = run_qds_teleportation_experiment(
        state_name=state_key,
        theta=theta,
        phi=phi,
        attack_type="none",
        attack_strength=0.0,
        shots=shots,
        seed_simulator=42
    )

    current_res = run_qds_teleportation_experiment(
        state_name=state_key,
        theta=theta,
        phi=phi,
        attack_type=attack_key,
        attack_strength=attack_strength,
        shots=shots,
        seed_simulator=42
    )

    cur_metrics = current_res["metrics"]

    # Run Detector
    detector_output = detect_threat(
        total_shots=cur_metrics["total_shots"],
        error_count=cur_metrics["error_count"],
        baseline_noise=baseline_noise,
        alpha=alpha
    )

    # Top Status Banner
    st.subheader("Verification & Threat Detection Summary")

    col_status, col_metrics1, col_metrics2, col_metrics3 = st.columns([2, 1, 1, 1])

    with col_status:
        if detector_output["threat_detected"]:
            st.markdown('<div class="badge-attack">🚨 ATTACK DETECTED</div>', unsafe_allow_html=True)
            st.error(f"Adversary tampered with channel (QBER = {cur_metrics['qber']:.2%})")
        else:
            st.markdown('<div class="badge-legit">✅ LEGITIMATE STATE VERIFIED</div>', unsafe_allow_html=True)
            st.success(f"Quantum state intact (Fidelity = {cur_metrics['fidelity']:.2%})")

    with col_metrics1:
        st.metric("Quantum Bit Error Rate (QBER)", f"{cur_metrics['qber']:.2%}", delta=f"{cur_metrics['qber'] - baseline_noise:.2%}", delta_color="inverse")

    with col_metrics2:
        st.metric("State Fidelity", f"{cur_metrics['fidelity']:.2%}")

    with col_metrics3:
        st.metric("Hypothesis Test p-value", f"{detector_output['p_value']:.4e}")

    st.markdown("---")

    # Detailed Statistical Breakdown Cards
    col_stat1, col_stat2, col_stat3, col_stat4 = st.columns(4)
    with col_stat1:
        st.metric("Test Statistic (Z-Score)", f"{detector_output['z_score']:.2f}", help="Standard deviations above expected baseline noise")
    with col_stat2:
        st.metric("Critical Threshold QBER", f"{detector_output['threshold_qber']:.2%}", help=f"Cutoff QBER for alpha={alpha}")
    with col_stat3:
        st.metric("False Acceptance Rate (FAR)", f"{detector_output['far_estimate']:.2%}", help="Estimated probability of missing an attack")
    with col_stat4:
        st.metric("False Rejection Rate (FRR)", f"{detector_output['frr_estimate']:.2%}", help="Probability of false alarm under normal operation")

    # Visualization Plots
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        fig_dist = plot_measurement_distribution(
            legit_metrics=legit_res["metrics"],
            attacked_metrics=cur_metrics if attack_key != "none" and attack_strength > 0 else None
        )
        st.pyplot(fig_dist)

    with col_chart2:
        fig_alice = plot_alice_measurement_distribution(cur_metrics["alice_counts"])
        st.pyplot(fig_alice)

    # Raw Outcome Data Table
    st.subheader("Raw Measurement Shot Statistics")
    df_raw = pd.DataFrame([
        {
            "Scenario": "Legitimate (No Noise)",
            "Total Shots": legit_res["metrics"]["total_shots"],
            "Success Shots (|0⟩)": legit_res["metrics"]["success_count"],
            "Error Shots (|1⟩)": legit_res["metrics"]["error_count"],
            "QBER": f"{legit_res['metrics']['qber']:.4f}",
            "Fidelity": f"{legit_res['metrics']['fidelity']:.4f}"
        },
        {
            "Scenario": f"Current Run ({attack_key}, p={attack_strength})",
            "Total Shots": cur_metrics["total_shots"],
            "Success Shots (|0⟩)": cur_metrics["success_count"],
            "Error Shots (|1⟩)": cur_metrics["error_count"],
            "QBER": f"{cur_metrics['qber']:.4f}",
            "Fidelity": f"{cur_metrics['fidelity']:.4f}"
        }
    ])
    st.dataframe(df_raw, use_container_width=True, hide_index=True)


# -----------------------------------------------------------------------------
# TAB 2: Sensitivity & Threat Curves
# -----------------------------------------------------------------------------
with tab2:
    st.header("📈 Attack Strength Sensitivity Analysis")
    st.write("Sweeps adversary attack probability $p \\in [0.0, 1.0]$ to evaluate detector sensitivity and QBER degradation.")

    col_ctrl1, col_ctrl2 = st.columns(2)
    with col_ctrl1:
        sweep_attack_type = st.selectbox(
            "Select Attack Type for Sensitivity Sweep:",
            options=["bit_flip", "phase_flip", "bit_phase_flip", "depolarizing", "intercept_resend"],
            index=1
        )
    with col_ctrl2:
        num_points = st.slider("Sweep Resolution (Points):", 5, 21, 11)

    if st.button("🔄 Execute Sensitivity Sweep", use_container_width=True):
        with st.spinner("Running quantum simulation parameter sweep..."):
            p_range = np.linspace(0.0, 1.0, num_points)
            sweep_data = []

            for p_val in p_range:
                res = run_qds_teleportation_experiment(
                    state_name=state_key,
                    theta=theta,
                    phi=phi,
                    attack_type=sweep_attack_type,
                    attack_strength=float(p_val),
                    shots=shots,
                    seed_simulator=42
                )
                m = res["metrics"]
                det = detect_threat(m["total_shots"], m["error_count"], baseline_noise=baseline_noise, alpha=alpha)
                sweep_data.append({
                    "attack_strength": p_val,
                    "qber": m["qber"],
                    "fidelity": m["fidelity"],
                    "threat_detected": det["threat_detected"],
                    "p_value": det["p_value"],
                    "z_score": det["z_score"]
                })

            st.session_state["sweep_data"] = sweep_data
            st.session_state["sweep_attack_type"] = sweep_attack_type

    if "sweep_data" in st.session_state:
        sweep_data = st.session_state["sweep_data"]
        fig_sens = plot_attack_sensitivity_curves(
            sweep_results=sweep_data,
            threshold_qber=detect_threat(shots, 0, baseline_noise, alpha)["threshold_qber"]
        )
        st.pyplot(fig_sens)

        st.subheader("Sweep Data Points")
        st.dataframe(pd.DataFrame(sweep_data), use_container_width=True)


# -----------------------------------------------------------------------------
# TAB 3: Quantum Circuit Diagram
# -----------------------------------------------------------------------------
with tab3:
    st.header("🔌 Quantum Teleportation Circuit Structure")
    st.write("Constructed 3-Qubit Teleportation Circuit with Alice Bell Measurement & Bob Correction:")

    circuit_demo = build_teleportation_circuit(state_name=state_key, theta=theta, phi=phi, verification_mode=True)

    fig_circ, ax_circ = plt.subplots(figsize=(10, 4), dpi=150)
    try:
        circuit_demo.draw(output='mpl', ax=ax_circ)
        st.pyplot(fig_circ)
    except Exception as e:
        st.text(str(circuit_demo.draw(output='text')))


# -----------------------------------------------------------------------------
# TAB 4: Math & Protocol Blueprint
# -----------------------------------------------------------------------------
with tab4:
    st.header("📚 Theoretical Blueprint & Mathematics")

    st.markdown("""
    ### 1. Quantum Teleportation Mathematics
    Alice wishes to teleport an arbitrary quantum state $|\\psi\\rangle = \\alpha |0\\rangle + \\beta |1\\rangle$ to Bob using a shared Bell pair $|\\Phi^+\\rangle = \\frac{1}{\\sqrt{2}}(|00\\rangle + |11\\rangle)_{12}$.

    The joint 3-qubit state is:
    $$|\\Psi_0\\rangle = (\\alpha |0\\rangle + \\beta |1\\rangle)_0 \\otimes \\frac{1}{\\sqrt{2}}(|00\\rangle + |11\\rangle)_{12}$$

    Expanding in Alice's Bell basis on qubits 0 and 1 yields:
    $$|\\Psi_0\\rangle = \\frac{1}{2} \\left[ |\\Phi^+\\rangle_{01} (\\alpha|0\\rangle + \\beta|1\\rangle)_2 + |\\Phi^-\\rangle_{01} (\\alpha|0\\rangle - \\beta|1\\rangle)_2 + |\\Psi^+\\rangle_{01} (\\beta|0\\rangle + \\alpha|1\\rangle)_2 + |\\Psi^-\\rangle_{01} (\\beta|0\\rangle - \\alpha|1\\rangle)_2 \\right]$$

    Alice performs a Bell measurement on qubits 0 and 1, yielding 2 classical bits $(c_0, c_1)$:
    - Outcomes **00**: Bob holds $\\alpha|0\\rangle + \\beta|1\\rangle$ (Apply $I$)
    - Outcomes **01**: Bob holds $\\alpha|0\\rangle - \\beta|1\\rangle$ (Apply $Z$)
    - Outcomes **10**: Bob holds $\\beta|0\\rangle + \\alpha|1\\rangle$ (Apply $X$)
    - Outcomes **11**: Bob holds $\\beta|0\\rangle - \\alpha|1\\rangle$ (Apply $X Z$)

    ---

    ### 2. Quantum Digital Signature (QDS) State Authentication Model
    In this prototype, Alice authenticates her transmission by preparing states from a secret basis set $\{|0\\rangle, |1\\rangle, |+\\rangle, |-\\rangle\}$.
    Bob applies the inverse operation $U_{\\text{prep}}^\\dagger$ to the teleported qubit before measurement. Under ideal conditions:
    $$U_{\\text{prep}}^\\dagger \\rho_{\\text{Bob}} U_{\\text{prep}} = |0\\rangle\\langle 0| \\implies \\text{QBER} = 0$$

    ---

    ### 3. Statistical Threat Detection Formula
    Errors follow a **Binomial Distribution**: $k \\sim \\text{Binomial}(N, p_0)$.
    The detector evaluates the sample Z-score:
    $$Z = \\frac{\\hat{p} - p_0}{\\sqrt{\\frac{p_0(1-p_0)}{N}}}$$
    If $p\\text{-value} < \\alpha$, the Null Hypothesis ($H_0$) is rejected, signaling an **Adversary Attack**.

    ---

    ### 4. What is Needed for Production QDS?
    1. **Multi-Port Beamsplitter / Quantum Memories**: To store non-orthogonal reference states across long time delays.
    2. **Decoy State Protocols**: To detect photon-number-splitting attacks in optical implementations.
    3. **Swap Test / Quantum State Tomography**: For direct overlap estimation without pre-shared basis knowledge.
    """)

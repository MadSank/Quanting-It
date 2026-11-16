"""
QUATINIT: Quantum Digital Signature (QDS) Security Operations Console
=====================================================================
Competition Demonstration Platform (SIH 2026 Problem Statement 26141)

Gottesman-Chuang Asymmetric QDS Architecture with Teleportation Transport Adaptation,
Destructive Controlled-SWAP Verification, and Multi-Layer Threat Detection.
"""

from __future__ import annotations

import time
import json
import os
from typing import Dict, Any, Optional, List
import pandas as pd
import streamlit as st

from src.metrics import AttackType, DefenseStatus, AttackResult
from src.qds_verifier import VerificationOutcome, GCVerificationResult
from src.ui_helpers import (
    ProtocolState,
    initialize_protocol_session,
    sign_message,
    verify_packet,
    transfer_to_charlie,
    execute_attack_scenario,
    run_teleportation_transport_demo,
    get_copy_budget_metrics,
    format_masked_key,
    measure_e91_detailed,
    run_staged_demo_pipeline,
    prepare_fresh_transaction_keys,
    are_verifier_keys_consumed,
    ATTACK_CATALOGUE,
    run_chsh_ui_experiment,
    render_chsh_correlation_chart,
    render_chsh_s_chart,
    render_chsh_comparison_chart,
)
from src.chsh import run_chsh_experiment, run_chsh_comparison
from src.ui.theme import inject_css
from src.ui.layout import hero, channel_flow, page_header, section, side_label, params

# ---------------------------------------------------------------------------
# Streamlit Application Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Quatinit · Quantum Digital Signature Console",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="auto",
)

# ---------------------------------------------------------------------------
# Theme & Visual System State Initialization (Theme persists independently)
# ---------------------------------------------------------------------------
if "ui_theme" not in st.session_state:
    st.session_state.ui_theme = "DARK"

if "e91_history" not in st.session_state:
    st.session_state.e91_history = []

if "last_chsh_result" not in st.session_state:
    st.session_state.last_chsh_result = None

if "chsh_comparison" not in st.session_state:
    st.session_state.chsh_comparison = None



# ---------------------------------------------------------------------------
# Visual system: tokens + stylesheet live in src/ui/theme.py
# ---------------------------------------------------------------------------
inject_css(st.session_state.ui_theme)


# ---------------------------------------------------------------------------
# Cryptographic Session Initialization & Persistence
# ---------------------------------------------------------------------------
def init_session(force_reset: bool = False):
    """Safely initialize or reset cryptographic session state while preserving UI theme and logs."""
    if force_reset or "protocol_state" not in st.session_state:
        existing_history = []
        if "protocol_state" in st.session_state and st.session_state.protocol_state is not None:
            existing_history = getattr(st.session_state.protocol_state, "history", [])

        st.session_state.protocol_state = initialize_protocol_session(
            n_positions=32,
            fingerprint_qubits=8,
            private_key_bits=128,
            max_copies=4,
            c1_threshold=0.05,
            c2_threshold=0.20,
        )
        if existing_history:
            st.session_state.protocol_state.history = existing_history

        st.session_state.last_packet = None
        st.session_state.last_bob_result = None
        st.session_state.last_charlie_result = None
        st.session_state.last_attack_result = None
        if "custom_payload" not in st.session_state:
            st.session_state.custom_payload = "AUTHORIZE $1,000,000,000 WIRE SETTLEMENT TO AUDITED ESCROW 9482"
        st.session_state.staged_demo_result = None

init_session(force_reset=False)
state: ProtocolState = st.session_state.protocol_state


# ---------------------------------------------------------------------------
# Sidebar: Console Controls, Theme Settings & Resource Accounting
# ---------------------------------------------------------------------------
with st.sidebar:
    side_label("Session")
    if st.button("Reset cryptographic session", width="stretch", help="Wipe all keys and generate a fresh three-party session"):
        init_session(force_reset=True)
        st.rerun()

    side_label("Protocol parameters")
    params([
        ("Scheme", "Gottesman–Chuang"),
        ("Positions M", "32"),
        ("Fingerprint qubits n", "8 (dim 256)"),
        ("Private key L", "128 bits"),
        ("Copy budget T", "4 / position"),
        ("Thresholds c₁ / c₂", "0.05 / 0.20"),
    ])

    side_label("Public-key ledger")
    budget_stats = get_copy_budget_metrics(state.alice.key_pair, [state.bob.key_register, state.charlie_register])
    active_copies = budget_stats["active_in_circulation"]
    consumed_copies = budget_stats["consumed_copies"]
    total_slots = budget_stats["total_budget_slots"]
    remaining_ratio = active_copies / total_slots if total_slots > 0 else 0.0
    m1, m2 = st.columns(2)
    m1.metric("In circulation", f"{active_copies}/{total_slots}")
    m2.metric("Consumed", f"{consumed_copies}")
    st.progress(remaining_ratio, text=f"Budget remaining {remaining_ratio*100:.0f}%")

    side_label("Holevo bound")
    params([
        ("Accessible info T·n", "32 bits"),
        ("Secret length L", "128 bits"),
        ("Secrecy margin ΔH", "96 bits"),
    ])

    st.divider()
    developer_mode = st.toggle("Diagnostics mode", value=False)


# ---------------------------------------------------------------------------
# Top Header Banner: Security Operations Console Overview
# ---------------------------------------------------------------------------
session_id_short = state.session.session_id[:8] if state.session else "uninitialised"
seq_num = state.session.current_sequence_number if state.session else 0
hero(session_id_short, seq_num, [("info", "Bell monitor active"), ("accept", "ML-DSA-65 bound")])

has_attack = (
    state.last_result is not None
    and state.last_result.attack_type != AttackType.NO_ATTACK
    and not state.last_result.threat_score.is_accepted
)
if has_attack:
    channel_flow(state.last_result.attack_type.value, state.last_result.rejection_code,
                 state.last_result.detection_layer)
else:
    channel_flow()


# ---------------------------------------------------------------------------
# Navigation Tabs (Zero Emojis, Technical Headers)
# ---------------------------------------------------------------------------
tabs = st.tabs([
    "Overview",
    "Keys & copy budgets",
    "Sign & verify",
    "Bell monitor",
    "Threat lab",
    "Guided demo",
])


# ===========================================================================
# TAB 1: OVERVIEW & ARCHITECTURE
# ===========================================================================
with tabs[0]:
    page_header(1, 6, "Overview", "How a Quatinit signature works", "Alice signs by revealing one-time classical keys; Bob and Charlie check them against quantum public keys they hold, using SWAP tests that destroy the copy they use.")

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown(
            """
            <div class="soc-card">
                <h4 style="color: var(--text-bright); margin-top: 0;">01 · Key distribution</h4>
                <p style="font-size: 0.85rem; color: var(--text-muted);">
                    Alice generates classical secret key pairs (k_0, k_1) and prepares phase-encoded quantum fingerprint states
                    |f_k&gt; = (1 / &radic;N) &sum;_j (-1)^{E(k)_j} |j&gt;.
                    Copies are distributed to Bob and Charlie over teleportation-assisted transport channels.
                </p>
                <span class="status-badge status-badge-info">FINITE COPY BUDGET: T=4</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_b:
        st.markdown(
            """
            <div class="soc-card">
                <h4 style="color: var(--text-bright); margin-top: 0;">02 · Signing &amp; transport</h4>
                <p style="font-size: 0.85rem; color: var(--text-muted);">
                    Alice computes session-salted message digest H = SHA-256(m || sess || chal || seq)
                    and reveals the matching classical key k_{m_i} per position.
                    The control-plane transcript is authenticated using auxiliary <strong>NIST ML-DSA-65</strong>.
                </p>
                <span class="status-badge status-badge-info">HYBRID POST-QUANTUM CONTROL</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_c:
        st.markdown(
            """
            <div class="soc-card">
                <h4 style="color: var(--text-bright); margin-top: 0;">03 · Destructive verification</h4>
                <p style="font-size: 0.85rem; color: var(--text-muted);">
                    Bob regenerates the expected quantum fingerprint from Alice's revealed key and executes a
                    destructive <strong>Controlled-SWAP test</strong> against his registered public key copy.
                    A calibrated statistical threshold test (c1, c2) isolates forged states.
                </p>
                <span class="status-badge status-badge-info">CONTROLLED-SWAP TEST OVERLAP</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Core Principles & Boundary Analysis
    section("Guarantees and limits")
    col_g1, col_g2 = st.columns(2)
    with col_g1:
        st.markdown(
            """
            * **Asymmetric Unforgeability**: Verifiers hold quantum public keys that permit verification but are mathematically insufficient to reconstruct Alice's private key.
            * **Transferability & Dispute Resolution**: Verified signatures can be forwarded to Charlie. Thresholds $c_1 < c_2$ mathematically guarantee that Bob cannot accept a signature that Charlie rejects.
            * **Logical Finite-Copy Accounting**: Each verification destructively consumes a quantum copy. Software enforces strict copy accounting; no physical cloning protection is fabricated.
            """
        )
    with col_g2:
        st.markdown(
            """
            * **Holevo Information Barrier**: $T$ public copies provide at most $T \\cdot n = 32$ bits of accessible mutual information, ensuring an entropy margin of $\\Delta H = 96$ bits against Alice's 128-bit private key.
            * **E91-Inspired Bell Channel Monitoring**: Background entanglement pairs monitor the quantum distribution channel for eavesdropping disturbance.
            * **Auxiliary Control-Plane Security**: NIST ML-DSA-65 authenticates classical transcripts, preventing classical man-in-the-middle tampering.
            """
        )

    # Session Activity Log
    if state.history:
        section("Verification history")
        df_hist = pd.DataFrame(state.history).iloc[::-1]
        st.dataframe(
            df_hist,
            width="stretch",
            hide_index=True,
            column_config={
                "is_accepted": st.column_config.CheckboxColumn("Accepted", help="Protocol acceptance status"),
                "mismatch_rate": st.column_config.NumberColumn("Mismatch Rate", format="%.3f"),
                "elapsed_ms": st.column_config.NumberColumn("Latency (ms)", format="%.1f ms"),
            },
        )


# ===========================================================================
# TAB 2: KEY GENERATION & COPY BUDGETS
# ===========================================================================
with tabs[1]:
    page_header(2, 6, "Key generation", "Key material and copy budgets", "Each signature position has two 128-bit private keys and a finite number of quantum public-key copies. Spending a copy is irreversible.")

    col_k1, col_k2 = st.columns(2)

    with col_k1:
        st.markdown(
            """
            <div class="soc-card">
                <div style="font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase;">Signer Private Secret Material</div>
                <h4 style="color: var(--border-alert); margin: 4px 0 8px 0;">ALICE: PRIVATE SIGNING KEYS</h4>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0;">
                    CLASSIFICATION: <strong>CONFIDENTIAL / PRIVATE</strong><br>
                    Two 128-bit private keys (k_0, k_1) per signature position. Maintained securely in memory and never transmitted until signing.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        key_sample_data = []
        for pk in state.alice.key_pair.private_keys[: min(8, state.n_positions)]:
            key_sample_data.append({
                "Position Index": f"Bit {pk.position:02d}",
                "Private Key k_0": format_masked_key(pk.k0),
                "Private Key k_1": format_masked_key(pk.k1),
                "Length": f"{state.alice.key_pair.private_key_length} bits",
            })
        st.dataframe(pd.DataFrame(key_sample_data), width="stretch", hide_index=True)
        st.caption("Displaying first 8 of 32 key pairs. Private bytes are masked to safeguard private secrets.")

    with col_k2:
        st.markdown(
            """
            <div class="soc-card">
                <div style="font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase;">Verifier Public Verification States</div>
                <h4 style="color: var(--text-bright); margin: 4px 0 8px 0;">BOB & CHARLIE: QUANTUM PUBLIC MATERIAL</h4>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0;">
                    CLASSIFICATION: <strong>QUANTUM PUBLIC / DISTRIBUTED</strong><br>
                    Phase-encoded fingerprint states in Hilbert dimension 256 (n=8 qubits) distributed via teleportation transport.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        pub_stats = []
        for reg_name, reg in [("Bob (Primary Verifier)", state.bob.key_register), ("Charlie (Arbiter / Transfer)", state.charlie_register)]:
            avail = sum(1 for c in reg.copies.values() if c.status.name == "AVAILABLE")
            consumed = sum(1 for c in reg.copies.values() if c.status.name == "CONSUMED")
            pub_stats.append({
                "Verifier Entity": reg_name,
                "Position Count": f"{state.n_positions} pairs",
                "State Dimension": f"{state.fingerprint_qubits} qubits (dim 256)",
                "Available Copies": avail,
                "Consumed Copies": consumed,
            })
        st.dataframe(pd.DataFrame(pub_stats), width="stretch", hide_index=True)

        st.markdown(
            """
            <div class="soc-card" style="margin-top: 14px;">
                <h5 style="color: var(--text-bright); margin: 0 0 6px 0;">Phase-Encoded Fingerprint Construction</h5>
                <code class="mono-data">
                |f_k&gt; = (1 / &radic;256) &middot; &sum;_{j=0}^{255} (-1)^{E(k)_j} |j&gt;
                </code>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 8px;">
                    Generated via Hadamard transform followed by BCH phase inversion.
                    Inner product overlap between distinct keys is bounded by |&lang;f_k | f_k'&rang;| &le; 0.25 under BCH codeword separation.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ===========================================================================
# TAB 3: SIGN & VERIFY LIFECYCLE
# ===========================================================================
with tabs[2]:
    page_header(3, 6, "Sign and verify", "Sign a transaction, then verify it twice", "Write a payload, inspect the signed packet, and watch Bob verify it and transfer it to Charlie.")

    def select_preset_scenario(payload_text: str):
        st.session_state.custom_payload = payload_text
        st.session_state.last_packet = None
        st.session_state.last_bob_result = None
        st.session_state.last_charlie_result = None
        prepare_fresh_transaction_keys(st.session_state.protocol_state)

    section("Transaction payload", "01")
    col_inp, col_presets = st.columns([2.2, 1])

    with col_presets:
        st.caption("Presets")
        col_p1, col_p2 = st.columns(2)
        col_p1.button(
            "Bank wire",
            on_click=select_preset_scenario,
            args=("AUTHORIZE $1,000,000,000 WIRE SETTLEMENT TO AUDITED ESCROW 9482",),
            width="stretch",
            help="Load High-Value Interbank Wire Settlement scenario with fresh quantum keys.",
        )
        col_p2.button(
            "Grid command",
            on_click=select_preset_scenario,
            args=("OPERATIONAL_DISPATCH_FEEDER_ISOLATION_SUBSTATION_04",),
            width="stretch",
            help="Load Critical Grid Feeder Isolation Command scenario with fresh quantum keys.",
        )

    with col_inp:
        message_input = st.text_input(
            "Plaintext payload",
            key="custom_payload",
            help="Enter plaintext transaction payload to sign.",
        )

    if st.button("Sign as Alice", type="primary"):
        if are_verifier_keys_consumed(state):
            prepare_fresh_transaction_keys(state)

        packet, elapsed_ms = sign_message(state, message_input)
        st.session_state.last_packet = packet
        st.session_state.last_bob_result = None
        st.session_state.last_charlie_result = None
        st.success(f"Signature successfully generated in {elapsed_ms:.1f} ms.")

    # Display Active Packet Details
    if st.session_state.last_packet is not None:
        pkt = st.session_state.last_packet
        st.markdown("---")
        section("Signed packet", "02")

        col_pkt1, col_pkt2, col_pkt3 = st.columns(3)
        with col_pkt1:
            st.markdown(
                f"""
                <div class="soc-card">
                    <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Session-Bound Digest (SHA-256)</div>
                    <div class="mono-data" style="color: var(--text-bright); word-break: break-all;">
                        {pkt.message_hash[:24]}...{pkt.message_hash[-16:]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_pkt2:
            st.markdown(
                f"""
                <div class="soc-card">
                    <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Auxiliary ML-DSA-65 Signature</div>
                    <div class="mono-data" style="color: var(--border-success); word-break: break-all;">
                        {pkt.ml_dsa_signature[:24]}...{pkt.ml_dsa_signature[-16:]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_pkt3:
            st.markdown(
                f"""
                <div class="soc-card">
                    <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Revealed Key Count</div>
                    <div class="mono-data" style="color: var(--text-main);">
                        {len(pkt.qds_signature.revealed_keys)} / {state.n_positions} keys revealed
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("---")
        section("Verification by Bob and Charlie", "03")
        col_v1, col_v2 = st.columns(2)

        with col_v1:
            st.markdown("##### PRIMARY VERIFICATION (BOB)")
            if st.button("Verify as Bob (SWAP tests)", width="stretch"):
                res_bob, elapsed_v = verify_packet(state, pkt)
                st.session_state.last_bob_result = res_bob

            if st.session_state.last_bob_result is not None:
                res = st.session_state.last_bob_result
                score = res.threat_score

                if score.is_accepted:
                    st.markdown(
                        """
                        <div class="soc-card-success">
                            <span class="status-badge status-badge-accept">STATUS: ACCEPTED (1-ACC)</span><br><br>
                            Signature verified successfully. Statistical mismatch rate is within acceptance threshold c1 (5.0%).
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f"""
                        <div class="soc-card-alert">
                            <span class="status-badge status-badge-reject">STATUS: REJECTED</span><br><br>
                            Rejection Code: <strong>{res.rejection_code}</strong> | Detection Layer: <strong>{res.detection_layer}</strong>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                m1, m2, m3 = st.columns(3)
                m1.metric("Mismatch Rate", f"{score.qds_mismatch_rate*100:.1f}%")
                m2.metric("Accept Threshold (c1)", "5.0%")
                m3.metric("Rejection Threshold (c2)", "20.0%")

        with col_v2:
            st.markdown("##### TRANSFER VERIFICATION (CHARLIE)")
            st.caption("Bob forwards the validated transaction to Charlie. Charlie independently verifies it using arbiter threshold c2.")
            if st.button("Transfer to Charlie and verify", width="stretch"):
                charlie_res, elapsed_c = transfer_to_charlie(state, pkt)
                st.session_state.last_charlie_result = charlie_res

            if st.session_state.last_charlie_result is not None:
                c_res = st.session_state.last_charlie_result
                if c_res.outcome in (VerificationOutcome.ACC_1, VerificationOutcome.ACC_0):
                    st.markdown(
                        f"""
                        <div class="soc-card-success">
                            <span class="status-badge status-badge-accept">TRANSFER STATUS: ACCEPTED ({c_res.outcome.value})</span><br><br>
                            Charlie independently verified signature against threshold c2. Non-repudiation guaranteed.
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f"""
                        <div class="soc-card-alert">
                            <span class="status-badge status-badge-reject">TRANSFER STATUS: REJECTED ({c_res.outcome.value})</span><br><br>
                            Charlie rejected transferred signature. Dispute initiated.
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                c1, c2 = st.columns(2)
                c1.metric("Charlie Mismatches", f"{c_res.n_failures} / {c_res.n_positions}")
                c2.metric("Charlie Mismatch Rate", f"{c_res.mismatch_rate*100:.1f}%")


# ===========================================================================
# TAB 4: E91 BELL-CORRELATION MONITORING & TELEPORTATION
# ===========================================================================
with tabs[3]:
    page_header(4, 6, "Channel monitoring", "Bell monitor and teleportation transport", "Entangled pairs reveal an eavesdropper through broken correlations. The CHSH test and teleportation trace sit underneath.")

    st.markdown(
        """
        <div class="soc-card">
            <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0;">
                <strong>SCIENTIFIC SPECIFICATION</strong>: This component is an <em>E91-inspired monitoring mechanism rather than a complete E91 QKD implementation</em>.
                It monitors quantum channel integrity by measuring entanglement correlation preservation across distributed Bell pairs.
                Disturbance caused by eavesdropping (e.g. intercept-resend) disrupts these correlations, tripping the detection layer prior to signature verification.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    section("How the Bell monitor works")
    st.markdown(
        """
        ```text
        ENTANGLED PAIR PREPARATION ---> EPR DISTRIBUTION ---> MEASUREMENT BASES (X/Z) ---> CORRELATION ANALYSIS ---> BASELINE COMPARISON ---> INTEGRITY ASSESSMENT
                    |                                                    |
             Alice (|Phi+>)                                         Bob (|Phi+>)
        ```
        """
    )

    # Interactive E91 Scan Panel
    col_e_ctrl, col_e_metric = st.columns([1.2, 1.8])

    with col_e_ctrl:
        st.markdown("##### Channel Scan Configuration")
        e91_pairs = st.slider("Bell pairs sampled", min_value=50, max_value=250, value=100, step=25)
        e91_attack_type = st.selectbox(
            "Channel Disturbance Simulation",
            options=["NONE", "INTERCEPT_RESEND"],
            format_func=lambda s: "CLEAN CHANNEL (NO EAVESDROPPING)" if s == "NONE" else "EVE INTERCEPT-RESEND ATTACK",
        )

        if st.button("Run correlation scan", type="primary", width="stretch"):
            e_result = measure_e91_detailed(num_pairs=e91_pairs, attack_type=e91_attack_type)
            st.session_state.last_e91_scan = e_result
            st.session_state.e91_history.append({
                "Timestamp": time.strftime("%H:%M:%S"),
                "Pairs": e91_pairs,
                "Attack": e91_attack_type,
                "Error Rate": f"{e_result['error_rate']*100:.1f}%",
                "Matches": e_result["matches"],
                "Status": e_result["channel_status"],
            })

    with col_e_metric:
        scan_data = getattr(st.session_state, "last_e91_scan", None)
        if scan_data is None:
            scan_data = measure_e91_detailed(num_pairs=100, attack_type="NONE")

        st.markdown("##### Live Channel Telemetry")
        m_e1, m_e2, m_e3, m_e4 = st.columns(4)
        m_e1.metric("Error Rate", scan_data["error_rate_pct"])
        m_e2.metric("Baseline Rate", "0.00%")
        m_e3.metric("Threshold", scan_data["threshold_pct"])
        m_e4.metric("Matched-Basis Corr.", f"{scan_data['correlation_coeff']:.3f}")

        status = scan_data["channel_status"]
        if status == "NORMAL":
            st.markdown('<div class="soc-card-success"><span class="status-badge status-badge-accept">CHANNEL STATUS: NORMAL</span><br><br>Entanglement correlations preserved. Channel error rate is below threshold (15.0%).</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="soc-card-alert"><span class="status-badge status-badge-reject">CHANNEL STATUS: {status}</span><br><br>Entanglement correlation collapsed. Intercept-resend eavesdropping detected!</div>', unsafe_allow_html=True)

    # Historical Monitoring Data
    if st.session_state.e91_history:
        st.markdown("##### Recent Correlation Scan History")
        st.dataframe(pd.DataFrame(st.session_state.e91_history).iloc[::-1], width="stretch", hide_index=True)

    with st.expander("How this works", expanded=False):
        st.markdown(
            """
            1. **Entanglement Distribution**: Alice and Bob receive halves of an entangled Bell pair $|\\Phi^+\\rangle = \\frac{1}{\\sqrt{2}}(|00\\rangle + |11\\rangle)$.
            2. **Random Basis Measurement**: Both parties measure in randomly chosen complementary bases (Pauli-Z or Pauli-X).
            3. **Correlation Sifting**: When measurement bases match, legitimate entanglement dictates identical outcomes (0% error rate).
            4. **Adversarial Disturbance**: If Eve intercepts and measures in an arbitrary basis, she collapses the superposition, introducing a theoretical **25.0% error rate** on matched bases.
            5. **Threshold Assessment**: When the measured error rate exceeds the 15.0% threshold, the channel is declared compromised and QDS transport is aborted.
            """
        )

    st.markdown("---")

    # =======================================================================
    # CHSH BELL INEQUALITY TEST & ENTANGLEMENT VERIFICATION
    # =======================================================================
    section("CHSH Bell inequality test")
    st.markdown(
        """
        <div class="soc-card">
            <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0;">
                <strong>NON-LOCALITY & ENTANGLEMENT VERIFICATION</strong>: 
                The Clauser-Horne-Shimony-Holt (CHSH) test evaluates the Bell parameter 
                <code>S = E(a,b) - E(a,b') + E(a',b) + E(a',b')</code> across 4 complementary measurement angles 
                (Alice: <em>a=0, a'=π/2</em>; Bob: <em>b=π/4, b'=3π/4</em>). 
                Any local hidden variable theory is strictly bounded by <strong>|S| ≤ 2.0</strong>. 
                A violation (<code>S > 2.0</code>) certifies genuine quantum non-locality and uncompromised entanglement (ideal Tsirelson bound <strong>S = 2√2 ≈ 2.8284</strong>).
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_chsh_ctrl, col_chsh_view = st.columns([1.2, 1.8])

    with col_chsh_ctrl:
        st.markdown("##### CHSH Experiment Configuration")
        chsh_mode = st.selectbox(
            "Execution Platform",
            options=["IDEAL_SIMULATOR", "NOISY_SIMULATOR", "IBM_HARDWARE"],
            format_func=lambda m: {
                "IDEAL_SIMULATOR": "Local Aer Simulator (Ideal / Noise-Free)",
                "NOISY_SIMULATOR": "Local Aer Simulator (Depolarizing Noise Channel)",
                "IBM_HARDWARE": "Genuine IBM Quantum QPU (Hardware Execution)",
            }[m],
            key="chsh_mode_select",
        )

        chsh_shots = st.select_slider(
            "Shots per Measurement Setting",
            options=[1024, 2048, 4096, 8192, 16384],
            value=4096,
            key="chsh_shots_slider",
        )

        chsh_attack = "NONE"
        chsh_params = {}
        ibm_token_input = None
        ibm_backend_input = "least_busy"
        confirmed_qpu = False

        if chsh_mode == "IDEAL_SIMULATOR":
            chsh_attack = st.selectbox(
                "Channel Disturbance Condition",
                options=["NONE", "INTERCEPT_RESEND"],
                format_func=lambda a: "Clean Channel (Uncompromised Entanglement)" if a == "NONE" else "Eve Intercept-Resend Attack (Entanglement Breaking)",
                key="chsh_ideal_attack",
            )
            if chsh_attack == "INTERCEPT_RESEND":
                eve_basis = st.selectbox(
                    "Eve Intercept Basis Angle θE",
                    options=[0.0, 1.5707963, 0.785398],
                    format_func=lambda ang: f"θE = {ang:.2f} rad ({'Z Basis' if ang == 0 else ('X Basis' if abs(ang - 1.57) < 0.1 else 'Diagonal')})",
                    key="chsh_eve_basis",
                )
                chsh_params["eve_angle"] = eve_basis

        elif chsh_mode == "NOISY_SIMULATOR":
            chsh_attack = "DEPOLARIZING_NOISE"
            noise_str = st.slider(
                "Depolarizing Noise Strength (p)",
                min_value=0.0,
                max_value=0.60,
                value=0.25,
                step=0.05,
                help="Physical 1-qubit depolarizing channel error probability applied to Bob's photon in transit.",
                key="chsh_noise_strength",
            )
            chsh_params["noise_strength"] = noise_str

        elif chsh_mode == "IBM_HARDWARE":
            st.markdown(
                """
                <div class="soc-card-alert" style="margin-bottom: 0.75rem;">
                    <strong>IBM QUANTUM QPU SUBMISSION</strong><br>
                    Hardware execution sends circuits to real physical quantum processors.
                    Requires <code>qiskit-ibm-runtime</code> and valid IBM Quantum API credentials.
                </div>
                """,
                unsafe_allow_html=True,
            )
            env_token = os.environ.get("QISKIT_IBM_TOKEN") or os.environ.get("IBM_QUANTUM_TOKEN")
            token_placeholder = "●●●●●● (Loaded from Environment)" if env_token else "Paste IBM Quantum API Token"
            ibm_token_input = st.text_input(
                "IBM Quantum API Token",
                type="password",
                placeholder=token_placeholder,
                help="Retrieve from quantum.ibm.com/account",
                key="chsh_ibm_token",
            )
            if not ibm_token_input and env_token:
                ibm_token_input = env_token

            ibm_backend_input = st.selectbox(
                "Target IBM QPU Backend",
                options=["least_busy", "ibm_sherbrooke", "ibm_brisbane", "ibm_kyiv"],
                help="Select specific QPU or use least busy operational system.",
                key="chsh_ibm_backend",
            )

            confirmed_qpu = st.checkbox(
                "I explicitly confirm submission to real IBM Quantum hardware",
                value=False,
                key="chsh_qpu_confirm",
            )

        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            run_single = st.button("Run CHSH test", type="primary", width="stretch")
        with col_btn2:
            run_compare = st.button("Run three-way comparison", width="stretch", help="Executes Clean, Depolarizing Noise, and Intercept-Resend in parallel for direct side-by-side analysis.")

        if run_single:
            if chsh_mode == "IBM_HARDWARE" and not confirmed_qpu:
                st.error("Submission aborted: Explicit hardware confirmation checkbox is required.")
            else:
                with st.spinner("Executing CHSH Bell circuits on selected backend..."):
                    exec_res = run_chsh_ui_experiment(
                        shots=chsh_shots,
                        execution_mode=chsh_mode,
                        attack_type=chsh_attack,
                        attack_params=chsh_params,
                        ibm_token=ibm_token_input,
                        ibm_backend=ibm_backend_input,
                        confirmed_hardware=confirmed_qpu,
                    )
                    if exec_res["success"]:
                        st.session_state.last_chsh_result = exec_res["result"]
                        st.session_state.chsh_comparison = None
                    else:
                        st.error(f"Execution Error: {exec_res['error']}")

        if run_compare:
            with st.spinner("Executing comparative 3-way CHSH experiments..."):
                comp_data = run_chsh_comparison(
                    shots=chsh_shots,
                    noise_strength=0.30,
                    eve_angle=0.0,
                )
                st.session_state.chsh_comparison = comp_data
                st.session_state.last_chsh_result = comp_data["CLEAN"]

    with col_chsh_view:
        chsh_res = getattr(st.session_state, "last_chsh_result", None)
        if chsh_res is None:
            chsh_res = run_chsh_experiment(shots=4096, attack_type="NONE")
            st.session_state.last_chsh_result = chsh_res

        st.markdown("##### CHSH Quantum Non-Locality Telemetry")
        m_c1, m_c2, m_c3, m_c4 = st.columns(4)
        m_c1.metric("Measured S", f"{chsh_res.s_value:.3f}", f"±{chsh_res.uncertainty:.3f}")
        m_c2.metric("Classical Bound", "≤ 2.000")
        m_c3.metric("Tsirelson Bound", "2√2 ≈ 2.828")
        sig_text = f"{chsh_res.sigma_violation:.1f}σ" if chsh_res.uncertainty > 0 else "N/A"
        m_c4.metric("Significance", sig_text, f"p={chsh_res.p_value_classical:.1e}")

        # Hardware vs Simulation badge and Violation Status
        mode_badge = (
            '<span class="status-badge status-badge-accept" style="background: #1e1b4b; border-color: #818cf8; color: #c7d2fe;">PLATFORM: IBM HARDWARE QPU</span>'
            if chsh_res.execution_mode == "IBM_HARDWARE"
            else f'<span class="status-badge status-badge-neutral">PLATFORM: {chsh_res.execution_mode}</span>'
        )

        job_info = f"Job ID: <code>{chsh_res.job_id}</code>" if chsh_res.job_id else f"Backend: <code>{chsh_res.backend_name}</code>"

        if chsh_res.violates_classical:
            st.markdown(
                f"""
                <div class="soc-card-success">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="status-badge status-badge-accept">BELL INEQUALITY VIOLATED (S > 2.0)</span>
                        {mode_badge}
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.85rem;">
                        <strong>Quantum Non-Locality Confirmed</strong>: 95% Confidence Interval [{chsh_res.confidence_interval_95[0]:.3f}, {chsh_res.confidence_interval_95[1]:.3f}] strictly excludes local realism (|S| ≤ 2.0). Entangled channel verified with {sig_text} statistical confidence. {job_info}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="soc-card-alert">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="status-badge status-badge-reject">LOCAL BOUND SATISFIED (|S| ≤ 2.0)</span>
                        {mode_badge}
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.85rem;">
                        <strong>Entanglement Disrupted / Classical Mixture</strong>: Measured parameter S = {chsh_res.s_value:.3f} does not violate the classical hidden-variable limit (|S| ≤ 2.0). Indicates channel decoherence or eavesdropper interception. {job_info}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Visualizations
        comp_res = getattr(st.session_state, "chsh_comparison", None)
        if comp_res is not None:
            st.markdown("##### 3-Way Comparative Channel Analysis")
            fig_comp = render_chsh_comparison_chart(comp_res)
            st.pyplot(fig_comp, width="stretch")
            import matplotlib.pyplot as plt
            plt.close(fig_comp)
        else:
            st.markdown("##### Correlation Settings Breakdown")
            fig_corr = render_chsh_correlation_chart(chsh_res)
            st.pyplot(fig_corr, width="stretch")
            import matplotlib.pyplot as plt
            plt.close(fig_corr)

            fig_s = render_chsh_s_chart(chsh_res)
            st.pyplot(fig_s, width="stretch")
            plt.close(fig_s)

        # Correlation details expander and JSON Export
        with st.expander("Measurement data and JSON export", expanded=False):
            corr_rows = []
            for name, c in chsh_res.correlations.items():
                corr_rows.append({
                    "Setting": name,
                    "Alice θA": f"{c.alice_angle:.3f} rad",
                    "Bob θB": f"{c.bob_angle:.3f} rad",
                    "Correlation E": f"{c.correlation:.4f}",
                    "Uncertainty ΔE": f"±{c.uncertainty:.4f}",
                    "Counts (00+11)": c.n_same,
                    "Counts (01+10)": c.n_diff,
                    "Total Shots": c.shots,
                })
            st.dataframe(pd.DataFrame(corr_rows), width="stretch", hide_index=True)

            export_json = json.dumps(chsh_res.to_dict(), indent=2)
            st.download_button(
                label="EXPORT CHSH EXPERIMENT RESULTS (JSON)",
                data=export_json,
                file_name=f"chsh_experiment_{int(time.time())}.json",
                mime="application/json",
                width="stretch",
            )

    st.markdown("---")
    section("Teleportation transport")

    st.markdown(
        """
        <div class="soc-card">
            <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0;">
                <em>Teleportation transports an unknown quantum state using entanglement and classical correction bits.
                Security comes from the surrounding QDS protocol and verification mechanism, not the teleportation transport itself.</em>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_t_in, col_t_out = st.columns([1.2, 1.8])
    with col_t_in:
        st.markdown("##### Transport Circuit Configuration")
        input_state = st.selectbox("Input state", ["+", "-", "0", "1"], index=0, format_func=lambda s: f"State |{s}>")
        channel_err = st.selectbox("Channel noise model", ["NONE", "X", "Z", "DEPOLARIZING"], index=0)
        corrupt_crx = st.checkbox("Corrupt correction bit crx", value=False)
        corrupt_crz = st.checkbox("Corrupt correction bit crz", value=False)

        if st.button("Run teleportation", width="stretch"):
            t_res = run_teleportation_transport_demo(
                input_state_char=input_state,
                channel_error=channel_err,
                corrupt_crx=corrupt_crx,
                corrupt_crz=corrupt_crz,
            )
            st.session_state.teleport_result = t_res

    with col_t_out:
        t_data = getattr(st.session_state, "teleport_result", None)
        if t_data is None:
            t_data = run_teleportation_transport_demo()

        st.markdown("##### Transport Circuit Trace")
        col_m1, col_m2, col_m3 = st.columns(3)
        col_m1.metric("Input State", t_data["input_state"])
        col_m2.metric("State Fidelity", t_data["fidelity_pct"])
        col_m3.metric("Pauli Correction", t_data["pauli_correction"])

        if t_data["reconstructed_successfully"]:
            st.markdown('<div class="soc-card-success"><span class="status-badge status-badge-accept">TRANSPORT STATUS: FIDELITY PRESERVED</span><br><br>State reconstructed at receiver with fidelity &gt; 95%.</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="soc-card-alert"><span class="status-badge status-badge-reject">TRANSPORT STATUS: FIDELITY DEGRADED ({t_data["fidelity_pct"]})</span><br><br>Channel noise or correction tampering corrupted state reconstruction.</div>', unsafe_allow_html=True)


# ===========================================================================
# TAB 5: COMPLETE ATTACK MATRIX & THREAT LAB
# ===========================================================================
with tabs[4]:
    page_header(5, 6, "Threat lab", "Attack matrix and live evaluation", "Every modelled attack, which layer stops it, and a live run against the current session.")

    # Threat Summary Counters
    n_total = len(ATTACK_CATALOGUE)
    n_detected = sum(1 for a in ATTACK_CATALOGUE if a["defense_status"] == "DETECTED")
    n_prevented = sum(1 for a in ATTACK_CATALOGUE if a["defense_status"] == "PREVENTED")
    n_mitigated = sum(1 for a in ATTACK_CATALOGUE if a["defense_status"] == "MITIGATED")
    n_out_of_scope = sum(1 for a in ATTACK_CATALOGUE if a["defense_status"] in ("OUT_OF_SCOPE", "NOT_DETECTABLE"))

    col_sm1, col_sm2, col_sm3, col_sm4, col_sm5 = st.columns(5)
    col_sm1.metric("Total Threat Vectors", f"{n_total}")
    col_sm2.metric("Detected by System", f"{n_detected}")
    col_sm3.metric("Structurally Prevented", f"{n_prevented}")
    col_sm4.metric("Mitigated / Tolerated", f"{n_mitigated}")
    col_sm5.metric("Out of Scope / Non-Tamper", f"{n_out_of_scope}")

    st.markdown("---")
    section("Attack matrix")

    # Filter Controls
    col_f1, col_f2, col_f3 = st.columns([1.5, 1.5, 2])
    categories = ["ALL CATEGORIES"] + sorted(list(set(a["category"] for a in ATTACK_CATALOGUE)))
    statuses = ["ALL STATUSES", "DETECTED", "PREVENTED", "MITIGATED"]

    with col_f1:
        cat_filter = st.selectbox("Category", categories)
    with col_f2:
        status_filter = st.selectbox("Defence status", statuses)
    with col_f3:
        search_query = st.text_input("Search attacks", placeholder="Search by name, component, or detection layer...")

    # Filtered List
    filtered_attacks = ATTACK_CATALOGUE
    if cat_filter != "ALL CATEGORIES":
        filtered_attacks = [a for a in filtered_attacks if a["category"] == cat_filter]
    if status_filter != "ALL STATUSES":
        filtered_attacks = [a for a in filtered_attacks if a["defense_status"] == status_filter]
    if search_query:
        q = search_query.lower()
        filtered_attacks = [
            a for a in filtered_attacks
            if q in a["name"].lower() or q in a["target_component"].lower() or q in a["detection_layer"].lower() or q in a["description"].lower()
        ]

    # Display Filtered Matrix Table
    matrix_rows = []
    for a in filtered_attacks:
        matrix_rows.append({
            "ID": a["attack_id"],
            "Threat Vector": a["name"],
            "Category": a["category"],
            "Target Component": a["target_component"],
            "Defense Status": a["defense_status"],
            "Detection Layer": a["detection_layer"],
            "Typical Mismatch": a["typical_mismatch"],
            "Threat Level": a["threat_level"],
        })
    st.dataframe(pd.DataFrame(matrix_rows), width="stretch", hide_index=True)

    # Attack Detail & Execution Section
    st.markdown("---")
    section("Inspect and run an attack")

    selected_atk_name = st.selectbox(
        "Select Attack Vector for Technical Inspection",
        options=[a["name"] for a in ATTACK_CATALOGUE],
    )
    atk_entry = next(a for a in ATTACK_CATALOGUE if a["name"] == selected_atk_name)

    col_det1, col_det2 = st.columns([1.8, 1.2])

    with col_det1:
        st.markdown(
            f"""
            <div class="soc-card">
                <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Threat Specification — {atk_entry['attack_id']}</div>
                <h4 style="color: var(--text-bright); margin: 4px 0 10px 0;">{atk_entry['name']}</h4>
                <p style="font-size: 0.9rem; color: var(--text-main);"><strong>Description</strong>: {atk_entry['description']}</p>
                <p style="font-size: 0.85rem; color: var(--text-muted);"><strong>Target Component</strong>: {atk_entry['target_component']}</p>
                <p style="font-size: 0.85rem; color: var(--text-muted);"><strong>Detection Method</strong>: {atk_entry['detection_method']}</p>
                <p style="font-size: 0.85rem; color: var(--text-muted);"><strong>System Response</strong>: {atk_entry['system_response']}</p>
                <p style="font-size: 0.85rem; color: var(--text-muted);"><strong>Scientific Basis</strong>: {atk_entry['why_it_fails']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_det2:
        st.markdown(
            f"""
            <div class="soc-card">
                <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Defense Parameters</div>
                <div style="margin: 8px 0;">
                    <span class="status-badge {'status-badge-accept' if atk_entry['defense_status'] == 'PREVENTED' else 'status-badge-reject'}">{atk_entry['defense_status']}</span>
                    <span class="status-badge status-badge-info">{atk_entry['detection_layer']}</span>
                </div>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin: 4px 0;">Expected Mismatch: <strong>{atk_entry['typical_mismatch']}</strong></p>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin: 4px 0;">Threat Rating: <strong>{atk_entry['threat_level']}</strong></p>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin: 4px 0;">Validation Reference: <code>{atk_entry['test_reference']}</code></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        target_payload = st.text_input("Payload to attack", value="TRANSACTION_SETTLEMENT_ORD_9824")
        if st.button("Run attack against live pipeline", type="primary", width="stretch"):
            pkt, atk_res, elapsed_atk = execute_attack_scenario(state, atk_entry["attack_type"], target_payload)
            st.session_state.last_attack_result = atk_res

    # Live Attack Result Display
    if st.session_state.last_attack_result is not None:
        res = st.session_state.last_attack_result
        score = res.threat_score
        threat_lvl = getattr(score, "threat_level", "HIGH" if score and not score.is_accepted else "LOW")
        threat_val = getattr(score, "overall_threat_score", 0.85 if score and not score.is_accepted else 0.05)

        st.markdown("##### Threat Engine Live Evaluation")
        col_res1, col_res2, col_res3, col_res4 = st.columns(4)
        col_res1.metric("Threat Level", threat_lvl)
        col_res2.metric("Threat Score", f"{threat_val:.2f} / 1.00")
        col_res3.metric("Detection Layer", res.detection_layer)
        col_res4.metric("Mismatch Rate", f"{getattr(score, 'qds_mismatch_rate', 0.0)*100:.1f}%")


# ===========================================================================
# TAB 6: ONE-CLICK COMPETITION DEMONSTRATION
# ===========================================================================
with tabs[5]:
    page_header(6, 6, "Guided demo", "End-to-end demonstration", "Run the full pipeline honestly or with an attacker and follow each stage with its timing.")

    st.markdown(
        """
        <div class="soc-card">
            <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0;">
                Designed for live presentation and competition evaluation.
                Executes the complete protocol flow across <strong>7 discrete stages</strong> with real quantum state simulation,
                destructive SWAP test verification, and multi-layer threat scoring.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_ctl_a, col_ctl_b = st.columns([1.2, 1.8])

    with col_ctl_a:
        st.markdown("##### Demonstration Mode")
        demo_mode_sel = st.radio(
            "Scenario",
            options=["Honest transaction", "Adversarial attack"],
            index=0,
        )

        selected_adv_atk = None
        if demo_mode_sel == "Adversarial attack":
            selected_adv_atk = st.selectbox(
                "Attack",
                options=[
                    AttackType.FORGERY_ATTEMPT,
                    AttackType.MESSAGE_TAMPERING,
                    AttackType.INTERCEPT_RESEND,
                    AttackType.REPLAY,
                    AttackType.QUANTUM_DEPOLARIZING,
                    AttackType.SIGNATURE_TAMPERING,
                ],
                format_func=lambda a: a.value,
            )

        if st.button("Run demonstration", type="primary", width="stretch"):
            mode_str = "HONEST" if demo_mode_sel == "Honest transaction" else "ADVERSARIAL"
            with st.spinner("Executing 7-stage protocol pipeline..."):
                demo_output = run_staged_demo_pipeline(
                    mode=mode_str,
                    attack_type=selected_adv_atk,
                    n_positions=32,
                    payload="AUTHORIZE $1,000,000,000 WIRE SETTLEMENT TO AUDITED ESCROW 9482",
                )
                st.session_state.staged_demo_result = demo_output

    with col_ctl_b:
        d_out = getattr(st.session_state, "staged_demo_result", None)
        if d_out is not None:
            if d_out["success"]:
                st.markdown(
                    f"""
                    <div class="soc-card-success">
                        <span class="status-badge status-badge-accept">TRANSACTION STATUS: ACCEPTED</span><br><br>
                        All 7 protocol lifecycle stages executed and validated in <strong>{d_out['total_elapsed_ms']} ms</strong>.<br>
                        Bob verified Controlled-SWAP test (0.0% mismatch) and Charlie accepted dispute transfer.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                    <div class="soc-card-alert">
                        <span class="status-badge status-badge-reject">TRANSACTION STATUS: REJECTED</span><br><br>
                        Adversarial intervention detected and isolated in <strong>{d_out['total_elapsed_ms']} ms</strong>.<br>
                        Threat engine flagged attack. Multi-layer defenses prevented fraudulent acceptance.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    # Visual Process Timeline Display
    if getattr(st.session_state, "staged_demo_result", None) is not None:
        st.markdown("---")
        section("Stage timeline")
        demo_data = st.session_state.staged_demo_result

        for stage in demo_data["stages"]:
            status_cls = "pipeline-step" if stage["status"] in ("COMPLETED", "ACCEPTED") else "pipeline-step-failed"
            badge_cls = "status-badge-accept" if stage["status"] in ("COMPLETED", "ACCEPTED") else ("status-badge-reject" if stage["status"] in ("REJECTED", "FAILED") else "status-badge-warn")

            st.markdown(
                f"""
                <div class="{status_cls}">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 700; font-size: 0.95rem; color: var(--text-bright);">{stage['code']}: {stage['name']}</span>
                        <span class="status-badge {badge_cls}">{stage['status']} ({stage['elapsed_ms']} ms)</span>
                    </div>
                    <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 2px;">ACTOR: {stage['actor']}</div>
                    <p style="font-size: 0.85rem; color: var(--text-main); margin: 6px 0 8px 0;">{stage['summary']}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Expandable Intermediate Technical Artifacts
            with st.expander(f"Inspect {stage['code']} Technical Artifacts", expanded=False):
                st.json(stage["artifacts"])

        # Latency Breakdown Table
        st.markdown("##### Latency Breakdown across Stages")
        timing_rows = [
            {"Stage": s["code"] + " — " + s["name"], "Latency (ms)": f"{s['elapsed_ms']} ms", "Status": s["status"]}
            for s in demo_data["stages"]
        ]
        timing_rows.append({"Stage": "TOTAL PROTOCOL RUNTIME", "Latency (ms)": f"{demo_data['total_elapsed_ms']} ms", "Status": "COMPLETED"})
        st.dataframe(pd.DataFrame(timing_rows), width="stretch", hide_index=True)


# ===========================================================================
# DIAGNOSTICS / DEBUG MODE (OFF BY DEFAULT)
# ===========================================================================
if developer_mode:
    st.markdown("---")
    section("Diagnostics and raw protocol state")
    with st.expander("Session handle and crypto context", expanded=True):
        st.json({
            "session_id": state.session.session_id,
            "challenge": state.session.challenge,
            "current_sequence_number": state.session.current_sequence_number,
            "n_positions": state.n_positions,
            "fingerprint_qubits": state.fingerprint_qubits,
            "trusted_classical_pub_key_prefix": state.trusted_classical_pub_key[:32] + "...",
            "history_log_count": len(state.history),
            "current_ui_theme": st.session_state.ui_theme,
        })

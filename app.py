"""
QUATINIT: Quantum Digital Signature (QDS) Security Operations Console
=====================================================================
Competition Demonstration Platform (SIH 2026 Problem Statement 26141)

Gottesman-Chuang Asymmetric QDS Architecture with Teleportation Transport Adaptation,
Destructive Controlled-SWAP Verification, and Multi-Layer Threat Detection.
"""

from __future__ import annotations

import time
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
)

# ---------------------------------------------------------------------------
# Streamlit Application Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="QUATINIT | Quantum Digital Signature Console",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Theme & Visual System State Initialization (Theme persists independently)
# ---------------------------------------------------------------------------
if "ui_theme" not in st.session_state:
    st.session_state.ui_theme = "DARK"

if "e91_history" not in st.session_state:
    st.session_state.e91_history = []


# ---------------------------------------------------------------------------
# Visual System: Quantum Security Operations Console (Dark & Light Palettes)
# ---------------------------------------------------------------------------
def apply_console_styling(theme: str):
    if theme == "LIGHT":
        css = """
        <style>
            :root {
                --bg-primary: #f8fafc;
                --bg-secondary: #f1f5f9;
                --bg-card: #ffffff;
                --bg-card-secondary: #f8fafc;
                --border-subtle: #cbd5e1;
                --border-accent: #0284c7;
                --border-alert: #dc2626;
                --border-success: #059669;
                --text-main: #0f172a;
                --text-muted: #475569;
                --text-bright: #0284c7;
                --card-alert-bg: #fef2f2;
                --card-success-bg: #f0fdf4;
                --badge-accept-bg: #dcfce7;
                --badge-accept-text: #166534;
                --badge-accept-border: #86efac;
                --badge-reject-bg: #fee2e2;
                --badge-reject-text: #991b1b;
                --badge-reject-border: #fca5a5;
                --badge-info-bg: #e0f2fe;
                --badge-info-text: #0369a1;
                --badge-info-border: #7dd3fc;
                --badge-warn-bg: #fef3c7;
                --badge-warn-text: #92400e;
                --badge-warn-border: #fde68a;
            }
            .stApp {
                background: #f8fafc;
                color: #0f172a;
                font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            }
            header[data-testid="stHeader"] {
                background: #f8fafc;
            }
            section[data-testid="stSidebar"] {
                background-color: #f1f5f9;
                border-right: 1px solid #cbd5e1;
            }
        """
    else:  # DARK MODE
        css = """
        <style>
            :root {
                --bg-primary: #070a12;
                --bg-secondary: #0b1120;
                --bg-card: #0f172a;
                --bg-card-secondary: #131d33;
                --border-subtle: #1e293b;
                --border-accent: #0284c7;
                --border-alert: #b91c1c;
                --border-success: #047857;
                --text-main: #f8fafc;
                --text-muted: #94a3b8;
                --text-bright: #38bdf8;
                --card-alert-bg: #1c0a10;
                --card-success-bg: #061e14;
                --badge-accept-bg: #064e3b;
                --badge-accept-text: #34d399;
                --badge-accept-border: #059669;
                --badge-reject-bg: #7f1d1d;
                --badge-reject-text: #f87171;
                --badge-reject-border: #dc2626;
                --badge-info-bg: #0c4a6e;
                --badge-info-text: #38bdf8;
                --badge-info-border: #0284c7;
                --badge-warn-bg: #78350f;
                --badge-warn-text: #fbbf24;
                --badge-warn-border: #d97706;
            }
            .stApp {
                background: linear-gradient(180deg, #070a12 0%, #0c1222 100%);
                color: #f8fafc;
                font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            }
            header[data-testid="stHeader"] {
                background: #070a12;
            }
            section[data-testid="stSidebar"] {
                background-color: #0b1120;
                border-right: 1px solid #1e293b;
            }
        """

    shared_css = """
        /* Console Card Containers */
        .soc-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 6px;
            padding: 16px 18px;
            margin-bottom: 14px;
        }
        .soc-card-accent {
            background-color: var(--bg-card);
            border: 1px solid var(--border-accent);
            border-radius: 6px;
            padding: 16px 18px;
            margin-bottom: 14px;
        }
        .soc-card-alert {
            background-color: var(--card-alert-bg);
            border: 1px solid var(--border-alert);
            border-radius: 6px;
            padding: 16px 18px;
            margin-bottom: 14px;
        }
        .soc-card-success {
            background-color: var(--card-success-bg);
            border: 1px solid var(--border-success);
            border-radius: 6px;
            padding: 16px 18px;
            margin-bottom: 14px;
        }

        /* Status & Defense Badges */
        .status-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        .status-badge-accept {
            background-color: var(--badge-accept-bg);
            color: var(--badge-accept-text);
            border: 1px solid var(--badge-accept-border);
        }
        .status-badge-reject {
            background-color: var(--badge-reject-bg);
            color: var(--badge-reject-text);
            border: 1px solid var(--badge-reject-border);
        }
        .status-badge-info {
            background-color: var(--badge-info-bg);
            color: var(--badge-info-text);
            border: 1px solid var(--badge-info-border);
        }
        .status-badge-warn {
            background-color: var(--badge-warn-bg);
            color: var(--badge-warn-text);
            border: 1px solid var(--badge-warn-border);
        }

        /* Technical Data Display */
        .mono-data {
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.85rem;
            letter-spacing: 0.3px;
        }

        /* Metric Formatting */
        div[data-testid="stMetricValue"] {
            font-family: 'Consolas', 'Courier New', monospace;
            font-weight: 700;
            font-size: 1.6rem;
            color: var(--text-bright);
        }
        div[data-testid="stMetricLabel"] {
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
        }

        /* Process Pipeline Step Connector */
        .pipeline-step {
            border-left: 3px solid var(--border-accent);
            padding-left: 14px;
            margin-bottom: 12px;
        }
        .pipeline-step-failed {
            border-left: 3px solid var(--border-alert);
            padding-left: 14px;
            margin-bottom: 12px;
        }
    </style>
    """
    st.markdown(css + shared_css, unsafe_allow_html=True)

apply_console_styling(st.session_state.ui_theme)


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
    st.markdown("### CONSOLE CONTROLS")

    # Theme Toggle (Persists across reruns, does NOT touch crypto state)
    selected_theme = st.radio(
        "DISPLAY THEME",
        options=["DARK MODE", "LIGHT MODE"],
        index=0 if st.session_state.ui_theme == "DARK" else 1,
        help="Toggle between Dark and Light console interfaces without affecting cryptographic state.",
    )
    new_theme = "DARK" if "DARK" in selected_theme else "LIGHT"
    if new_theme != st.session_state.ui_theme:
        st.session_state.ui_theme = new_theme
        st.rerun()

    st.markdown("---")
    st.markdown("### SESSION RECOVERY")
    if st.button("RESET CRYPTOGRAPHIC SESSION", use_container_width=True, help="Wipe all keys and generate fresh 3-party session"):
        init_session(force_reset=True)
        st.rerun()

    st.markdown("---")
    st.markdown("### PROTOCOL PARAMETERS")
    st.markdown(
        """
        * **Architecture**: Gottesman-Chuang QDS
        * **Positions (M)**: `32`
        * **Fingerprint Qubits (n)**: `8` (Hilbert dim `256`)
        * **Private Key Length (L)**: `128` bits
        * **Copy Budget (T)**: `4` per position
        * **Thresholds**: $c_1 = 0.05$, $c_2 = 0.20$
        """
    )

    st.markdown("---")
    st.markdown("### PUBLIC-KEY RESOURCE LEDGER")
    budget_stats = get_copy_budget_metrics(state.alice.key_pair, [state.bob.key_register, state.charlie_register])
    active_copies = budget_stats["active_in_circulation"]
    consumed_copies = budget_stats["consumed_copies"]
    total_slots = budget_stats["total_budget_slots"]
    remaining_ratio = active_copies / total_slots if total_slots > 0 else 0.0

    st.metric("Copies in Circulation", f"{active_copies} / {total_slots}")
    st.metric("SWAP-Consumed Copies", f"{consumed_copies}")
    st.progress(remaining_ratio, text=f"Active Budget: {remaining_ratio*100:.1f}%")

    st.markdown("---")
    st.markdown("### HOLEVO ACCESSIBILITY BOUND")
    st.markdown(
        """
        * Max Accessible Info: $T \\cdot n = 32$ bits
        * Private Secret Length: $L = 128$ bits
        * **Entropy Secrecy Margin**: $\\Delta H = 96$ bits
        """
    )

    st.markdown("---")
    developer_mode = st.toggle("DIAGNOSTICS / DEBUG MODE", value=False)


# ---------------------------------------------------------------------------
# Top Header Banner: Security Operations Console Overview
# ---------------------------------------------------------------------------
col_title, col_status = st.columns([2.6, 1.4])
with col_title:
    st.markdown("## QUATINIT — QUANTUM DIGITAL SIGNATURE CONSOLE")
    st.caption("Asymmetric Gottesman-Chuang QDS with Teleportation Transport Adaptation, Controlled-SWAP Verification, and Multi-Layer Threat Detection")

with col_status:
    session_id_short = state.session.session_id[:8] if state.session else "UNINITIALIZED"
    seq_num = state.session.current_sequence_number if state.session else 0

    st.markdown(
        f"""
        <div class="soc-card" style="padding: 10px 14px; margin-top: 6px;">
            <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Active Cryptographic Context</div>
            <div class="mono-data" style="font-weight: 700; color: var(--text-bright); font-size: 0.95rem;">
                SESSION: {session_id_short}... | SEQ: {seq_num}
            </div>
            <div style="margin-top: 6px;">
                <span class="status-badge status-badge-info">BELL MONITOR: ACTIVE</span>
                <span class="status-badge status-badge-accept">ML-DSA-65: BOUND</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Visual Channel Status Indicator
has_attack = (
    state.last_result is not None
    and state.last_result.attack_type != AttackType.NO_ATTACK
    and not state.last_result.threat_score.is_accepted
)

if has_attack:
    attack_name = state.last_result.attack_type.value
    st.markdown(
        f"""
        <div class="soc-card-alert" style="text-align: center;">
            <span class="status-badge status-badge-reject">CHANNEL STATUS: ADVERSARIAL INTERCEPTION DETECTED</span>
            <div class="mono-data" style="margin-top: 6px; font-weight: 700;">
                ALICE [SIGNER] ------------&gt; EVE [{attack_name}] ------------&gt; BOB [VERIFIER]
            </div>
            <div style="margin-top: 6px; font-size: 0.85rem; color: var(--text-muted);">
                Rejection Code: <strong>{state.last_result.rejection_code}</strong> | Detection Layer: <strong>{state.last_result.detection_layer}</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        """
        <div class="soc-card-success" style="text-align: center;">
            <span class="status-badge status-badge-accept">CHANNEL STATUS: SECURE / UNCOMPROMISED</span>
            <div class="mono-data" style="margin-top: 6px; font-weight: 700;">
                ALICE [SIGNER] ===========&gt; QUANTUM CHANNEL [TELEPORTATION TRANSPORT] ===========&gt; BOB [VERIFIER] -----&gt; CHARLIE [ARBITER]
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Navigation Tabs (Zero Emojis, Technical Headers)
# ---------------------------------------------------------------------------
tabs = st.tabs([
    "OVERVIEW & ARCHITECTURE",
    "KEY GENERATION & COPY BUDGETS",
    "SIGN & VERIFY LIFECYCLE",
    "E91 BELL-CORRELATION MONITORING",
    "ATTACK MATRIX & THREAT LAB",
    "ONE-CLICK DEMONSTRATION",
])


# ===========================================================================
# TAB 1: OVERVIEW & ARCHITECTURE
# ===========================================================================
with tabs[0]:
    st.subheader("System Architecture & Operational Topology")

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown(
            """
            <div class="soc-card">
                <h4 style="color: var(--text-bright); margin-top: 0;">01. KEY DISTRIBUTION</h4>
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
                <h4 style="color: var(--text-bright); margin-top: 0;">02. SIGNING & TRANSPORT</h4>
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
                <h4 style="color: var(--text-bright); margin-top: 0;">03. DESTRUCTIVE VERIFICATION</h4>
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
    st.markdown("### Cryptographic Guarantees & Threat Boundaries")
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
        st.markdown("### Verification History Log")
        df_hist = pd.DataFrame(state.history).iloc[::-1]
        st.dataframe(
            df_hist,
            use_container_width=True,
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
    st.subheader("Key Material Generation & Quantum Copy Accounting")

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
        st.dataframe(pd.DataFrame(key_sample_data), use_container_width=True, hide_index=True)
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
        st.dataframe(pd.DataFrame(pub_stats), use_container_width=True, hide_index=True)

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
    st.subheader("Interactive Transaction Signing, Transport & Verification")

    def select_preset_scenario(payload_text: str):
        st.session_state.custom_payload = payload_text
        st.session_state.last_packet = None
        st.session_state.last_bob_result = None
        st.session_state.last_charlie_result = None
        prepare_fresh_transaction_keys(st.session_state.protocol_state)

    st.markdown("#### STEP 01: TRANSACTION PAYLOAD INPUT")
    col_inp, col_presets = st.columns([2.2, 1])

    with col_presets:
        st.write("Preset Scenarios:")
        col_p1, col_p2 = st.columns(2)
        col_p1.button(
            "HIGH-VALUE WIRE",
            on_click=select_preset_scenario,
            args=("AUTHORIZE $1,000,000,000 WIRE SETTLEMENT TO AUDITED ESCROW 9482",),
            use_container_width=True,
            help="Load High-Value Interbank Wire Settlement scenario with fresh quantum keys.",
        )
        col_p2.button(
            "GRID COMMAND",
            on_click=select_preset_scenario,
            args=("OPERATIONAL_DISPATCH_FEEDER_ISOLATION_SUBSTATION_04",),
            use_container_width=True,
            help="Load Critical Grid Feeder Isolation Command scenario with fresh quantum keys.",
        )

    with col_inp:
        message_input = st.text_input(
            "Plaintext Payload",
            key="custom_payload",
            help="Enter plaintext transaction payload to sign.",
        )

    if st.button("EXECUTE SIGNING ROUTINE (ALICE)", type="primary"):
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
        st.markdown("#### STEP 02: INSPECTION OF SIGNED SECUREPACKET")

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
        st.markdown("#### STEP 03: VERIFICATIONS BY BOB & CHARLIE")
        col_v1, col_v2 = st.columns(2)

        with col_v1:
            st.markdown("##### PRIMARY VERIFICATION (BOB)")
            if st.button("EXECUTE CONTROLLED-SWAP VERIFICATION (BOB)", use_container_width=True):
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
            if st.button("TRANSFER TRANSACTION TO CHARLIE & VERIFY", use_container_width=True):
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
    st.subheader("E91-Inspired Bell-Correlation Monitoring & Quantum Transport")

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

    st.markdown("#### CONCEPTUAL FLOW: BELL-CORRELATION MONITORING")
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
        e91_pairs = st.slider("Bell Pairs Sampled", min_value=50, max_value=250, value=100, step=25)
        e91_attack_type = st.selectbox(
            "Channel Disturbance Simulation",
            options=["NONE", "INTERCEPT_RESEND"],
            format_func=lambda s: "CLEAN CHANNEL (NO EAVESDROPPING)" if s == "NONE" else "EVE INTERCEPT-RESEND ATTACK",
        )

        if st.button("EXECUTE BELL CORRELATION SCAN", type="primary", use_container_width=True):
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
        m_e4.metric("Correlation Coeff", f"{scan_data['correlation_coeff']:.3f}")

        status = scan_data["channel_status"]
        if status == "NORMAL":
            st.markdown('<div class="soc-card-success"><span class="status-badge status-badge-accept">CHANNEL STATUS: NORMAL</span><br><br>Entanglement correlations preserved. Channel error rate is below threshold (15.0%).</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="soc-card-alert"><span class="status-badge status-badge-reject">CHANNEL STATUS: {status}</span><br><br>Entanglement correlation collapsed. Intercept-resend eavesdropping detected!</div>', unsafe_allow_html=True)

    # Historical Monitoring Data
    if st.session_state.e91_history:
        st.markdown("##### Recent Correlation Scan History")
        st.dataframe(pd.DataFrame(st.session_state.e91_history).iloc[::-1], use_container_width=True, hide_index=True)

    with st.expander("HOW THIS WORKS — TECHNICAL EXPLANATION", expanded=False):
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
    st.markdown("#### QUANTUM STATE TRANSPORT ADAPTATION (TELEPORTATION)")
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
        input_state = st.selectbox("Input Quantum State", ["+", "-", "0", "1"], index=0, format_func=lambda s: f"State |{s}>")
        channel_err = st.selectbox("Quantum Channel Noise Model", ["NONE", "X", "Z", "DEPOLARIZING"], index=0)
        corrupt_crx = st.checkbox("Corrupt Classical Correction Bit crx", value=False)
        corrupt_crz = st.checkbox("Corrupt Classical Correction Bit crz", value=False)

        if st.button("EXECUTE TELEPORTATION TRANSPORT", use_container_width=True):
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
    st.subheader("Comprehensive Threat Matrix & Defense Verification")

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
    st.markdown("#### ATTACK MATRIX DIRECTORY")

    # Filter Controls
    col_f1, col_f2, col_f3 = st.columns([1.5, 1.5, 2])
    categories = ["ALL CATEGORIES"] + sorted(list(set(a["category"] for a in ATTACK_CATALOGUE)))
    statuses = ["ALL STATUSES", "DETECTED", "PREVENTED", "MITIGATED"]

    with col_f1:
        cat_filter = st.selectbox("Filter by Category", categories)
    with col_f2:
        status_filter = st.selectbox("Filter by Defense Status", statuses)
    with col_f3:
        search_query = st.text_input("Search Threat Vectors", placeholder="Search by name, component, or detection layer...")

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
    st.dataframe(pd.DataFrame(matrix_rows), use_container_width=True, hide_index=True)

    # Attack Detail & Execution Section
    st.markdown("---")
    st.markdown("#### ATTACK DETAIL INSPECTION & LIVE EXECUTION")

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

        target_payload = st.text_input("Payload for Attack Execution", value="TRANSACTION_SETTLEMENT_ORD_9824")
        if st.button("EXECUTE ATTACK IN LIVE PIPELINE", type="primary", use_container_width=True):
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
    st.subheader("Automated End-to-End Demonstration Pipeline")

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
            "Select Scenario Type",
            options=["HONEST TRANSACTION FLOW", "ADVERSARIAL ATTACK FLOW"],
            index=0,
        )

        selected_adv_atk = None
        if "ADVERSARIAL" in demo_mode_sel:
            selected_adv_atk = st.selectbox(
                "Select Adversarial Attack Vector",
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

        if st.button("RUN AUTOMATED DEMONSTRATION", type="primary", use_container_width=True):
            mode_str = "HONEST" if "HONEST" in demo_mode_sel else "ADVERSARIAL"
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
        st.markdown("#### STAGE-BY-STAGE PROCESS TIMELINE")
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
        st.dataframe(pd.DataFrame(timing_rows), use_container_width=True, hide_index=True)


# ===========================================================================
# DIAGNOSTICS / DEBUG MODE (OFF BY DEFAULT)
# ===========================================================================
if developer_mode:
    st.markdown("---")
    st.subheader("DIAGNOSTICS & RAW PROTOCOL STATE")
    with st.expander("Session Internal Handle & Crypto Context", expanded=True):
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

import streamlit as st
import time
from src.attack_simulator import AttackSimulator
from src.metrics import AttackType

st.set_page_config(page_title="Quantum Auth Protocol (Final)", layout="wide", initial_sidebar_state="collapsed")

# Custom CSS for cinematic look
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        color: #00ffcc;
    }
    .metric-label {
        font-size: 1rem;
        color: #888;
    }
    .eve-panel { background-color: #2b0000; padding: 15px; border-radius: 10px; border: 1px solid #ff4444; }
    .alice-panel { background-color: #00112b; padding: 15px; border-radius: 10px; border: 1px solid #4488ff; }
    .quantum-panel { background-color: #002b11; padding: 15px; border-radius: 10px; border: 1px solid #44ff88; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Quantum Message Authentication (Hybrid ML-DSA + QDS)")

# --- Session State ---
if 'sim' not in st.session_state:
    st.session_state.sim = AttackSimulator(64)
if 'attack_type' not in st.session_state:
    st.session_state.attack_type = AttackType.NO_ATTACK
if 'run_id' not in st.session_state:
    st.session_state.run_id = 0

# --- Top Bar ---
comp_mode = st.toggle("🏆 Competition Demo Mode (High Value Payload)")
payload = "AUTHORIZE $1,000,000,000 TRANSFER TO ACCOUNT 9482" if comp_mode else "HELLO BOB"

col_left, col_center, col_right = st.columns([1, 1.5, 1])

# Run Simulation
@st.cache_data(show_spinner=False)
def run_simulation(attack, run_id, msg):
    sim = AttackSimulator(64)
    # Extract packet before verification
    alice, bob, session = sim.setup_environment()
    packet = alice.create_packet(msg, 64)
    
    # Tamper if needed
    if attack == AttackType.SIGNATURE_TAMPERING:
        from src.eve import Eve
        packet = Eve.tamper_ml_dsa_signature(packet)
    elif attack == AttackType.FORGERY_ATTEMPT:
        from src.eve import Eve
        packet.qds_signature = Eve.forge_signature(
            packet.message_hash, "deadbeef", 64, packet.session_id, packet.sequence_number
        )
    elif attack == AttackType.HASH_TAMPERING:
        from src.eve import Eve
        packet = Eve.tamper_hash(packet, "deadbeef00000000000000000000000000000000000000000000000000000000")
        
    e91_sim = "INTERCEPT_RESEND" if attack == AttackType.E91_CHANNEL_DISTURBANCE else "NONE"
    
    start_time = time.time()
    res = bob.verify_packet(packet, simulate_e91_attack=e91_sim)
    elapsed = time.time() - start_time
    
    return packet, res, elapsed

packet, res, elapsed = run_simulation(st.session_state.attack_type, st.session_state.run_id, payload)
score = res.threat_score

# ==========================================
# LEFT: EVE / HACKER
# ==========================================
with col_left:
    st.markdown('<div class="eve-panel">', unsafe_allow_html=True)
    st.subheader("🕵️ Eve (Attacker)")
    
    attack_map = {
        "None (Safe)": AttackType.NO_ATTACK,
        "Tamper ML-DSA Signature": AttackType.SIGNATURE_TAMPERING,
        "Forge QDS State": AttackType.FORGERY_ATTEMPT,
        "Intercept & Resend (E91)": AttackType.E91_CHANNEL_DISTURBANCE,
        "Tamper SHA-256 Hash": AttackType.HASH_TAMPERING
    }
    
    selected_attack = st.selectbox("Select Attack Vector", list(attack_map.keys()))
    if st.button("🚀 Transmit Packet"):
        st.session_state.attack_type = attack_map[selected_attack]
        st.session_state.run_id += 1
        st.rerun()

    st.markdown("---")
    st.markdown("### 🚨 Threat Analysis")
    
    if score.is_accepted:
        st.success("✅ PACKET ACCEPTED")
    else:
        st.error(f"❌ REJECTED: {res.rejection_code}")
        st.error(f"Layer: {res.detection_layer}")
        
    st.progress(score.overall_confidence, text=f"Confidence: {score.overall_confidence*100:.1f}%")
    st.markdown('</div>', unsafe_allow_html=True)

# ==========================================
# CENTER: ALICE -> BOB / CLASSICAL
# ==========================================
with col_center:
    st.markdown('<div class="alice-panel">', unsafe_allow_html=True)
    st.subheader("📜 Classical Verification (ML-DSA)")
    
    st.markdown(f"**Payload**: `{packet.message}`")
    st.markdown(f"**SHA-256**: `{packet.message_hash[:16]}...{packet.message_hash[-16:]}`")
    
    ct = packet.metadata.get("canonical_transcript", "")
    parts = ct.split("||")
    if len(parts) >= 4:
        st.markdown("**Canonical Transcript Bound:**")
        st.code(f"Session: {parts[0]}\nSeq: {parts[1]}\nHash: {parts[2]}\nQ-Meta: {parts[4]}", language="text")
    
    ml_dsa_sig = packet.ml_dsa_signature or ""
    if ml_dsa_sig:
        st.markdown("**ML-DSA-65 Signature:**")
        st.code(f"{ml_dsa_sig[:32]}......{ml_dsa_sig[-32:]}")
        if score.ml_dsa_valid:
            st.success("✅ ML-DSA FIPS-204 Signature Valid")
        else:
            st.error("❌ ML-DSA Signature Verification FAILED")
    
    st.markdown(f"*Verification Time: {elapsed*1000:.2f} ms*")
    st.markdown('</div>', unsafe_allow_html=True)


# ==========================================
# RIGHT: QUANTUM CHANNEL
# ==========================================
with col_right:
    st.markdown('<div class="quantum-panel">', unsafe_allow_html=True)
    st.subheader("⚛️ Quantum Channel (Qiskit)")
    
    st.metric("E91 Disturbance Rate", f"{score.e91_error_rate*100:.1f}%", delta_color="inverse")
    if score.e91_error_rate > 0.15:
        st.error("⚠️ ENTANGLEMENT BROKEN")
    else:
        st.success("✅ Channel Secure")
        
    st.markdown("---")
    
    st.metric("QDS Mismatch Rate", f"{score.qds_mismatch_rate*100:.1f}%", delta_color="inverse")
    if score.qds_mismatch_rate > 0.05:
        st.error("⚠️ QDS MISMATCH DETECTED")
    else:
        st.success("✅ QDS Proof Valid")

    st.markdown('</div>', unsafe_allow_html=True)


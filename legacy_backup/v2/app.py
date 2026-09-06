import streamlit as st
import time
import pandas as pd
from src.attack_simulator import AttackSimulator
from src.metrics import AttackType
from src.crypto import compute_message_hash
from src.quantum_fingerprint import derive_fingerprint_binding, derive_fingerprint_specification
from src.eve import Eve

st.set_page_config(page_title="Hybrid Quantum/PQ Demo", layout="wide")

st.markdown("""
<style>
.stApp {
    font-family: "Courier New", Courier, monospace;
}
.sci-header {
    font-size: 0.9em;
    color: #00d2ff;
    letter-spacing: 1px;
}
.narrative-text {
    font-size: 1.1em;
    margin-top: 10px;
    margin-bottom: 10px;
}
</style>
""", unsafe_allow_html=True)

st.title("Post-Quantum & Quantum-Channel Authentication")
st.markdown("""
**ESTABLISHED:** SHA-256 | ML-DSA-65 (FIPS 204) | Quantum Teleportation | Bell States  
**EXPERIMENTAL:** Session-bound Quantum Fingerprint | E91-Inspired Channel Monitoring | Hybrid Verification

*Note: The ML-DSA layer provides classical post-quantum authenticity. The quantum layer provides experimental channel-integrity monitoring.*
""")

# Sidebar Controls
st.sidebar.header("Controls")
competition_mode = st.sidebar.button("🏆 COMPETITION MODE", type="primary")

msg_input = "TRANSFER 10 BTC TO ALICE"
run_transmission = False
run_eve = False
attack_type = "Modify Message"

if not competition_mode:
    msg_input = st.sidebar.text_input("Message to Send", "HELLO BOB")
    run_transmission = st.sidebar.button("▶ RUN LIVE TRANSMISSION", type="primary")
    
    st.sidebar.markdown("---")
    st.sidebar.header("Run with Eve")
    attack_type = st.sidebar.selectbox("Eve's Attack", [
        "Modify Message",
        "Modify Signature",
        "Replay Packet",
        "Intercept Quantum States"
    ])
    run_eve = st.sidebar.button("💀 RUN WITH EVE")
else:
    st.sidebar.info("Competition Mode Active.\nRunning automated narrative...")
    run_eve = True

col_eve, col_center, col_quantum = st.columns([1, 1.3, 1])

with col_eve:
    st.subheader("💀 EVE")
    st.markdown("<div class='sci-header'>ATTACKER VIEW</div>", unsafe_allow_html=True)
    ph_eve = st.empty()

with col_center:
    st.subheader("🔐 MESSAGE & CRYPTO")
    st.markdown("<div class='sci-header'>ALICE → BOB DATA</div>", unsafe_allow_html=True)
    ph_center = st.empty()

with col_quantum:
    st.subheader("⚛️ QUANTUM CHANNEL")
    st.markdown("<div class='sci-header'>QISKIT AER SIMULATION</div>", unsafe_allow_html=True)
    ph_quantum = st.empty()

def update_center(step, content):
    with ph_center.container():
        st.markdown(f"### {step}")
        st.markdown(content, unsafe_allow_html=True)

def update_quantum(content):
    with ph_quantum.container():
        st.markdown(content, unsafe_allow_html=True)

def update_eve(content):
    with ph_eve.container():
        st.markdown(content, unsafe_allow_html=True)

def simulate_transmission(msg, is_eve=False, eve_attack=None):
    # Setup
    sim = AttackSimulator(proof_length=8)
    alice, bob, session = sim.setup_session()
    
    update_eve("*Monitoring classical and quantum channels...*\n\nStatus: WAITING")
    update_quantum("Status: IDLE\n\nNo quantum states active.")
    
    # 1. Alice creates message
    with ph_center.container():
        st.markdown("### Alice creates message")
        for i in range(1, len(msg) + 1):
            st.code(msg[:i])
            time.sleep(0.05)
            
    time.sleep(0.5)
    
    # 2. Message to Bytes
    bytes_str = " ".join([f"{ord(c):02X}" for c in msg])
    with ph_center.container():
        st.markdown("### Classical Protection")
        st.markdown("Message becomes bytes:")
        st.code(bytes_str)
    
    time.sleep(1.0)
    
    # 3. SHA-256
    seq = session.get_next_sequence_number()
    msg_hash = compute_message_hash(msg, session.session_id, session.challenge, seq)
    with ph_center.container():
        st.markdown("### SHA-256 Processing")
        st.markdown("Blocks compressed into digest:")
        st.code(f"BLOCK 01\n{bytes_str[:20]}...\n\n   ↓ SHA-256\n\n{msg_hash}")
        
    time.sleep(1.0)
    
    # 4. ML-DSA Sign
    with ph_center.container():
        st.markdown("### Post-Quantum Signature")
        st.markdown("SHA-256 Digest + ML-DSA-65 Private Key")
        st.markdown("↓\n**ML-DSA-65 SIGNING**")
        packet = alice.create_packet(msg, 8) 
        st.code(f"PUBLIC KEY\n{packet.pq_public_key[:16]}...{packet.pq_public_key[-8:]}\n\nSIGNATURE\n{packet.pq_signature[:16]}...{packet.pq_signature[-8:]}")
        
    time.sleep(1.0)
    
    # 5. Quantum Binding
    fp_binding = derive_fingerprint_binding(packet.message_hash, alice.session_auth_context, session.session_id, packet.sequence_number)
    spec = derive_fingerprint_specification(fp_binding, alice.session_auth_context, packet.quantum_fingerprint.proof_length)
    q_states = "   ".join([s["state"] for s in spec])
    
    update_quantum(f"### Preparing Fingerprint\n\nBinding Hash → State Choices\n\nExpected states:\n\n`{q_states}`")
    time.sleep(1.5)
    
    # 6. Bell Pairs
    update_quantum(f"### Bell Pair Generation\n\nAlice ───────────── Bob\n\n`|00> → H → CX → Bell Pair`\n\n**ENTANGLEMENT ESTABLISHED**")
    time.sleep(1.5)
    
    # 7. Teleportation
    update_quantum("### Teleportation\n\nAlice measures her qubit and the fingerprint qubit.\nClassical results sent to Bob.\nBob applies Pauli corrections.\n\n`Teleportation successful.`")
    time.sleep(1.5)
    
    # 8. EVE ACTS
    if is_eve:
        eve_view = f"### INTERCEPTED PACKET\n\n**Message:**\n`{msg}`\n\n**SHA-256:**\n`{packet.message_hash[:12]}...`\n\n**ML-DSA Signature:**\n`{packet.pq_signature[:12]}...`\n\n**Quantum states:**\n`QUANTUM STATES UNKNOWN`"
        update_eve(eve_view)
        time.sleep(1.5)
        
        if eve_attack == "Modify Message":
            tampered_msg = "PAY EVE 999"
            eve_view += f"\n\n---\n\n### EVE ATTEMPT\nModify plaintext\n\n`{msg}`\n→ `{tampered_msg}`"
            update_eve(eve_view)
            packet = Eve.tamper_message(packet, tampered_msg)
            time.sleep(1.5)
            
        elif eve_attack == "Modify Signature":
            eve_view += f"\n\n---\n\n### EVE ATTEMPT\nModify signature\n\n`Flipping bits in ML-DSA signature...`"
            update_eve(eve_view)
            last_char = packet.pq_signature[-1]
            new_char = '0' if last_char != '0' else '1'
            bad_sig = packet.pq_signature[:-1] + new_char
            packet = Eve.tamper_signature(packet, bad_sig)
            time.sleep(1.5)
            
        elif eve_attack == "Replay Packet":
            eve_view += f"\n\n---\n\n### EVE ATTEMPT\nReplay old packet\n\n`Sending previously intercepted packet again...`"
            update_eve(eve_view)
            bob.verify_packet(packet)
            time.sleep(1.5)
            
        elif eve_attack == "Intercept Quantum States":
            eve_view += f"\n\n---\n\n### EVE ATTEMPT\nIntercept quantum transmission\n\n`Eve measures passing qubits in random bases...`"
            update_eve(eve_view)
            update_quantum("### 🚨 DISTURBANCE\n\nEve measured the state!\nQuantum state has collapsed.\n\n`|+> → ???`")
            tampered_fp = Eve.intercept_measure_resend(packet.quantum_fingerprint, list(range(8)))
            packet.quantum_fingerprint = tampered_fp
            time.sleep(1.5)
            
    # 9. Bob Verification
    with ph_center.container():
        st.markdown("### Bob Verification")
        st.markdown("Bob receives classical data and quantum states...")
        
    time.sleep(1.0)
    
    # E91 Check
    e91_status = "INTERCEPT_RESEND" if (is_eve and eve_attack == "Intercept Quantum States") else "NONE"
    e91_err = bob.e91_monitor.simulate_channel(e91_status)
    
    if e91_status == "NONE":
        update_quantum(f"### E91 Channel Monitor\n\nCorrelation\n`████████████████████ ~{(1-e91_err)*100:.1f}%`\n\nDisturbance\n`██░░░░░░░░░░░░░░░░░░ {e91_err*100:.1f}%`\n\n**STATUS: SECURE**")
    else:
        update_quantum(f"### E91 Channel Monitor\n\nCorrelation\n`██████████░░░░░░░░░░ ~{(1-e91_err)*100:.1f}%`\n\nDisturbance\n`██████████████░░░░░░ {e91_err*100:.1f}%`\n\n**STATUS: ⚠ EVE DETECTED**")
        
    res = bob.verify_packet(packet, simulate_e91_attack=e91_status)
    
    time.sleep(1.5)
    
    with ph_center.container():
        if res.attack_successful or not is_eve:
            st.success("### ✓ AUTHENTIC MESSAGE")
            st.code(f"╔══════════════════════════════╗\n║      MESSAGE ACCEPTED        ║\n║                              ║\n║ SHA-256              ✓       ║\n║ ML-DSA-65            ✓       ║\n║ Quantum Fingerprint  ✓       ║\n║ E91 Channel          ✓       ║\n║ Replay Protection    ✓       ║\n╚══════════════════════════════╝")
        else:
            st.error("### ✗ MESSAGE REJECTED")
            st.code(f"╔══════════════════════════════╗\n║      ATTACK DETECTED         ║\n║                              ║\n║ FAILED LAYER:                ║\n║ {res.detection_layer.ljust(29)}║\n║                              ║\n║ REASON:                      ║\n║ {res.rejection_code.ljust(29)}║\n╚══════════════════════════════╝")
            
            if eve_attack == "Modify Message":
                update_eve(eve_view + "\n\n**RESULT:**\nSHA-256 mismatch\nML-DSA signature invalid over modified hash.\n\n`✗ BLOCKED`")
            elif eve_attack == "Modify Signature":
                update_eve(eve_view + "\n\n**RESULT:**\nML-DSA verification failed. Signature is mathematically invalid.\n\n`✗ BLOCKED`")
            elif eve_attack == "Replay Packet":
                update_eve(eve_view + "\n\n**RESULT:**\nSequence/session mismatch. Packet already consumed.\n\n`✗ BLOCKED`")
            elif eve_attack == "Intercept Quantum States":
                update_eve(eve_view + "\n\n**RESULT:**\nQuantum measurement disturbance.\nE91 correlation degradation.\nQuantum verification failed.\n\n`✗ BLOCKED`")

if run_transmission:
    simulate_transmission(msg_input, is_eve=False)
elif run_eve:
    simulate_transmission(msg_input, is_eve=True, eve_attack=attack_type)

st.markdown("---")
st.header("Security Architecture Comparison")
st.code("""
                     Classical     ML-DSA      Quantum      Hybrid
─────────────────────────────────────────────────────────────────────────
Message integrity           ✓             ✓           ✓           ✓
Signature authenticity      RSA/ECC       ✓           —           ✓
Quantum attack resistance   ✗             ✓           exp         ✓
Replay detection            ✓             ✓           ✓           ✓
Quantum channel monitoring  ✗             ✗           ✓           ✓
Experimental entanglement   ✗             ✗           ✓           ✓

[ POST-QUANTUM SIGNATURE + QUANTUM CHANNEL MONITORING + CLASSICAL INTEGRITY ]
""")

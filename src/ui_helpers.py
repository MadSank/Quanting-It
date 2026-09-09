"""
UI Helpers & Protocol Execution Engine for Streamlit App
========================================================

Encapsulates all state-management, protocol lifecycle routines,
one-click demo flows, and formatting functions for the Quatinit UI.
Designed to decouple Streamlit presentation from backend cryptographic calls
and enable automated regression testing.
"""

from __future__ import annotations

import time
import os
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass, field

from src.session import Session, SessionManager
from src.crypto import generate_challenge, compute_message_hash
from src.classical_channel import ClassicalChannelAuth
from src.alice import Alice
from src.bob import Bob
from src.eve import Eve
from src.gc_keys import GCKeyGenerator, GCKeyPair, VerifierKeyRegister, CopyStatus
from src.qds_signer import GCSigner, GCSignature
from src.qds_verifier import GCVerifier, GCVerificationResult, VerificationOutcome
from src.e91_monitor import E91Monitor
from src.threat_engine import GCThreatScorer, ThreatScore, GCForgeryModel
from src.metrics import AttackType, AttackResult, DefenseStatus
from src.packet import SecurePacket
from src.teleportation import (
    create_teleportation_circuit,
    simulate_teleportation,
    teleport_fidelity_single_qubit,
    teleport_fingerprint_state,
)
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector


@dataclass
class ProtocolState:
    """Encapsulates active cryptographic session state for the UI."""
    session_manager: SessionManager
    session: Session
    alice: Alice
    bob: Bob
    charlie_register: VerifierKeyRegister
    charlie_verifier: GCVerifier
    trusted_classical_pub_key: str
    n_positions: int = 32
    fingerprint_qubits: int = 8
    current_packet: Optional[SecurePacket] = None
    last_result: Optional[AttackResult] = None
    last_charlie_result: Optional[GCVerificationResult] = None
    history: List[Dict[str, Any]] = field(default_factory=list)


def initialize_protocol_session(
    n_positions: int = 32,
    fingerprint_qubits: int = 8,
    private_key_bits: int = 128,
    max_copies: int = 4,
    c1_threshold: float = 0.05,
    c2_threshold: float = 0.20,
) -> ProtocolState:
    """
    Initialize a fresh, coherent 3-party QDS cryptographic session.
    Generates private keys, prepares quantum public keys, and distributes them
    to Bob and Charlie via simulated teleportation channels.
    """
    sm = SessionManager()
    challenge = generate_challenge()
    sm.start_session(challenge)
    session = sm.current_session

    pub_key, priv_key = ClassicalChannelAuth.generate_keys()

    key_pair = GCKeyGenerator.generate(
        n_positions=n_positions,
        fingerprint_qubits=fingerprint_qubits,
        private_key_bits=private_key_bits,
        max_total_copies=max_copies,
    )

    alice = Alice(
        session_manager=sm,
        classical_priv_key=priv_key,
        classical_pub_key=pub_key,
        key_pair=key_pair,
        n_positions=n_positions,
        fingerprint_qubits=fingerprint_qubits,
    )

    # Distribute public key copies to Bob and Charlie
    registers = alice.distribute_public_keys(["Bob", "Charlie"], teleport=True)

    e91_monitor = E91Monitor(error_threshold=0.15)
    threat_scorer = GCThreatScorer(
        c1_threshold_fraction=c1_threshold,
        c2_threshold_fraction=c2_threshold,
        e91_threshold=0.15,
    )

    bob = Bob(
        session_manager=sm,
        e91_monitor=e91_monitor,
        threat_scorer=threat_scorer,
        trusted_classical_pub_key=pub_key,
        key_register=registers["Bob"],
        acceptance_threshold=c1_threshold,
        rejection_threshold=c2_threshold,
    )

    charlie_reg = registers["Charlie"]
    charlie_verifier = GCVerifier(
        key_register=charlie_reg,
        acceptance_threshold=c1_threshold,
        rejection_threshold=c2_threshold,
    )

    return ProtocolState(
        session_manager=sm,
        session=session,
        alice=alice,
        bob=bob,
        charlie_register=charlie_reg,
        charlie_verifier=charlie_verifier,
        trusted_classical_pub_key=pub_key,
        n_positions=n_positions,
        fingerprint_qubits=fingerprint_qubits,
    )


def are_verifier_keys_consumed(state: ProtocolState) -> bool:
    """
    Check if any of Bob's or Charlie's quantum public key copies have been consumed
    by a prior verification in the current session.
    """
    if state.bob is None or state.bob.key_register is None:
        return True
    return any(
        c.status.name == "CONSUMED"
        for c in state.bob.key_register.copies.values()
    )


def prepare_fresh_transaction_keys(state: ProtocolState) -> None:
    """
    Replenishes fresh quantum key pairs and public key registers for Alice, Bob, and Charlie
    prior to signing a new transaction, upholding the Gottesman-Chuang single-use key specification
    while preserving session context and verification history.
    """
    private_key_bits = getattr(state.alice.key_pair, "private_key_length", 128)
    max_copies = getattr(state.alice.key_pair, "max_total_copies", 4)
    key_pair = GCKeyGenerator.generate(
        n_positions=state.n_positions,
        fingerprint_qubits=state.fingerprint_qubits,
        private_key_bits=private_key_bits,
        max_total_copies=max_copies,
    )
    state.alice.key_pair = key_pair
    registers = state.alice.distribute_public_keys(["Bob", "Charlie"], teleport=True)
    state.bob.receive_public_keys(registers["Bob"])
    state.charlie_register = registers["Charlie"]
    state.charlie_verifier.key_register = registers["Charlie"]
    state.current_packet = None
    state.last_result = None
    state.last_charlie_result = None


def sign_message(state: ProtocolState, message: str) -> Tuple[SecurePacket, float]:
    """
    Alice signs a message using her classical private keys and binds the canonical ML-DSA transcript.
    Returns (packet, elapsed_time_ms).
    """
    if not message:
        message = "EMPTY_PAYLOAD"

    start_time = time.perf_counter()
    packet = state.alice.create_packet(message, n_qubits=state.n_positions)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    state.current_packet = packet
    return packet, elapsed_ms


def verify_packet(
    state: ProtocolState,
    packet: Optional[SecurePacket] = None,
    simulate_e91: str = "NONE",
    is_transfer: bool = False,
) -> Tuple[AttackResult, float]:
    """
    Bob verifies the provided (or active) SecurePacket through the 5-layer pipeline.
    Returns (attack_result, elapsed_time_ms).
    """
    pkt = packet or state.current_packet
    if pkt is None:
        raise ValueError("No packet available to verify. Sign a message first.")

    start_time = time.perf_counter()
    result = state.bob.verify_packet(pkt, simulate_e91_attack=simulate_e91, is_transfer=is_transfer)
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    state.last_result = result

    # Log to history
    log_entry = {
        "timestamp": time.strftime("%H:%M:%S"),
        "verifier": "Bob",
        "message": pkt.message[:24],
        "attack_type": result.attack_type.value,
        "is_accepted": result.threat_score.is_accepted if result.threat_score else False,
        "rejection_code": result.rejection_code,
        "detection_layer": result.detection_layer,
        "mismatch_rate": result.details.get("qds_mismatch_rate", 0.0),
        "elapsed_ms": round(elapsed_ms, 2),
    }
    state.history.append(log_entry)

    return result, elapsed_ms


def transfer_to_charlie(
    state: ProtocolState,
    packet: Optional[SecurePacket] = None,
) -> Tuple[GCVerificationResult, float]:
    """
    Bob transfers the verified signature to Charlie. Charlie independently verifies
    revealed private keys against his own stored quantum public key copies using threshold c2.
    """
    pkt = packet or state.current_packet
    if pkt is None:
        raise ValueError("No packet available to transfer. Sign a message first.")

    start_time = time.perf_counter()
    msg_bytes = pkt.message.encode("utf-8") if isinstance(pkt.message, str) else pkt.message
    res = state.charlie_verifier.verify(
        signature=pkt.qds_signature,
        key_register=state.charlie_register,
        message=msg_bytes,
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    state.last_charlie_result = res

    log_entry = {
        "timestamp": time.strftime("%H:%M:%S"),
        "verifier": "Charlie (Transfer)",
        "message": pkt.message[:24],
        "attack_type": "TRANSFER_VERIFICATION",
        "is_accepted": res.outcome in (VerificationOutcome.ACC_1, VerificationOutcome.ACC_0),
        "rejection_code": res.outcome.value,
        "detection_layer": "CHARLIE_SWAP_TEST",
        "mismatch_rate": res.mismatch_rate,
        "elapsed_ms": round(elapsed_ms, 2),
    }
    state.history.append(log_entry)

    return res, elapsed_ms


def execute_attack_scenario(
    state: ProtocolState,
    attack_type: AttackType,
    custom_message: str = "TRANSACTION_AUTHORIZATION",
) -> Tuple[SecurePacket, AttackResult, float]:
    """
    Executes a real backend attack against the live pipeline.
    Creates a fresh isolated session to prevent contaminating active console key registers.
    """
    attack_state = initialize_protocol_session(
        n_positions=state.n_positions,
        fingerprint_qubits=state.fingerprint_qubits,
    )

    # 1. Sign original packet
    packet, _ = sign_message(attack_state, custom_message)

    tampered_packet = packet
    simulate_e91 = "NONE"

    # 2. Intervene via Eve based on attack type
    if attack_type == AttackType.NO_ATTACK:
        pass
    elif attack_type == AttackType.MESSAGE_TAMPERING:
        tampered_packet = Eve.tamper_message(packet, "ALTERED_TRANSACTION_PAYLOAD")
    elif attack_type == AttackType.HASH_TAMPERING:
        tampered_packet = Eve.tamper_hash(
            packet, "deadbeef00000000000000000000000000000000000000000000000000000000"
        )
    elif attack_type == AttackType.SIGNATURE_TAMPERING:
        tampered_packet = Eve.tamper_ml_dsa_signature(packet)
    elif attack_type == AttackType.FORGERY_ATTEMPT:
        msg_bytes = packet.message.encode("utf-8") if isinstance(packet.message, str) else packet.message
        tampered_packet.qds_signature = Eve.forge_gc_signature(
            message=msg_bytes,
            n_positions=attack_state.n_positions,
            key_bytes=16,
            session_id=packet.session_id,
            sequence_number=packet.sequence_number,
        )
    elif attack_type == AttackType.SEQUENCE_TAMPERING:
        tampered_packet = Eve.tamper_sequence(packet, 9999)
    elif attack_type == AttackType.REPLAY:
        # First verify honest packet to consume copy and advance sequence
        attack_state.bob.verify_packet(packet)
        # Now replay the same packet
        tampered_packet = packet
    elif attack_type == AttackType.KEY_SUBSTITUTION:
        tampered_packet = Eve.tamper_revealed_key(packet, position_idx=0)
    elif attack_type == AttackType.PROOF_SUBSTITUTION:
        # Swap with signature from a different message
        other_pkt, _ = sign_message(attack_state, "DIFFERENT_MESSAGE")
        tampered_packet.qds_signature = other_pkt.qds_signature
    elif attack_type == AttackType.COMPROMISED_SESSION_CONTEXT:
        tampered_packet.session_id = "stolen_session_id_xyz"
    elif attack_type == AttackType.E91_CHANNEL_DISTURBANCE:
        simulate_e91 = "INTERCEPT_RESEND"
    elif attack_type == AttackType.INTERCEPT_RESEND:
        simulate_e91 = "INTERCEPT_RESEND"
    elif attack_type == AttackType.IMPERSONATION:
        from src.crypto import compute_message_hash
        seq_num = attack_state.session.current_sequence_number + 1
        msg = custom_message
        msg_hash = compute_message_hash(msg, attack_state.session.session_id, attack_state.session.challenge, seq_num)
        forged_sig = Eve.forge_gc_signature(
            message=msg.encode("utf-8"),
            n_positions=attack_state.n_positions,
            key_bytes=16,
            session_id=attack_state.session.session_id,
            sequence_number=seq_num,
        )
        tampered_packet = SecurePacket(
            session_id=attack_state.session.session_id,
            sequence_number=seq_num,
            message=msg,
            message_hash=msg_hash,
            qds_signature=forged_sig,
        )
    elif attack_type == AttackType.CROSS_SESSION_REUSE:
        other_state = initialize_protocol_session(n_positions=attack_state.n_positions)
        other_pkt, _ = sign_message(other_state, custom_message)
        tampered_packet = other_pkt
    elif attack_type == AttackType.COPY_EXHAUSTION:
        # Repeatedly verify until all copies in Bob's register are consumed
        max_copies = getattr(attack_state.alice.key_pair, "max_total_copies", 4)
        for _ in range(max_copies + 1):
            temp_pkt, _ = sign_message(attack_state, f"EXHAUST_COPY_{_}")
            attack_state.bob.verify_packet(temp_pkt)
        tampered_packet = packet
    elif attack_type == AttackType.UNAUTHORIZED_VERIFICATION:
        from src.gc_keys import VerifierKeyRegister
        unauth_reg = VerifierKeyRegister(owner="Eve")
        attack_state.bob.key_register = unauth_reg
        tampered_packet = packet
    elif attack_type == AttackType.REPUDIATION_ATTEMPT:
        tampered_packet = packet
        tampered_packet.ml_dsa_signature = "00" * 3309
    elif attack_type == AttackType.TRANSFERABILITY_ATTACK:
        tampered_packet = Eve.tamper_revealed_key(packet, position_idx=0)
    elif attack_type in (AttackType.QUANTUM_X, AttackType.QUANTUM_Z, AttackType.QUANTUM_Y, AttackType.QUANTUM_DEPOLARIZING):
        fake_sv = Statevector.from_label("0" * attack_state.fingerprint_qubits)
        Eve.substitute_public_key(attack_state.bob.key_register, position=0, bit=0, fake_state=fake_sv)
        Eve.substitute_public_key(attack_state.bob.key_register, position=0, bit=1, fake_state=fake_sv)
        tampered_packet = packet
    elif attack_type == AttackType.HOLEVO_EXHAUSTION:
        for copy in attack_state.bob.key_register.copies.values():
            copy.status = CopyStatus.CONSUMED
        tampered_packet = packet
    else:
        # Fallback to general attack simulator
        from src.attack_simulator import AttackSimulator
        sim = AttackSimulator(state.n_positions)
        res = sim.run_attack(attack_type, f"attack_{attack_type.value}")
        state.last_result = res
        return packet, res, 1.0

    # 3. Bob verifies the packet using attack_state
    result, elapsed_ms = verify_packet(attack_state, tampered_packet, simulate_e91=simulate_e91)
    state.last_result = result
    if attack_state.history:
        state.history.append(attack_state.history[-1])
    return tampered_packet, result, elapsed_ms


def run_honest_demo_pipeline(n_positions: int = 32) -> Dict[str, Any]:
    """
    Executes an end-to-end honest transaction demo:
    1. Key Generation & Distribution (Teleportation)
    2. Message Signing (Private Key Revelation & ML-DSA binding)
    3. Primary Verification (Bob Controlled-SWAP Test)
    4. Transfer Verification (Charlie Independent Verification)
    """
    total_start = time.perf_counter()

    # Step 1: Setup Session & Generate Keys
    t0 = time.perf_counter()
    state = initialize_protocol_session(n_positions=n_positions)
    t_keygen_ms = (time.perf_counter() - t0) * 1000.0

    # Step 2: Sign Message
    t0 = time.perf_counter()
    msg = "CONFIDENTIAL_SETTLEMENT_ORDER_$500M"
    packet, t_sign_ms = sign_message(state, msg)

    # Step 3: Bob Verifies
    res_bob, t_bob_ms = verify_packet(state, packet)

    # Step 4: Transfer to Charlie
    res_charlie, t_charlie_ms = transfer_to_charlie(state, packet)

    total_elapsed_ms = (time.perf_counter() - total_start) * 1000.0

    return {
        "state": state,
        "packet": packet,
        "bob_result": res_bob,
        "charlie_result": res_charlie,
        "timings_ms": {
            "keygen": round(t_keygen_ms, 1),
            "sign": round(t_sign_ms, 1),
            "bob_verify": round(t_bob_ms, 1),
            "charlie_verify": round(t_charlie_ms, 1),
            "total": round(total_elapsed_ms, 1),
        },
        "success": res_bob.threat_score.is_accepted and res_charlie.outcome in (VerificationOutcome.ACC_1, VerificationOutcome.ACC_0),
    }


def run_adversarial_demo_pipeline(attack_type: AttackType, n_positions: int = 32) -> Dict[str, Any]:
    """
    Executes a complete adversarial demo:
    1. Setup clean session
    2. Alice signs payload
    3. Eve intercepts and injects specified attack
    4. Bob executes multi-layer verification
    5. Threat engine scores and isolates detection layer
    """
    total_start = time.perf_counter()

    state = initialize_protocol_session(n_positions=n_positions)
    msg = "AUTHORIZE_HIGH_VALUE_WIRE_TRANSFER"
    tampered_packet, res, elapsed_ms = execute_attack_scenario(state, attack_type, msg)

    total_elapsed_ms = (time.perf_counter() - total_start) * 1000.0

    return {
        "state": state,
        "attack_type": attack_type,
        "tampered_packet": tampered_packet,
        "result": res,
        "threat_score": res.threat_score,
        "detection_layer": res.detection_layer,
        "rejection_code": res.rejection_code,
        "defense_status": res.defense_status.value,
        "detected": res.detected,
        "elapsed_ms": round(elapsed_ms, 1),
        "total_elapsed_ms": round(total_elapsed_ms, 1),
    }


def run_teleportation_transport_demo(
    input_state_char: str = "+",
    channel_error: str = "NONE",
    corrupt_crx: bool = False,
    corrupt_crz: bool = False,
    bell_error: str = "NONE",
) -> Dict[str, Any]:
    """
    Runs a single-qubit quantum teleportation transport circuit demo.
    Demonstrates Bell-pair generation, Alice's Bell-basis measurement,
    classical correction bits (crz, crx), and Bob's conditional Pauli corrections.
    """
    qc_prep = QuantumCircuit(1)
    if input_state_char == "1":
        qc_prep.x(0)
    elif input_state_char == "+":
        qc_prep.h(0)
    elif input_state_char == "-":
        qc_prep.x(0)
        qc_prep.h(0)

    expected_sv = Statevector(qc_prep)

    c_err = channel_error if channel_error != "NONE" else None
    b_err = bell_error if bell_error != "NONE" else None

    circuit = create_teleportation_circuit(
        state_prep_circuit=qc_prep,
        corrupt_crx=corrupt_crx,
        corrupt_crz=corrupt_crz,
        bell_error=b_err,
        channel_error=c_err,
    )

    fidelity = teleport_fidelity_single_qubit(circuit, expected_sv)
    sim_res = simulate_teleportation(circuit)

    # Extract sample measurement bits
    counts = sim_res.get("counts", {})
    sample_measurement = list(counts.keys())[0] if counts else "0 0"
    parts = sample_measurement.split()
    crx_val = parts[0] if len(parts) > 0 else "0"
    crz_val = parts[1] if len(parts) > 1 else "0"

    return {
        "input_state": f"|{input_state_char}⟩",
        "fidelity": round(fidelity, 4),
        "fidelity_pct": f"{fidelity * 100:.2f}%",
        "crx_bit": crx_val,
        "crz_bit": crz_val,
        "pauli_correction": f"Z^{crz_val} X^{crx_val}",
        "channel_error": channel_error,
        "bell_error": bell_error,
        "corrupted_classical": corrupt_crx or corrupt_crz,
        "reconstructed_successfully": fidelity > 0.95,
    }


def get_copy_budget_metrics(
    key_pair: GCKeyPair,
    registers: Optional[List[VerifierKeyRegister]] = None
) -> Dict[str, Any]:
    """Compute aggregated quantum public-key copy budget accounting statistics."""
    total_allowed = 0
    total_distributed = 0
    total_consumed = 0

    for budget in key_pair.copy_budgets.values():
        total_allowed += budget.max_copies
        total_distributed += budget.distributed_copies
        total_consumed += budget.consumed_copies

    if registers:
        consumed_in_regs = sum(
            1 for reg in registers
            for copy in reg.copies.values()
            if copy.status == CopyStatus.CONSUMED
        )
        total_consumed = max(total_consumed, consumed_in_regs)

    remaining_distributable = max(0, total_allowed - total_distributed)
    active_in_circulation = max(0, total_distributed - total_consumed)

    return {
        "max_copies_per_position": key_pair.max_total_copies,
        "total_budget_slots": total_allowed,
        "distributed_copies": total_distributed,
        "consumed_copies": total_consumed,
        "remaining_distributable": remaining_distributable,
        "active_in_circulation": active_in_circulation,
    }


def format_masked_key(key_bytes: bytes, visible_bytes: int = 2) -> str:
    """Safely format a private key for UI display without exposing full secret material."""
    if not key_bytes:
        return "••••••••"
    hex_str = key_bytes.hex()
    prefix = hex_str[: visible_bytes * 2]
    return f"{prefix}••••••••••••••••"


# ---------------------------------------------------------------------------
# Complete Attack Matrix Catalogue (Grounded in ATTACK_MATRIX.md & metrics.py)
# ---------------------------------------------------------------------------
ATTACK_CATALOGUE: List[Dict[str, Any]] = [
    {
        "attack_id": "ATK-01",
        "attack_type": AttackType.MESSAGE_TAMPERING,
        "name": "Message Content Tampering",
        "category": "CLASSICAL CONTROL-PLANE",
        "description": "Adversary alters plaintext message string in transit after Alice generates the signature.",
        "target_component": "Classical Payload",
        "applicable": True,
        "detection_method": "SHA-256 Digest Re-computation",
        "system_response": "Layer 3 Abort: Recomputed digest diverges; packet processing is rejected.",
        "defense_status": "DETECTED",
        "detection_layer": "CLASSICAL_HASH",
        "rejection_code": "HASH_MISMATCH",
        "typical_mismatch": "100.0%",
        "threat_level": "HIGH",
        "why_it_fails": "Bob locally recomputes H(m || sess || chal || seq). Tampering in m causes Avalanche divergence in the 256-bit hash, immediately failing Layer 3 check.",
        "test_reference": "tests/test_hash_integrity.py",
    },
    {
        "attack_id": "ATK-02",
        "attack_type": AttackType.HASH_TAMPERING,
        "name": "Hash Binding Tampering",
        "category": "CLASSICAL CONTROL-PLANE",
        "description": "Adversary substitutes or tampers with the message_hash field in SecurePacket.",
        "target_component": "Classical Digest Binding",
        "applicable": True,
        "detection_method": "Session Challenge Verification",
        "system_response": "Layer 3 Abort: Digest does not match expectation from local challenge.",
        "defense_status": "DETECTED",
        "detection_layer": "CLASSICAL_HASH",
        "rejection_code": "HASH_MISMATCH",
        "typical_mismatch": "100.0%",
        "threat_level": "HIGH",
        "why_it_fails": "The session challenge is known to Alice and Bob from the authenticated handshake. An adversary cannot produce a valid hash binding without the ephemeral challenge.",
        "test_reference": "tests/test_hash_integrity.py",
    },
    {
        "attack_id": "ATK-03",
        "attack_type": AttackType.SIGNATURE_TAMPERING,
        "name": "ML-DSA Canonical Transcript Tampering",
        "category": "CLASSICAL CONTROL-PLANE",
        "description": "Adversary tampers with the auxiliary NIST ML-DSA-65 post-quantum signature or canonical transcript.",
        "target_component": "Classical Control-Plane Authentication",
        "applicable": True,
        "detection_method": "FIPS-204 MLDSA65 Verification",
        "system_response": "Layer 3.5 Abort: Asymmetric lattice-based cryptographic verification failure.",
        "defense_status": "DETECTED",
        "detection_layer": "ML_DSA_VERIFICATION",
        "rejection_code": "ML_DSA_INVALID",
        "typical_mismatch": "N/A (Lattice Auth Failure)",
        "threat_level": "HIGH",
        "why_it_fails": "ML-DSA-65 signing binds session_id, sequence, hash, and quantum metadata into a single transcript. Any tampering breaks post-quantum unforgeability.",
        "test_reference": "tests/test_classical_channel.py",
    },
    {
        "attack_id": "ATK-04",
        "attack_type": AttackType.SEQUENCE_TAMPERING,
        "name": "Sequence Number Tampering",
        "category": "CLASSICAL CONTROL-PLANE",
        "description": "Adversary alters the sequential packet sequence number to desynchronize communication.",
        "target_component": "Session Sequence Counter",
        "applicable": True,
        "detection_method": "Monotonic Sequence Window Enforcement",
        "system_response": "Layer 2 Abort: Non-sequential sequence number rejected.",
        "defense_status": "DETECTED",
        "detection_layer": "REPLAY_PROTECTION",
        "rejection_code": "REPLAY_DETECTED",
        "typical_mismatch": "N/A (Sequence Abort)",
        "threat_level": "MEDIUM",
        "why_it_fails": "SessionManager enforces strictly monotonic sequence numbers (seq == current + 1). Arbitrary sequence numbers are immediately dropped.",
        "test_reference": "tests/test_replay.py",
    },
    {
        "attack_id": "ATK-05",
        "attack_type": AttackType.COMPROMISED_SESSION_CONTEXT,
        "name": "Compromised Session Identifier",
        "category": "CLASSICAL CONTROL-PLANE",
        "description": "Adversary injects a foreign, expired, or synthetic session ID into the transmission.",
        "target_component": "Session Boundary",
        "applicable": True,
        "detection_method": "Active Session State Verification",
        "system_response": "Layer 1 Abort: Unrecognized session ID rejected before quantum verification.",
        "defense_status": "DETECTED",
        "detection_layer": "SESSION_STATE",
        "rejection_code": "INVALID_SESSION",
        "typical_mismatch": "N/A (Session Abort)",
        "threat_level": "HIGH",
        "why_it_fails": "Bob verifies that packet.session_id matches the active authenticated session handle. Foreign identifiers are rejected at the perimeter.",
        "test_reference": "tests/test_session.py",
    },
    {
        "attack_id": "ATK-06",
        "attack_type": AttackType.FORGERY_ATTEMPT,
        "name": "Direct Quantum Signature Forgery",
        "category": "QDS & CRYPTOGRAPHIC",
        "description": "Adversary crafts a fabricated signature without knowledge of Alice's 128-bit private keys.",
        "target_component": "Quantum Fingerprint Overlap",
        "applicable": True,
        "detection_method": "Controlled-SWAP Test against Registered Fingerprints",
        "system_response": "Layer 4 Rejection: Mismatch rate significantly exceeds acceptance threshold c1 (5%).",
        "defense_status": "DETECTED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "QDS_SWAP_TEST_THRESHOLD_EXCEEDED",
        "typical_mismatch": "48.0% - 52.0%",
        "threat_level": "CRITICAL",
        "why_it_fails": "Gottesman-Chuang QOWF guarantees that random candidate keys have near-zero inner product with Alice's true key, yielding ~50% SWAP failure rate >> c1.",
        "test_reference": "tests/test_forgery.py",
    },
    {
        "attack_id": "ATK-07",
        "attack_type": AttackType.IMPERSONATION,
        "name": "Signer Impersonation Attack",
        "category": "IDENTITY & AUTHENTICATION",
        "description": "Adversary attempts to impersonate Alice by computing valid message hash for Bob's active session but signing with adversary key material.",
        "target_component": "Signer Identity & Key Association",
        "applicable": True,
        "detection_method": "Controlled-SWAP Test against Alice's Public Keys",
        "system_response": "Layer 4 Rejection: SWAP test mismatch with Bob's registered public keys from Alice.",
        "defense_status": "DETECTED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "QDS_SWAP_TEST_THRESHOLD_EXCEEDED",
        "typical_mismatch": "50.0%",
        "threat_level": "CRITICAL",
        "why_it_fails": "Bob's public key register was pre-distributed by Alice. The adversary's candidate keys fail SWAP tests against Bob's registered copies.",
        "test_reference": "tests/test_end_to_end_security.py",
    },
    {
        "attack_id": "ATK-08",
        "attack_type": AttackType.REPLAY,
        "name": "Signature Replay Attack",
        "category": "REPLAY & PROTOCOL",
        "description": "Adversary intercepts a valid signed packet and re-transmits it at a later time.",
        "target_component": "Public Key Copy Budget & Sequence State",
        "applicable": True,
        "detection_method": "Destructive Copy Consumption & Sequence Tracking",
        "system_response": "Prevention & Rejection: Stale sequence rejected; quantum copies marked CONSUMED.",
        "defense_status": "PREVENTED",
        "detection_layer": "REPLAY_PROTECTION",
        "rejection_code": "REPLAY_DETECTED",
        "typical_mismatch": "N/A (Resource Depleted / Stale)",
        "threat_level": "HIGH",
        "why_it_fails": "Dual protection: (1) First verification destructively consumes Bob's public key copy; (2) Monotonic sequence increments, rejecting the replayed sequence number.",
        "test_reference": "tests/test_replay.py",
    },
    {
        "attack_id": "ATK-09",
        "attack_type": AttackType.CROSS_SESSION_REUSE,
        "name": "Cross-Session Signature Reuse",
        "category": "REPLAY & PROTOCOL",
        "description": "Adversary captures a legitimate signature from Session A and attempts verification in Session B.",
        "target_component": "Session Cryptographic Salt",
        "applicable": True,
        "detection_method": "Session Challenge and Digest Verification",
        "system_response": "Layer 1 / Layer 3 Abort: Session ID and challenge mismatch.",
        "defense_status": "DETECTED",
        "detection_layer": "SESSION_STATE",
        "rejection_code": "INVALID_SESSION",
        "typical_mismatch": "100.0%",
        "threat_level": "HIGH",
        "why_it_fails": "Every session generates an independent cryptographic challenge. Hashes and transcripts from Session A are invalid in Session B.",
        "test_reference": "tests/test_end_to_end_security.py",
    },
    {
        "attack_id": "ATK-10",
        "attack_type": AttackType.KEY_SUBSTITUTION,
        "name": "Single-Position Key Substitution",
        "category": "IDENTITY & AUTHENTICATION",
        "description": "Adversary selectively modifies the revealed private key at a single position index.",
        "target_component": "Individual Key Position",
        "applicable": True,
        "detection_method": "Per-Position Controlled-SWAP Test",
        "system_response": "Layer 4 Failure: SWAP test fails on the tampered position index.",
        "defense_status": "DETECTED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "QDS_SWAP_TEST_THRESHOLD_EXCEEDED",
        "typical_mismatch": "3.1% - 50.0%",
        "threat_level": "MEDIUM",
        "why_it_fails": "Any modified 128-bit key generates an orthogonal fingerprint state, registering a 50% failure rate for that qubit and tripping threshold c1.",
        "test_reference": "tests/test_gc_protocol.py",
    },
    {
        "attack_id": "ATK-11",
        "attack_type": AttackType.PROOF_SUBSTITUTION,
        "name": "Proof / Signature Substitution",
        "category": "IDENTITY & AUTHENTICATION",
        "description": "Adversary substitutes the signature with a legitimate signature from a completely different message.",
        "target_component": "Message-to-Key Mapping",
        "applicable": True,
        "detection_method": "Controlled-SWAP Test across Revealed Bit Positions",
        "system_response": "Layer 4 Rejection: High mismatch rate on differing message bit positions.",
        "defense_status": "DETECTED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "QDS_SWAP_TEST_THRESHOLD_EXCEEDED",
        "typical_mismatch": "25.0% - 50.0%",
        "threat_level": "HIGH",
        "why_it_fails": "Because message hashes differ, keys revealed for Message A do not match the expected message bits of Message B, causing widespread SWAP failure.",
        "test_reference": "tests/test_gc_protocol.py",
    },
    {
        "attack_id": "ATK-12",
        "attack_type": AttackType.COPY_EXHAUSTION,
        "name": "Quantum Copy Budget Depletion",
        "category": "RESOURCE & CONSTRAINTS",
        "description": "Adversary repeatedly triggers verification to exhaust verifier's finite public key copy budget.",
        "target_component": "Finite Quantum Public-Key Ledger",
        "applicable": True,
        "detection_method": "Logical Copy Accounting Enforcer (T=4)",
        "system_response": "Protocol Lock: Rejects verification when available copies are exhausted.",
        "defense_status": "PREVENTED",
        "detection_layer": "COPY_BUDGET",
        "rejection_code": "NO_CLONING_BUDGET_EXHAUSTED",
        "typical_mismatch": "N/A (Resource Depleted)",
        "threat_level": "MEDIUM",
        "why_it_fails": "The protocol explicitly enforces a finite budget T < L/n. When all distributed copies are consumed, subsequent verification attempts are refused.",
        "test_reference": "tests/test_gc_keys.py",
    },
    {
        "attack_id": "ATK-13",
        "attack_type": AttackType.HOLEVO_EXHAUSTION,
        "name": "Key Inversion / Holevo Extraction Attack",
        "category": "RESOURCE & CONSTRAINTS",
        "description": "Adversary attempts collective quantum measurements on public keys to reconstruct Alice's private key.",
        "target_component": "Information-Theoretic Key Secrecy",
        "applicable": True,
        "detection_method": "Holevo Information Bound Proof (T * n <= 32 bits)",
        "system_response": "Information Barrier: Mutual information strictly bounded below key entropy.",
        "defense_status": "PREVENTED",
        "detection_layer": "COPY_BUDGET",
        "rejection_code": "NO_CLONING_BUDGET_EXHAUSTED",
        "typical_mismatch": "N/A (Information-Theoretic Wall)",
        "threat_level": "LOW",
        "why_it_fails": "Holevo's theorem bounds accessible information to I_acc <= T * n = 32 bits. With L=128 bits, an entropy gap of Delta H = 96 bits structurally prevents key inversion.",
        "test_reference": "tests/test_gc_keys.py",
    },
    {
        "attack_id": "ATK-14",
        "attack_type": AttackType.UNAUTHORIZED_VERIFICATION,
        "name": "Unauthorized Verifier Execution",
        "category": "RESOURCE & CONSTRAINTS",
        "description": "An unregistered third party lacking legitimate public key material attempts verification.",
        "target_component": "Verifier Key Register",
        "applicable": True,
        "detection_method": "Key Register Authorization Check",
        "system_response": "Execution Refusal: Verifier lacks registered quantum public states.",
        "defense_status": "PREVENTED",
        "detection_layer": "COPY_BUDGET",
        "rejection_code": "NO_CLONING_BUDGET_EXHAUSTED",
        "typical_mismatch": "N/A (Unauthorized)",
        "threat_level": "MEDIUM",
        "why_it_fails": "Verification requires pre-distributed quantum public states delivered from Alice during the key distribution phase.",
        "test_reference": "tests/test_gc_protocol.py",
    },
    {
        "attack_id": "ATK-15",
        "attack_type": AttackType.REPUDIATION_ATTEMPT,
        "name": "Signer Repudiation Attempt",
        "category": "QDS & CRYPTOGRAPHIC",
        "description": "Alice attempts to craft a signature that Bob accepts (at threshold c1) but Charlie rejects (at threshold c2).",
        "target_component": "Transferability & Non-Repudiation Gap",
        "applicable": True,
        "detection_method": "Calibrated Dual Threshold Gap (c1 = 0.05, c2 = 0.20)",
        "system_response": "Dispute Prevention: Measured binomial gap guarantees non-repudiation.",
        "defense_status": "PREVENTED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "ACCEPTED",
        "typical_mismatch": "0.0%",
        "threat_level": "LOW",
        "why_it_fails": "Threshold gap c2 - c1 is calibrated against binomial mismatch tails. Alice cannot forge states that pass Bob's test without also passing Charlie's test.",
        "test_reference": "tests/test_gc_protocol.py",
    },
    {
        "attack_id": "ATK-16",
        "attack_type": AttackType.TRANSFERABILITY_ATTACK,
        "name": "Transferability Disruption Attack",
        "category": "QDS & CRYPTOGRAPHIC",
        "description": "Adversary perturbs transferred signature to cause dispute between Bob and Charlie.",
        "target_component": "Charlie's Arbiter Threshold (c2 = 0.20)",
        "applicable": True,
        "detection_method": "Independent Charlie Controlled-SWAP Test",
        "system_response": "Dispute Resolution: Charlie evaluates against threshold c2.",
        "defense_status": "DETECTED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "QDS_SWAP_TEST_THRESHOLD_EXCEEDED",
        "typical_mismatch": "20.0% - 35.0%",
        "threat_level": "HIGH",
        "why_it_fails": "Charlie independently measures against his own stored quantum public keys, rejecting any transferred signature exceeding c2.",
        "test_reference": "tests/test_gc_protocol.py",
    },
    {
        "attack_id": "ATK-17",
        "attack_type": AttackType.INTERCEPT_RESEND,
        "name": "Quantum Intercept-and-Resend Attack",
        "category": "QUANTUM CHANNEL",
        "description": "Eve intercepts quantum transmission, measures in random basis, and resends collapsed state to Bob.",
        "target_component": "Quantum Channel Superposition",
        "applicable": True,
        "detection_method": "E91-Inspired Bell Correlation Monitoring & SWAP Test",
        "system_response": "Dual Detection: Bell error rate spikes to ~25%; SWAP test mismatch increases.",
        "defense_status": "DETECTED",
        "detection_layer": "E91_CHANNEL",
        "rejection_code": "E91_THRESHOLD_EXCEEDED",
        "typical_mismatch": "25.0% - 50.0%",
        "threat_level": "CRITICAL",
        "why_it_fails": "Measurement in non-orthogonal basis collapses superposition, introducing irreversible 25% disturbance on matched bases and destroying state fidelity.",
        "test_reference": "tests/test_e91_monitor.py",
    },
    {
        "attack_id": "ATK-18",
        "attack_type": AttackType.E91_CHANNEL_DISTURBANCE,
        "name": "Bell-Correlation Entanglement Disturbance",
        "category": "QUANTUM CHANNEL",
        "description": "Eavesdropper disrupts entanglement correlations on the Bell-state distribution bus.",
        "target_component": "EPR Pair Entanglement",
        "applicable": True,
        "detection_method": "E91-Inspired Matched-Basis Error Evaluation",
        "system_response": "Channel Alert: Error rate exceeding 15% aborts quantum transport.",
        "defense_status": "DETECTED",
        "detection_layer": "E91_CHANNEL",
        "rejection_code": "E91_THRESHOLD_EXCEEDED",
        "typical_mismatch": "22.0% - 28.0%",
        "threat_level": "HIGH",
        "why_it_fails": "CHSH correlations cannot be measured by a third party without disrupting entanglement. Error rate jumps from baseline 0% to ~25%.",
        "test_reference": "tests/test_e91_monitor.py",
    },
    {
        "attack_id": "ATK-19",
        "attack_type": AttackType.QUANTUM_X,
        "name": "Pauli-X Channel Attack (Bit Flip)",
        "category": "QUANTUM CHANNEL",
        "description": "Coherent bit-flip disturbance applied to public key quantum statevector.",
        "target_component": "Fingerprint Amplitude Basis",
        "applicable": True,
        "detection_method": "Controlled-SWAP Test",
        "system_response": "Layer 4 Rejection: Amplitude permutation ruins state overlap.",
        "defense_status": "DETECTED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "QDS_SWAP_TEST_THRESHOLD_EXCEEDED",
        "typical_mismatch": "50.0%",
        "threat_level": "HIGH",
        "why_it_fails": "Pauli-X permutes basis state amplitudes in |f_k>, altering the inner product and causing Controlled-SWAP test rejection.",
        "test_reference": "tests/test_teleportation.py",
    },
    {
        "attack_id": "ATK-20",
        "attack_type": AttackType.QUANTUM_Z,
        "name": "Pauli-Z Channel Attack (Phase Flip)",
        "category": "QUANTUM CHANNEL",
        "description": "Coherent phase-flip disturbance applied to phase-encoded quantum fingerprint.",
        "target_component": "Phase Encoding Codeword",
        "applicable": True,
        "detection_method": "Controlled-SWAP Test",
        "system_response": "Layer 4 Rejection: Phase inversion destroys constructive interference.",
        "defense_status": "DETECTED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "QDS_SWAP_TEST_THRESHOLD_EXCEEDED",
        "typical_mismatch": "50.0%",
        "threat_level": "HIGH",
        "why_it_fails": "Fingerprint states encode key material strictly into phase factors (-1)^{E(k)_j}. A Pauli-Z operation directly flips codeword phases, collapsing overlap.",
        "test_reference": "tests/test_teleportation.py",
    },
    {
        "attack_id": "ATK-21",
        "attack_type": AttackType.QUANTUM_Y,
        "name": "Pauli-Y Channel Attack (Bit & Phase Flip)",
        "category": "QUANTUM CHANNEL",
        "description": "Simultaneous bit-flip and phase-flip disturbance on public key quantum states.",
        "target_component": "Fingerprint Amplitudes & Phases",
        "applicable": True,
        "detection_method": "Controlled-SWAP Test",
        "system_response": "Layer 4 Rejection: Severe state vector degradation.",
        "defense_status": "DETECTED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "QDS_SWAP_TEST_THRESHOLD_EXCEEDED",
        "typical_mismatch": "50.0%",
        "threat_level": "HIGH",
        "why_it_fails": "Combines amplitude permutation with phase inversion, producing maximal divergence from expected fingerprint.",
        "test_reference": "tests/test_teleportation.py",
    },
    {
        "attack_id": "ATK-22",
        "attack_type": AttackType.QUANTUM_DEPOLARIZING,
        "name": "Depolarizing Quantum Channel Noise",
        "category": "QUANTUM CHANNEL",
        "description": "Environmental decoherence or depolarizing channel mixed with random density matrix.",
        "target_component": "Quantum State Purity",
        "applicable": True,
        "detection_method": "Controlled-SWAP Test & Threshold Calibration",
        "system_response": "Mitigation below c1; severe noise triggers Layer 4 rejection.",
        "defense_status": "MITIGATED",
        "detection_layer": "QDS_VERIFICATION",
        "rejection_code": "QDS_SWAP_TEST_THRESHOLD_EXCEEDED",
        "typical_mismatch": "Noise Rate * 50%",
        "threat_level": "MEDIUM",
        "why_it_fails": "Mild channel noise (< 5%) is absorbed by the calibrated acceptance threshold c1. Malicious noise exceeding c1 is rejected.",
        "test_reference": "tests/test_threshold_calibration.py",
    },
]


def measure_e91_detailed(
    num_pairs: int = 100,
    attack_type: str = "NONE",
) -> Dict[str, Any]:
    """
    Executes an E91-inspired Bell correlation measurement run on AerSimulator.
    Returns comprehensive metrics including baseline, current disturbance, matches,
    errors, threshold comparison, and integrity status.
    """
    mon = E91Monitor(num_pairs=num_pairs, error_threshold=0.15)
    stats = mon.measure_disturbance(attack_type=attack_type)

    error_rate = stats.get("error_rate", 0.0)
    matches = stats.get("matches", 0)
    errors = stats.get("errors", 0)
    threshold = mon.error_threshold

    status = "NORMAL"
    if error_rate > threshold:
        status = "DISTURBED"
    elif error_rate > (threshold * 0.7):
        status = "SUSPICIOUS"

    # CHSH-analogous correlation coefficient (1.0 for perfect correlation, 0.0 for uncorrelated)
    correlation_coeff = max(-1.0, min(1.0, 1.0 - 2.0 * error_rate))

    return {
        "num_pairs": num_pairs,
        "matches": matches,
        "errors": errors,
        "error_rate": round(error_rate, 4),
        "error_rate_pct": f"{error_rate * 100:.2f}%",
        "baseline_rate": 0.0,
        "deviation": round(error_rate - 0.0, 4),
        "threshold": threshold,
        "threshold_pct": f"{threshold * 100:.1f}%",
        "channel_status": status,
        "correlation_coeff": round(correlation_coeff, 3),
        "attack_simulated": attack_type,
        "detected": error_rate > threshold,
    }


def run_staged_demo_pipeline(
    mode: str = "HONEST",
    attack_type: Optional[AttackType] = None,
    n_positions: int = 32,
    payload: str = "TRANSACTION_AUTHORIZATION_ORD_9824",
) -> Dict[str, Any]:
    """
    Executes a structured 7-stage visual timeline demonstration:
    Stage 01: Key Generation & Copy Distribution
    Stage 02: Message Preparation & Session Binding
    Stage 03: QDS Signing & ML-DSA Transcript Binding
    Stage 04: Quantum State Transport (Teleportation adaptation)
    Stage 05: Controlled-SWAP Test Verification
    Stage 06: Protocol Decision & Dispute Resolution
    Stage 07: Threat Engine Analysis & Metrics Scoring
    """
    total_start = time.perf_counter()
    stages = []

    # -----------------------------------------------------------------------
    # STAGE 01: KEY GENERATION
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    state = initialize_protocol_session(n_positions=n_positions)
    t_stage1_ms = (time.perf_counter() - t0) * 1000.0

    stages.append({
        "stage_num": 1,
        "code": "STEP_01",
        "name": "KEY GENERATION & COPY DISTRIBUTION",
        "actor": "ALICE & REGISTRATION CHANNELS",
        "status": "COMPLETED",
        "elapsed_ms": round(t_stage1_ms, 1),
        "summary": "Generated 64 private keys (L=128 bits); prepared and distributed quantum public key copies via teleportation.",
        "artifacts": {
            "alice_private_keys": f"{state.n_positions * 2} keys (128-bit classical)",
            "bob_public_copies": f"{len(state.bob.key_register.copies)} copies in register",
            "charlie_public_copies": f"{len(state.charlie_register.copies)} copies in register",
            "fingerprint_dimension": f"{state.fingerprint_qubits} qubits (256 Hilbert space)",
            "holevo_accessible_info": "32 bits (T=4 copies * 8 qubits)",
            "holevo_entropy_gap": "96 bits (128 - 32)",
        },
    })

    # -----------------------------------------------------------------------
    # STAGE 02: MESSAGE PREPARATION
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    session = state.session
    msg = payload
    expected_hash = compute_message_hash(msg, session.session_id, session.challenge, session.current_sequence_number + 1)
    t_stage2_ms = (time.perf_counter() - t0) * 1000.0

    stages.append({
        "stage_num": 2,
        "code": "STEP_02",
        "name": "MESSAGE PREPARATION & BINDING",
        "actor": "ALICE",
        "status": "COMPLETED",
        "elapsed_ms": round(t_stage2_ms, 1),
        "summary": "Constructed session-salted SHA-256 digest bound to active challenge and sequence index.",
        "artifacts": {
            "plaintext": msg,
            "session_id": session.session_id,
            "sequence_number": session.current_sequence_number + 1,
            "session_challenge": session.challenge[:16] + "...",
            "computed_hash": expected_hash,
        },
    })

    # -----------------------------------------------------------------------
    # STAGE 03: QDS SIGNING
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    packet, t_sign_ms = sign_message(state, msg)
    t_stage3_ms = (time.perf_counter() - t0) * 1000.0

    stages.append({
        "stage_num": 3,
        "code": "STEP_03",
        "name": "QDS SIGNING & TRANSCRIPT BINDING",
        "actor": "ALICE (SIGNER)",
        "status": "COMPLETED",
        "elapsed_ms": round(t_stage3_ms, 1),
        "summary": "Revealed classical key k_{m_i} per position; bound canonical transcript with NIST ML-DSA-65 signature.",
        "artifacts": {
            "revealed_key_count": f"{len(packet.qds_signature.revealed_keys)} / {state.n_positions}",
            "sample_revealed_key": format_masked_key(packet.qds_signature.revealed_keys[0]),
            "ml_dsa_signature_len": f"{len(packet.ml_dsa_signature)} hex chars (ML-DSA-65)",
            "ml_dsa_sample": packet.ml_dsa_signature[:24] + "..." + packet.ml_dsa_signature[-16:],
        },
    })

    # -----------------------------------------------------------------------
    # STAGE 04: QUANTUM STATE TRANSPORT & ADVERSARIAL INTERVENTION
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    effective_packet = packet
    simulate_e91 = "NONE"
    attack_applied = attack_type if mode == "ADVERSARIAL" else AttackType.NO_ATTACK
    intervention_summary = "Transported quantum state over entanglement channel with EPR pairs and classical corrections."

    if mode == "ADVERSARIAL" and attack_type:
        effective_packet, res_atk, _ = execute_attack_scenario(state, attack_type, msg)
        intervention_summary = f"Adversary intercepted channel and executed {attack_type.value}."

    teleport_res = run_teleportation_transport_demo(
        input_state_char="+",
        channel_error="X" if attack_applied == AttackType.QUANTUM_X else ("NONE" if mode == "HONEST" else "DEPOLARIZING"),
    )
    t_stage4_ms = (time.perf_counter() - t0) * 1000.0

    stages.append({
        "stage_num": 4,
        "code": "STEP_04",
        "name": "QUANTUM STATE TRANSPORT",
        "actor": "QUANTUM CHANNEL (TELEPORTATION TRANSPORT)" if mode == "HONEST" else "EVE (ADVERSARIAL INTERCEPTION)",
        "status": "COMPLETED" if mode == "HONEST" else "INTERCEPTED",
        "elapsed_ms": round(t_stage4_ms, 1),
        "summary": intervention_summary,
        "artifacts": {
            "transport_mechanism": "Teleportation-based quantum state transport adaptation",
            "bell_pair": "|Phi+> = (|00> + |11>)/sqrt(2)",
            "classical_corrections": f"crz={teleport_res['crz_bit']}, crx={teleport_res['crx_bit']} -> Z^{teleport_res['crz_bit']} X^{teleport_res['crx_bit']}",
            "reconstructed_fidelity": teleport_res["fidelity_pct"],
            "adversarial_intervention": attack_applied.value,
        },
    })

    # -----------------------------------------------------------------------
    # STAGE 05: CONTROLLED-SWAP TEST VERIFICATION
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    res_bob, t_bob_ms = verify_packet(state, effective_packet, simulate_e91=simulate_e91)
    t_stage5_ms = (time.perf_counter() - t0) * 1000.0

    score = res_bob.threat_score
    mismatch_rate = score.qds_mismatch_rate if score else 0.0

    stages.append({
        "stage_num": 5,
        "code": "STEP_05",
        "name": "CONTROLLED-SWAP TEST VERIFICATION",
        "actor": "BOB (PRIMARY VERIFIER)",
        "status": "COMPLETED",
        "elapsed_ms": round(t_stage5_ms, 1),
        "summary": f"Executed destructive Controlled-SWAP tests across {state.n_positions} positions. Mismatch rate: {mismatch_rate*100:.1f}%.",
        "artifacts": {
            "swap_tests_performed": state.n_positions,
            "mismatch_count": getattr(score, "qds_n_mismatches", 0),
            "mismatch_rate": f"{mismatch_rate*100:.2f}%",
            "acceptance_threshold_c1": "5.0%",
            "rejection_threshold_c2": "20.0%",
            "copy_budget_consumed": "1 copy per verified position",
        },
    })

    # -----------------------------------------------------------------------
    # STAGE 06: DECISION & TRANSFERABILITY
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    decision = "ACCEPTED" if (score and score.is_accepted and res_bob.rejection_code == "ACCEPTED") else "REJECTED"
    charlie_outcome = "NOT_EXECUTED"

    if decision == "ACCEPTED":
        res_charlie, _ = transfer_to_charlie(state, effective_packet)
        charlie_outcome = res_charlie.outcome.value

    t_stage6_ms = (time.perf_counter() - t0) * 1000.0

    stages.append({
        "stage_num": 6,
        "code": "STEP_06",
        "name": "PROTOCOL DECISION & DISPUTE EVALUATION",
        "actor": "BOB & CHARLIE (ARBITER)",
        "status": decision,
        "elapsed_ms": round(t_stage6_ms, 1),
        "summary": f"Protocol evaluated statistical thresholds. Final verification decision: {decision}.",
        "artifacts": {
            "bob_decision": decision,
            "rejection_code": res_bob.rejection_code,
            "detection_layer": res_bob.detection_layer,
            "charlie_transfer_outcome": charlie_outcome,
            "non_repudiation_status": "GUARANTEED (c1 < c2)" if decision == "ACCEPTED" else "DISPUTE PREVENTED",
        },
    })

    # -----------------------------------------------------------------------
    # STAGE 07: THREAT ENGINE ANALYSIS
    # -----------------------------------------------------------------------
    t0 = time.perf_counter()
    threat_level = getattr(score, "threat_level", "HIGH" if decision == "REJECTED" else "LOW")
    threat_score_val = getattr(score, "overall_threat_score", 0.85 if decision == "REJECTED" else 0.05)
    t_stage7_ms = (time.perf_counter() - t0) * 1000.0

    stages.append({
        "stage_num": 7,
        "code": "STEP_07",
        "name": "THREAT ENGINE ANALYSIS",
        "actor": "SOC THREAT SCORING ENGINE",
        "status": "COMPLETED",
        "elapsed_ms": round(t_stage7_ms, 1),
        "summary": f"Categorized threat severity: {threat_level}. Defense status: {res_bob.defense_status.value}.",
        "artifacts": {
            "threat_level": threat_level,
            "overall_threat_score": f"{threat_score_val:.2f} / 1.00",
            "defense_status": res_bob.defense_status.value,
            "detection_layer": res_bob.detection_layer,
            "e91_disturbance_rate": f"{getattr(score, 'e91_error_rate', 0.0)*100:.1f}%",
            "confidence": f"{getattr(score, 'overall_confidence', 1.0)*100:.1f}%",
        },
    })

    total_elapsed_ms = (time.perf_counter() - total_start) * 1000.0

    return {
        "mode": mode,
        "attack_type": attack_type,
        "success": decision == "ACCEPTED",
        "decision": decision,
        "stages": stages,
        "bob_result": res_bob,
        "threat_score": score,
        "total_elapsed_ms": round(total_elapsed_ms, 1),
    }

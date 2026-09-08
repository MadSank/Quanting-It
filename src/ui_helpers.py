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
    Creates a fresh session or state if needed to prevent contamination.
    """
    # 1. Sign original packet
    packet, _ = sign_message(state, custom_message)

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
            n_positions=state.n_positions,
            key_bytes=16,
            session_id=packet.session_id,
            sequence_number=packet.sequence_number,
        )
    elif attack_type == AttackType.SEQUENCE_TAMPERING:
        tampered_packet = Eve.tamper_sequence(packet, 9999)
    elif attack_type == AttackType.REPLAY:
        # First verify honest packet to consume copy and advance sequence
        state.bob.verify_packet(packet)
        # Now replay the same packet
        tampered_packet = packet
    elif attack_type == AttackType.KEY_SUBSTITUTION:
        tampered_packet = Eve.tamper_revealed_key(packet, position_idx=0)
    elif attack_type == AttackType.PROOF_SUBSTITUTION:
        # Swap with signature from a different message
        other_pkt, _ = sign_message(state, "DIFFERENT_MESSAGE")
        tampered_packet.qds_signature = other_pkt.qds_signature
    elif attack_type == AttackType.COMPROMISED_SESSION_CONTEXT:
        tampered_packet.session_id = "stolen_session_id_xyz"
    elif attack_type == AttackType.E91_CHANNEL_DISTURBANCE:
        simulate_e91 = "INTERCEPT_RESEND"
    elif attack_type == AttackType.INTERCEPT_RESEND:
        simulate_e91 = "INTERCEPT_RESEND"
    elif attack_type == AttackType.IMPERSONATION:
        from src.crypto import compute_message_hash
        seq_num = state.session.current_sequence_number + 1
        msg = custom_message
        msg_hash = compute_message_hash(msg, state.session.session_id, state.session.challenge, seq_num)
        forged_sig = Eve.forge_gc_signature(
            message=msg.encode("utf-8"),
            n_positions=state.n_positions,
            key_bytes=16,
            session_id=state.session.session_id,
            sequence_number=seq_num,
        )
        tampered_packet = SecurePacket(
            session_id=state.session.session_id,
            sequence_number=seq_num,
            message=msg,
            message_hash=msg_hash,
            qds_signature=forged_sig,
        )
    elif attack_type == AttackType.CROSS_SESSION_REUSE:
        other_state = initialize_protocol_session(n_positions=state.n_positions)
        other_pkt, _ = sign_message(other_state, custom_message)
        tampered_packet = other_pkt
    elif attack_type == AttackType.COPY_EXHAUSTION:
        # Repeatedly verify until all copies in Bob's register are consumed
        for _ in range(state.bob.key_register.max_copies_per_position + 1):
            temp_pkt, _ = sign_message(state, f"EXHAUST_COPY_{_}")
            state.bob.verify_packet(temp_pkt)
        tampered_packet = packet
    elif attack_type == AttackType.UNAUTHORIZED_VERIFICATION:
        from src.gc_keys import VerifierKeyRegister
        unauth_reg = VerifierKeyRegister(verifier_id="Eve", max_copies_per_position=0)
        state.bob.key_register = unauth_reg
        tampered_packet = packet
    elif attack_type == AttackType.REPUDIATION_ATTEMPT:
        tampered_packet = packet
        tampered_packet.ml_dsa_signature = "00" * 3309
    elif attack_type == AttackType.TRANSFERABILITY_ATTACK:
        tampered_packet = Eve.tamper_revealed_key(packet, position_idx=0)
    elif attack_type in (AttackType.QUANTUM_X, AttackType.QUANTUM_Z, AttackType.QUANTUM_Y, AttackType.QUANTUM_DEPOLARIZING):
        fake_sv = Statevector.from_label("0" * state.fingerprint_qubits)
        Eve.substitute_public_key(state.bob.key_register, position=0, bit=0, fake_state=fake_sv)
        Eve.substitute_public_key(state.bob.key_register, position=0, bit=1, fake_state=fake_sv)
        tampered_packet = packet
    elif attack_type == AttackType.HOLEVO_EXHAUSTION:
        for copy in state.bob.key_register.copies.values():
            copy.status = CopyStatus.CONSUMED
        tampered_packet = packet
    else:
        # Fallback to general attack simulator
        from src.attack_simulator import AttackSimulator
        sim = AttackSimulator(state.n_positions)
        res = sim.run_attack(attack_type, f"attack_{attack_type.value}")
        return packet, res, 1.0

    # 3. Bob verifies the packet
    result, elapsed_ms = verify_packet(state, tampered_packet, simulate_e91=simulate_e91)
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

"""
Test Suite: UI Helpers & Protocol Flow Engine
=============================================

Validates the state initialization, signing, verification, transferability,
demo pipelines, teleportation simulation, and copy budget accounting
utilized by the Streamlit application.
"""

import pytest
from src.metrics import AttackType, DefenseStatus
from src.qds_verifier import VerificationOutcome
from src.ui_helpers import (
    initialize_protocol_session,
    sign_message,
    verify_packet,
    transfer_to_charlie,
    execute_attack_scenario,
    run_honest_demo_pipeline,
    run_adversarial_demo_pipeline,
    run_teleportation_transport_demo,
    get_copy_budget_metrics,
    format_masked_key,
    prepare_fresh_transaction_keys,
    are_verifier_keys_consumed,
)


def test_session_initialization():
    """Verify clean 3-party session initialization."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    assert state.session is not None
    assert state.alice is not None
    assert state.bob is not None
    assert state.charlie_register is not None
    assert state.n_positions == 16
    assert len(state.history) == 0


def test_sign_and_verify_honest():
    """Verify honest message signing and Bob verification."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    packet, t_sign = sign_message(state, "CONFIDENTIAL_INVOICE_123")
    assert packet.message == "CONFIDENTIAL_INVOICE_123"
    assert packet.qds_signature is not None
    assert packet.ml_dsa_signature is not None
    assert t_sign > 0.0

    result, t_verify = verify_packet(state, packet)
    assert result.threat_score.is_accepted is True
    assert result.rejection_code == "ACCEPTED"
    assert result.details.get("qds_mismatch_rate") == 0.0
    assert len(state.history) == 1


def test_transfer_to_charlie():
    """Verify that Bob's accepted signature transfers successfully to Charlie."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    packet, _ = sign_message(state, "TRANSFER_AGREEMENT")
    bob_res, _ = verify_packet(state, packet)
    assert bob_res.threat_score.is_accepted is True

    charlie_res, t_charlie = transfer_to_charlie(state, packet)
    assert charlie_res.outcome == VerificationOutcome.ACC_1
    assert charlie_res.mismatch_rate == 0.0
    assert len(state.history) == 2


def test_attack_message_tampering():
    """Verify that message tampering is detected by hash binding."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    tampered_pkt, res, _ = execute_attack_scenario(state, AttackType.MESSAGE_TAMPERING)
    assert res.detected is True
    assert res.rejection_code == "HASH_MISMATCH"
    assert res.threat_score.is_accepted is False


def test_attack_forgery():
    """Verify that forged signature is detected by SWAP test / ML-DSA verification."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    _, res, _ = execute_attack_scenario(state, AttackType.FORGERY_ATTEMPT)
    assert res.detected is True
    assert res.threat_score.is_accepted is False


def test_one_click_honest_pipeline():
    """Verify one-click honest demo pipeline execution."""
    demo = run_honest_demo_pipeline(n_positions=16)
    assert demo["success"] is True
    assert demo["bob_result"].threat_score.is_accepted is True
    assert demo["charlie_result"].outcome in (VerificationOutcome.ACC_1, VerificationOutcome.ACC_0)
    assert demo["timings_ms"]["total"] > 0.0


def test_one_click_adversarial_pipeline():
    """Verify one-click adversarial demo pipeline execution."""
    demo = run_adversarial_demo_pipeline(AttackType.HASH_TAMPERING, n_positions=16)
    assert demo["detected"] is True
    assert demo["rejection_code"] == "HASH_MISMATCH"
    assert demo["defense_status"] == "DETECTED"


def test_teleportation_demo_clean_and_error():
    """Verify teleportation simulation demo with clean and perturbed channels."""
    clean_demo = run_teleportation_transport_demo("+", channel_error="NONE")
    assert clean_demo["fidelity"] == pytest.approx(1.0, abs=1e-3)
    assert clean_demo["reconstructed_successfully"] is True

    error_demo = run_teleportation_transport_demo("0", channel_error="X")
    assert error_demo["fidelity"] == pytest.approx(0.0, abs=1e-3)
    assert error_demo["reconstructed_successfully"] is False


def test_copy_budget_accounting():
    """Verify copy budget metric aggregation."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    metrics_before = get_copy_budget_metrics(state.alice.key_pair)
    # Alice distributes 1 copy to Bob and 1 to Charlie per (pos, bit) -> 16 * 2 * 2 = 64
    assert metrics_before["distributed_copies"] == 64
    assert metrics_before["consumed_copies"] == 0

    # Verify packet -> consumes 16 copies for Bob
    packet, _ = sign_message(state, "BUDGET_TEST")
    verify_packet(state, packet)
    metrics_after = get_copy_budget_metrics(
        state.alice.key_pair, [state.bob.key_register, state.charlie_register]
    )
    assert metrics_after["consumed_copies"] == 16


def test_format_masked_key():
    """Verify safe masking of private key bytes."""
    sample_key = bytes.fromhex("a4f91234567890abcdef")
    masked = format_masked_key(sample_key, visible_bytes=2)
    assert masked.startswith("a4f9")
    assert "••••" in masked


def test_impersonation_attack():
    """Verify that impersonation (forged key material with valid hash) is detected."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    _, res, _ = execute_attack_scenario(state, AttackType.IMPERSONATION)
    assert res.detected is True
    assert res.threat_score.is_accepted is False


def test_cross_session_reuse_attack():
    """Verify that signatures from another session are rejected."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    _, res, _ = execute_attack_scenario(state, AttackType.CROSS_SESSION_REUSE)
    assert res.detected is True
    assert res.threat_score.is_accepted is False


def test_e91_disturbance_attack():
    """Verify that E91 channel disturbance is reflected in the entanglement monitor."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    _, res, _ = execute_attack_scenario(state, AttackType.E91_CHANNEL_DISTURBANCE)
    assert res.threat_score.e91_error_rate > 0.05


def test_verify_without_signing_raises():
    """Verify that attempting verification with no active packet raises ValueError."""
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)
    state.current_packet = None
    with pytest.raises(ValueError, match="No packet available"):
        verify_packet(state)


def test_attack_catalogue_completeness():
    """Verify that ATTACK_CATALOGUE contains 22 well-formed threat vectors."""
    from src.ui_helpers import ATTACK_CATALOGUE
    assert len(ATTACK_CATALOGUE) == 22
    for entry in ATTACK_CATALOGUE:
        assert entry["attack_id"].startswith("ATK-")
        assert len(entry["name"]) > 0
        assert entry["category"] in (
            "CLASSICAL CONTROL-PLANE",
            "IDENTITY & AUTHENTICATION",
            "REPLAY & PROTOCOL",
            "QDS & CRYPTOGRAPHIC",
            "QUANTUM CHANNEL",
            "RESOURCE & CONSTRAINTS",
        )
        assert entry["defense_status"] in ("DETECTED", "PREVENTED", "MITIGATED", "OUT_OF_SCOPE", "NOT_DETECTABLE")
        assert isinstance(entry["attack_type"], AttackType)


def test_measure_e91_detailed():
    """Verify detailed E91 measurement returns proper baseline and disturbance metrics."""
    from src.ui_helpers import measure_e91_detailed
    clean = measure_e91_detailed(num_pairs=50, attack_type="NONE")
    assert clean["error_rate"] == 0.0
    assert clean["channel_status"] == "NORMAL"
    assert clean["detected"] is False

    disturbed = measure_e91_detailed(num_pairs=100, attack_type="INTERCEPT_RESEND")
    assert disturbed["error_rate"] > 0.05
    assert disturbed["attack_simulated"] == "INTERCEPT_RESEND"


def test_staged_demo_pipeline_honest():
    """Verify 7-stage honest demonstration timeline pipeline."""
    from src.ui_helpers import run_staged_demo_pipeline
    demo = run_staged_demo_pipeline(mode="HONEST", n_positions=16)
    assert demo["success"] is True
    assert demo["decision"] == "ACCEPTED"
    assert len(demo["stages"]) == 7
    for s in demo["stages"]:
        assert s["status"] in ("COMPLETED", "ACCEPTED")
        assert len(s["artifacts"]) > 0


def test_staged_demo_pipeline_adversarial():
    """Verify 7-stage adversarial demonstration timeline pipeline."""
    from src.ui_helpers import run_staged_demo_pipeline
    demo = run_staged_demo_pipeline(
        mode="ADVERSARIAL",
        attack_type=AttackType.FORGERY_ATTEMPT,
        n_positions=16,
    )
    assert demo["success"] is False
    assert demo["decision"] == "REJECTED"
    assert len(demo["stages"]) == 7
    assert demo["stages"][3]["status"] == "INTERCEPTED"
    assert demo["stages"][5]["status"] == "REJECTED"


def test_consecutive_preset_scenarios_signing_and_verification():
    """
    Validate that consecutive preset scenarios (e.g. HIGH-VALUE WIRE followed by GRID COMMAND)
    both verify cleanly through Bob and Charlie without failing due to copy exhaustion.
    """
    state = initialize_protocol_session(n_positions=16, fingerprint_qubits=8)

    # 1. First scenario: HIGH-VALUE WIRE
    payload_wire = "AUTHORIZE $1,000,000,000 WIRE SETTLEMENT TO AUDITED ESCROW 9482"
    wire_pkt, t_sign1 = sign_message(state, payload_wire)
    assert wire_pkt.message == payload_wire

    bob_res1, _ = verify_packet(state, wire_pkt)
    assert bob_res1.threat_score.is_accepted is True
    assert bob_res1.threat_score.qds_mismatch_rate == 0.0

    charlie_res1, _ = transfer_to_charlie(state, wire_pkt)
    assert charlie_res1.outcome == VerificationOutcome.ACC_1
    assert charlie_res1.mismatch_rate == 0.0

    # Bob's keys should now be detected as consumed
    assert are_verifier_keys_consumed(state) is True

    # 2. Second scenario: GRID COMMAND (after preparing fresh transaction keys)
    prepare_fresh_transaction_keys(state)
    assert are_verifier_keys_consumed(state) is False

    payload_grid = "OPERATIONAL_DISPATCH_FEEDER_ISOLATION_SUBSTATION_04"
    grid_pkt, t_sign2 = sign_message(state, payload_grid)
    assert grid_pkt.message == payload_grid

    bob_res2, _ = verify_packet(state, grid_pkt)
    assert bob_res2.threat_score.is_accepted is True
    assert bob_res2.threat_score.qds_mismatch_rate == 0.0

    charlie_res2, _ = transfer_to_charlie(state, grid_pkt)
    assert charlie_res2.outcome == VerificationOutcome.ACC_1
    assert charlie_res2.mismatch_rate == 0.0


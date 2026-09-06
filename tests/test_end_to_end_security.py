import pytest
from src.attack_simulator import AttackSimulator
from src.metrics import AttackType

# We use 32 qubits for faster tests, but it still maintains statistical properties
def test_scenario_1_legitimate():
    sim = AttackSimulator(32)
    res = sim.run_attack(AttackType.NO_ATTACK, "t")
    assert not res.detected
    assert res.threat_score.is_accepted

def test_scenario_2_message_tampered():
    sim = AttackSimulator(32)
    res = sim.run_attack(AttackType.MESSAGE_TAMPERING, "t")
    assert res.detected
    assert res.detection_layer == "CLASSICAL_HASH"

def test_scenario_3_forgery_attempt():
    sim = AttackSimulator(32)
    res = sim.run_attack(AttackType.FORGERY_ATTEMPT, "t")
    assert res.detected
    assert res.detection_layer in ["CORRECTION_BITS", "ML_DSA_VERIFICATION", "QDS_VERIFICATION"]

def test_scenario_4_impersonation():
    sim = AttackSimulator(32)
    res = sim.run_attack(AttackType.IMPERSONATION, "t")
    assert res.detected
    assert res.detection_layer in ["CORRECTION_BITS", "ML_DSA_VERIFICATION", "QDS_VERIFICATION"]

def test_scenario_5_intercept_resend():
    sim = AttackSimulator(32)
    res = sim.run_attack(AttackType.INTERCEPT_RESEND, "t")
    assert res.detected
    assert res.detection_layer == "QDS_VERIFICATION"

def test_scenario_6_e91_disturbance():
    sim = AttackSimulator(32)
    res = sim.run_attack(AttackType.E91_CHANNEL_DISTURBANCE, "t")
    assert res.detected
    assert res.detection_layer == "E91_CHANNEL"

def test_scenario_7_replayed():
    sim = AttackSimulator(32)
    res = sim.run_attack(AttackType.REPLAY, "t")
    assert res.detected
    assert res.detection_layer == "REPLAY_PROTECTION"

def test_scenario_8_cross_session():
    sim = AttackSimulator(32)
    res = sim.run_attack(AttackType.CROSS_SESSION_REUSE, "t")
    assert res.detected
    # Because cross-session reuse means Alice uses a different QPKD auth context,
    # the QDS verification will fail.
    assert res.detection_layer in ["CORRECTION_BITS", "ML_DSA_VERIFICATION", "QDS_VERIFICATION"]

def test_scenario_9_compromised_context():
    sim = AttackSimulator(32)
    res = sim.run_attack(AttackType.COMPROMISED_SESSION_CONTEXT, "t")
    assert res.detected
    assert res.detection_layer == "SESSION_STATE"

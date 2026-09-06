
from src.attack_simulator import AttackSimulator
from src.metrics import AttackType

def test_message_tampering():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.MESSAGE_TAMPERING, "t")
    assert not res.attack_successful and res.detected

def test_sequence_tampering():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.SEQUENCE_TAMPERING, "t")
    assert res.detected

def test_replay_attack():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.REPLAY, "t")
    assert res.detected

def test_proof_substitution():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.PROOF_SUBSTITUTION, "t")
    assert res.detected

def test_cross_session_reuse():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.CROSS_SESSION_REUSE, "t")
    assert res.detected

def test_compromised_session_context():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.COMPROMISED_SESSION_CONTEXT, "t")
    # Even if they compromise context, they need valid PQ signatures and entanglement to pass everything
    assert res.detected

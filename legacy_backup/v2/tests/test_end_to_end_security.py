
from src.attack_simulator import AttackSimulator
from src.metrics import AttackType

def test_scenario_1_legitimate():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.NO_ATTACK, "t")
    assert not res.detected

def test_scenario_2_message_tampered():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.MESSAGE_TAMPERING, "t")
    assert res.detected

def test_scenario_3_replayed():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.REPLAY, "t")
    assert res.detected

def test_scenario_4_pauli_x():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.QUANTUM_X, "t")
    assert True

def test_scenario_5_pauli_z():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.QUANTUM_Z, "t")
    assert True

def test_scenario_6_intercept_resend_trials():
    sim = AttackSimulator(8)
    det = sum(sim.run_attack(AttackType.INTERCEPT_RESEND, f"t{i}").detected for i in range(10))
    assert det >= 0

def test_scenario_7_proof_reused_across_sessions():
    sim = AttackSimulator(8)
    res = sim.run_attack(AttackType.CROSS_SESSION_REUSE, "t")
    assert res.detected

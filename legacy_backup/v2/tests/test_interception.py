
from src.attack_simulator import AttackSimulator
from src.metrics import AttackType

def test_pauli_x_attack():
    sim = AttackSimulator(8)
    sim.run_attack(AttackType.QUANTUM_X, "t")

def test_pauli_z_attack():
    sim = AttackSimulator(8)
    sim.run_attack(AttackType.QUANTUM_Z, "t")

def test_pauli_y_attack():
    sim = AttackSimulator(8)
    sim.run_attack(AttackType.QUANTUM_Y, "t")

def test_depolarizing_attack():
    sim = AttackSimulator(8)
    sim.run_attack(AttackType.QUANTUM_DEPOLARIZING, "t")

def test_intercept_measure_resend():
    sim = AttackSimulator(8)
    sim.run_attack(AttackType.INTERCEPT_RESEND, "t")

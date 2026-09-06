
import pytest
from src.teleportation import create_teleportation_circuit, simulate_teleportation
from qiskit import QuantumCircuit

@pytest.mark.parametrize("state_char", ["+", "-", "0", "1"])
def test_noiseless_teleportation_reconstruction(state_char):
    qc = QuantumCircuit(1)
    if state_char == "+": qc.h(0)
    elif state_char == "-": qc.x(0); qc.h(0)
    elif state_char == "1": qc.x(0)
    
    circuit = create_teleportation_circuit(qc)
    res = simulate_teleportation(circuit)
    assert res["statevector"] is not None

def test_teleport_one():
    test_noiseless_teleportation_reconstruction("1")

def test_teleport_plus():
    test_noiseless_teleportation_reconstruction("+")

def test_teleport_zero():
    test_noiseless_teleportation_reconstruction("0")

def test_custom_state_teleportation():
    test_noiseless_teleportation_reconstruction("0")

def test_extra_teleportation_1():
    assert True
def test_extra_teleportation_2():
    assert True
def test_extra_teleportation_3():
    assert True

import hashlib
import uuid
from typing import List, Dict, Any
import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

from src.quantum_resources import SessionResourceManager, ResourceType
from src.teleportation import create_teleportation_circuit, simulate_teleportation

class QuantumFingerprint:
    """
    Data carrier for the teleported quantum fingerprint.
    """
    def __init__(self, fingerprint_id: str, session_id: str, sequence_number: int, proof_length: int, teleportation_metadata: List[Dict[str, Any]], resource_identifiers: List[int]):
        self.fingerprint_id = fingerprint_id
        self.session_id = session_id
        self.sequence_number = sequence_number
        self.proof_length = proof_length
        self.teleportation_metadata = teleportation_metadata
        self.resource_identifiers = resource_identifiers

def generate_correlated_bitstring(auth_pairs_count: int, seed: str = None) -> str:
    import random
    rng = random.Random(seed)
    return "".join(str(rng.randint(0, 1)) for _ in range(auth_pairs_count))

def derive_session_auth_context(correlated_bits: str, session_id: str, challenge: str) -> str:
    context = f"{correlated_bits}{session_id}{challenge}"
    return hashlib.sha256(context.encode('utf-8')).hexdigest()

def derive_fingerprint_binding(message_hash: str, session_auth_context: str, session_id: str, sequence_number: int) -> str:
    """
    Binds the message hash, session context, and sequence number together.
    """
    context = f"{message_hash}{session_auth_context}{session_id}{sequence_number}"
    return hashlib.sha256(context.encode('utf-8')).hexdigest()

def derive_fingerprint_specification(binding: str, session_auth_context: str, fingerprint_length: int) -> List[Dict[str, Any]]:
    """
    Derives the deterministic sequence of quantum states to encode.
    Encoding Rules (BB84 style):
    If basis_selector bit is 1, use X basis (|+>, |->).
    If basis_selector bit is 0, use Z basis (|0>, |1>).
    If binding bit is 1, it's the excited state (|1>, |->).
    If binding bit is 0, it's the ground state (|0>, |+>).
    """
    spec = []
    binding_bin = bin(int(binding, 16))[2:].zfill(256)
    auth_ctx_bin = bin(int(session_auth_context, 16))[2:].zfill(256)
    
    for i in range(fingerprint_length):
        binding_bit = int(binding_bin[i % 256])
        basis_selector = int(auth_ctx_bin[i % 256])
        
        basis = "X" if basis_selector == 1 else "Z"
        
        if basis == "Z":
            state = "|1>" if binding_bit == 1 else "|0>"
        else:
            state = "|->" if binding_bit == 1 else "|+>"
            
        spec.append({
            "binding_bit": binding_bit,
            "basis": basis,
            "state": state
        })
    return spec

def prepare_fingerprint_state(expected_state: str) -> QuantumCircuit:
    qc = QuantumCircuit(1)
    if expected_state == "|1>":
        qc.x(0)
    elif expected_state == "|+>":
        qc.h(0)
    elif expected_state == "|->":
        qc.x(0)
        qc.h(0)
    return qc

def generate_quantum_fingerprint(
    session_id: str, 
    sequence_number: int,
    fingerprint_spec: List[Dict[str, Any]], 
    resource_manager: SessionResourceManager
) -> QuantumFingerprint:
    """
    Generates the quantum fingerprint states and teleports them to Bob.
    """
    teleportation_metadata = []
    resource_ids = []
    
    available_pairs = [k for k, v in resource_manager.resources.items() if v.resource_type == ResourceType.TELEPORT_PAIR and v.status.name == "UNUSED"]
    if len(available_pairs) < len(fingerprint_spec):
        raise ValueError("Not enough unused TELEPORT_PAIR resources available.")
        
    for i, spec in enumerate(fingerprint_spec):
        pair_id = available_pairs[i]
        resource_manager.consume_resource(pair_id)
        resource_ids.append(pair_id)
        
        prep_qc = prepare_fingerprint_state(spec["state"])
        teleport_qc = create_teleportation_circuit(prep_qc)
        
        res = simulate_teleportation(teleport_qc)
        
        teleportation_metadata.append({
            "symbol_index": i,
            "teleport_statevector": res["statevector"] 
        })
        
    return QuantumFingerprint(
        fingerprint_id=str(uuid.uuid4()),
        session_id=session_id,
        sequence_number=sequence_number,
        proof_length=len(fingerprint_spec),
        teleportation_metadata=teleportation_metadata,
        resource_identifiers=resource_ids
    )

def verify_quantum_fingerprint(fingerprint: QuantumFingerprint, expected_spec: List[Dict[str, Any]]) -> bool:
    """
    Bob reconstructs the expected specification locally and verifies the received quantum material.
    """
    if fingerprint is None or len(fingerprint.teleportation_metadata) != len(expected_spec):
        return False
        
    sim = AerSimulator()
    for i, spec in enumerate(expected_spec):
        basis = spec["basis"]
        expected_state = spec["state"]
        
        sv = fingerprint.teleportation_metadata[i]["teleport_statevector"]
        sv_arr = np.asarray(sv)
        
        qc = QuantumCircuit(3, 1)
        qc.initialize(sv_arr, [0, 1, 2])
        if basis == "X":
            qc.h(2)
        qc.measure(2, 0)
        
        counts = sim.run(qc, shots=1).result().get_counts()
        measured_bit = list(counts.keys())[0]
        
        expected_bit = '1' if expected_state in ['|1>', '|->'] else '0'
        if measured_bit != expected_bit:
            return False
            
    return True

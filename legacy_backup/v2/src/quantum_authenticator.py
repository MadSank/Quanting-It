import hashlib
import uuid
from typing import List, Dict, Any, Tuple
from qiskit import QuantumCircuit
import numpy as np

from src.quantum_proof import QuantumProof
from src.quantum_resources import SessionResourceManager, ResourceType
from src.teleportation import create_teleportation_circuit, simulate_teleportation

# [EXPERIMENTAL PROTOCOL DESIGN]
# This module implements the session-based combination of correlated quantum material
# and message authentication via teleported quantum proofs.

def generate_correlated_bitstring(auth_pairs_count: int, seed: str = None) -> str:
    """
    [ESTABLISHED QUANTUM MECHANICS]
    In an ideal, noiseless simulation, measuring the |Φ+> Bell state in the Z-basis 
    always yields perfectly correlated outcomes for Alice and Bob.
    For this simulation, we generate a random bitstring that both Alice and Bob 
    can theoretically agree on by simulating identical Z-basis measurement outcomes.
    We use a seed here strictly to ensure the simulation deterministically produces the
    same bitstring for both Alice and Bob without needing full multi-node shared state.
    """
    # Use deterministic seeded PRNG to simulate the "correlated" nature of Bell measurements.
    # In a real physical setup, these are truly random but perfectly correlated.
    import random
    rng = random.Random(seed)
    return "".join(str(rng.randint(0, 1)) for _ in range(auth_pairs_count))

def derive_session_auth_context(correlated_bits: str, session_id: str, challenge: str) -> str:
    """
    [CLASSICAL CRYPTOGRAPHY]
    Derives the session authentication context.
    SHA256(quantum_correlated_bits || session_id || challenge)
    """
    context = f"{correlated_bits}{session_id}{challenge}"
    return hashlib.sha256(context.encode('utf-8')).hexdigest()

def derive_authentication_binding(message_hash: str, session_auth_context: str, session_id: str, sequence_number: int) -> str:
    """
    [CLASSICAL CRYPTOGRAPHY]
    Binds the message to the quantum authentication.
    SHA256(message_hash || session_auth_context || session_id || sequence_number)
    """
    context = f"{message_hash}{session_auth_context}{session_id}{sequence_number}"
    return hashlib.sha256(context.encode('utf-8')).hexdigest()

def derive_proof_specification(authentication_binding: str, session_auth_context: str, proof_length: int) -> List[Dict[str, Any]]:
    """
    [EXPERIMENTAL PROTOCOL DESIGN]
    Deterministically derive expected quantum states based on the binding and session auth context.
    """
    spec = []
    # Convert hex hashes to binary strings
    binding_bin = bin(int(authentication_binding, 16))[2:].zfill(256)
    auth_ctx_bin = bin(int(session_auth_context, 16))[2:].zfill(256)
    
    for i in range(proof_length):
        binding_bit = int(binding_bin[i % 256])
        basis_selector = int(auth_ctx_bin[i % 256])
        
        basis = "X" if basis_selector == 1 else "Z"
        
        if basis == "Z":
            state = "|1>" if binding_bit == 1 else "|0>"
        else: # basis == "X"
            state = "|->" if binding_bit == 1 else "|+>"
            
        spec.append({
            "binding_bit": binding_bit,
            "basis": basis,
            "state": state
        })
    return spec

def prepare_proof_state(expected_state: str) -> QuantumCircuit:
    """
    [ESTABLISHED QUANTUM MECHANICS]
    Prepare the input state using valid operations.
    """
    qc = QuantumCircuit(1)
    if expected_state == "|1>":
        qc.x(0)
    elif expected_state == "|+>":
        qc.h(0)
    elif expected_state == "|->":
        qc.x(0)
        qc.h(0)
    # "|0>" is default
    return qc

def generate_quantum_proof(
    session_id: str, 
    sequence_number: int,
    proof_spec: List[Dict[str, Any]], 
    resource_manager: SessionResourceManager
) -> QuantumProof:
    """
    [EXPERIMENTAL PROTOCOL DESIGN]
    Generates quantum proof states and teleports them.
    """
    teleportation_metadata = []
    resource_ids = []
    
    # We need a TELEPORT_PAIR for each symbol
    available_pairs = [k for k, v in resource_manager.resources.items() if v.resource_type == ResourceType.TELEPORT_PAIR and v.status.name == "UNUSED"]
    if len(available_pairs) < len(proof_spec):
        raise ValueError("Not enough unused TELEPORT_PAIR resources available.")
        
    for i, spec in enumerate(proof_spec):
        pair_id = available_pairs[i]
        resource_manager.consume_resource(pair_id)
        resource_ids.append(pair_id)
        
        prep_qc = prepare_proof_state(spec["state"])
        teleport_qc = create_teleportation_circuit(prep_qc)
        
        # Simulate Alice's measurement for teleportation.
        # Normally she sends classical crz and crx to Bob.
        # Here we just run the simulation to get Bob's output statevector.
        res = simulate_teleportation(teleport_qc)
        
        teleportation_metadata.append({
            "symbol_index": i,
            "teleport_statevector": res["statevector"] # In real world, only crx/crz would be transmitted, and Bob reconstructs locally. We pass SV for simulator check.
        })
        
    return QuantumProof(
        proof_id=str(uuid.uuid4()),
        session_id=session_id,
        sequence_number=sequence_number,
        proof_length=len(proof_spec),
        teleportation_metadata=teleportation_metadata,
        resource_identifiers=resource_ids
    )

def verify_quantum_proof(proof: QuantumProof, expected_spec: List[Dict[str, Any]]) -> bool:
    """
    [EXPERIMENTAL PROTOCOL DESIGN]
    Bob independently verifies the teleported proof states according to his derived expected_spec.
    """
    if len(proof.teleportation_metadata) != len(expected_spec):
        return False
        
    for i, spec in enumerate(expected_spec):
        basis = spec["basis"]
        expected_state = spec["state"]
        
        sv = proof.teleportation_metadata[i]["teleport_statevector"]
        # Convert Qiskit Statevector to np array
        sv_arr = np.asarray(sv)
        
        # In a real physical setup, Bob applies H if basis is X, then measures.
        # Since we have the statevector of all 3 qubits, and qubits 0, 1 are measured,
        # we check the state of qubit 2 (MSB in Qiskit).
        # We can extract the reduced state of qubit 2. 
        # Alternatively, simulate Bob's local measurement.
        
        qc = QuantumCircuit(3, 1)
        qc.initialize(sv_arr, [0, 1, 2])
        if basis == "X":
            qc.h(2)
        qc.measure(2, 0)
        
        from qiskit_aer import AerSimulator
        sim = AerSimulator()
        counts = sim.run(qc, shots=1).result().get_counts()
        
        # Only one outcome should be possible in an ideal simulation
        measured_bit = list(counts.keys())[0]
        
        expected_bit = '1' if expected_state in ['|1>', '|->'] else '0'
        if measured_bit != expected_bit:
            return False
            
    return True

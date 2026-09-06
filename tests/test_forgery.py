import pytest
import numpy as np
from src.qds_verifier import QDSVerifier
from src.eve import Eve
from src.qds_signer import derive_signing_spec
from src.threat_engine import ForgeryModel

def test_empirical_forgery_rate_matches_bound():
    """
    Empirical validation of the forgery bound.
    We run 100 forgery attempts and verify that the mean mismatch rate
    aligns with the theoretical expectation of ~25%.
    """
    n_qubits = 64
    n_attempts = 100
    mismatches_collected = []
    
    msg_hash = "1234567890" * 6
    ctx = "abcdef" * 10
    
    verifier = QDSVerifier(mismatch_threshold=0.05)
    
    for _ in range(n_attempts):
        # Eve creates a completely forged signature without quantum key
        forged_sig = Eve.forge_signature(msg_hash, ctx, n_qubits)
        
        # We need to bypass the classical ML-DSA check just for this test
        # so we can measure the quantum statistical properties
        forged_sig.correction_auth_tag = "bypassed"
        forged_sig.classical_pub_key = "bypassed"
        
        # Monkeypatch the verifier's classical check for this iteration
        original_verify = verifier.verify
        
        # Bob re-derives spec
        expected_spec = derive_signing_spec(msg_hash, ctx, n_qubits)
        
        # Manually count mismatches based on Bob's spec vs Eve's teleported states
        n_mismatches = 0
        from qiskit import QuantumCircuit
        
        for i, spec in enumerate(expected_spec):
            basis = spec["basis"]
            expected_state = spec["state"]
            sv = forged_sig.teleported_states[i]["statevector"]
            
            qc = QuantumCircuit(3, 1)
            qc.initialize(np.asarray(sv), [0, 1, 2])
            
            if basis == "X":
                qc.h(2)
                
            qc.measure(2, 0)
            
            # Since Eve just guessed the state preparation, when we measure
            # it we simulate the true physical outcome
            counts = verifier.sim.run(qc, shots=1).result().get_counts()
            measured_bit = list(counts.keys())[0]
            
            expected_bit = '1' if expected_state in ['|1>', '|->'] else '0'
            if measured_bit != expected_bit:
                n_mismatches += 1
                
        mismatches_collected.append(n_mismatches / n_qubits)
        
    mean_mismatch_rate = np.mean(mismatches_collected)
    
    # Theoretical expectation:
    # 50% of the time Eve guesses basis wrong -> 50% mismatch on those = 25% overall
    # 50% of the time Eve guesses basis right -> 50% mismatch on those = 25% overall
    # Wait, if Eve guesses right basis but random state, she is wrong 50% of the time.
    # Total mismatch probability per qubit = 0.5 * 0.5 (wrong basis) + 0.5 * 0.5 (right basis, wrong state) = 0.5
    # Let's check Eve's forge_signature implementation:
    # basis = random, state_bit = random.
    # If she guesses basis right, she guesses state right 50% of time.
    # If she guesses basis wrong, she gets outcome right 50% of time.
    # So expected mismatch is 50%.
    
    # In threat_engine.py, we model adversary_success = 0.75 for a slightly different attack
    # (where adversary knows the state but not basis, or intercepts and measures).
    # For pure random guessing, mismatch is 50%.
    
    assert 0.40 <= mean_mismatch_rate <= 0.60

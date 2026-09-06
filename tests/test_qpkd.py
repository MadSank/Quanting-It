import pytest
from src.qpkd import QPKDSession

def test_qpkd_distribution_clean_channel():
    """Test E91 QPKD distribution under noiseless conditions."""
    session = QPKDSession(session_id="test_session", error_threshold=0.15)
    
    # 64 signature pairs, 50 monitor pairs
    key_material = session.distribute_keys(n_signature_pairs=64, n_monitor_pairs=50)
    
    assert key_material.session_id == "test_session"
    assert key_material.n_signature_pairs == 64
    assert len(key_material.signature_statevectors) == 64
    
    # In a noiseless simulation, distribution error rate should be 0.0
    assert key_material.distribution_error_rate == 0.0
    assert key_material.distribution_secure is True
    
    # Auth context should be generated
    assert len(key_material.session_auth_context) == 64  # SHA-256 hex string

def test_qpkd_detects_e91_disturbance():
    """
    Test E91 QPKD fails when disturbance is injected.
    We mock the measurement outcome to simulate Eve's interference.
    """
    session = QPKDSession(session_id="test_session", error_threshold=0.15)
    
    # Save original distribute_keys to restore later
    original_distribute = session.distribute_keys
    
    # Mocking the simulator result to force errors
    class MockResult:
        def get_counts(self):
            # Qiskit format: outcome[0]=Bob, outcome[1]=Alice
            # Return mismatching bits to force E91 errors
            return {"01": 1}
            
    class MockSim:
        def run(self, qc, shots=1):
            class MockJob:
                def result(self):
                    return MockResult()
            return MockJob()
            
    session.sim = MockSim()
    
    key_material = session.distribute_keys(n_signature_pairs=64, n_monitor_pairs=50)
    
    # Error rate should be 1.0 (100%) because we forced mismatching bits on every shot
    assert key_material.distribution_error_rate == 1.0
    assert key_material.distribution_secure is False
    assert len(key_material.signature_statevectors) == 0  # No signature pairs allocated

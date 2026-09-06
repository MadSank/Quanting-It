import pytest
import copy
from src.qds_verifier import QDSVerifier
from src.qds_signer import QDSSigner
from src.qpkd import QPKDSession
from src.quantum_resources import SessionResourceManager, ResourceType

def setup_legitimate_signature(n_qubits=64):
    """Helper to generate a valid signature for testing the verifier."""
    session_id = "test_session"
    msg_hash = "1234567890" * 6
    
    qpkd = QPKDSession(session_id)
    qpkd.get_session_auth_context = lambda: "abcdef" * 10
    
    manager = SessionResourceManager(session_id)
    manager.allocate_pairs(n_qubits, ResourceType.SIGNATURE_PAIR)
    
    signature = QDSSigner.sign(
        message_hash=msg_hash,
        session_auth_context=qpkd.get_session_auth_context(),
        resource_manager=manager,
        session_id=session_id,
        sequence_number=1,
        n_qubits=n_qubits
    )
    
    return signature, msg_hash, qpkd.get_session_auth_context()

def test_qds_verify_legitimate():
    """Legitimate signature in noiseless sim should have 0 mismatches."""
    signature, msg_hash, ctx = setup_legitimate_signature(64)
    
    verifier = QDSVerifier(mismatch_threshold=0.05)
    result = verifier.verify(signature, msg_hash, ctx)
    
    assert result.is_valid is True
    assert result.n_mismatches == 0
    assert result.aggregate_mismatch_rate == 0.0

def test_qds_verify_forged_hash():
    """Verifying with the wrong hash should yield ~50% mismatches."""
    signature, _, ctx = setup_legitimate_signature(64)
    bad_hash = "0000000000" * 6
    
    verifier = QDSVerifier(mismatch_threshold=0.05)
    result = verifier.verify(signature, bad_hash, ctx)
    
    assert result.is_valid is False
    # In 64 qubits, random guessing gives ~50% error, so ~32 errors.
    # It's highly unlikely to have < 5% errors (<= 3 errors).
    assert result.aggregate_mismatch_rate > 0.05

def test_qds_verify_tampered_states():
    """Tampering with a teleported state should cause mismatches."""
    signature, msg_hash, ctx = setup_legitimate_signature(64)
    
    # Tamper with the first 10 qubits (simulate Pauli-X error on Bob's end)
    from src.eve import Eve
    tampered_sig = Eve.apply_pauli_x(signature, list(range(10)))
    
    verifier = QDSVerifier(mismatch_threshold=0.05)
    result = verifier.verify(tampered_sig, msg_hash, ctx)
    
    assert result.is_valid is False
    # At least some of the 10 tampered qubits should mismatch
    assert result.n_mismatches > 0
    assert result.aggregate_mismatch_rate > 0.05

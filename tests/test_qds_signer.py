import pytest
from src.qds_signer import QDSSigner, derive_signing_spec
from src.qpkd import QPKDSession
from src.quantum_resources import SessionResourceManager, ResourceType

def test_derive_signing_spec_determinism():
    """Test that deriving the spec from the same hash produces the same spec."""
    msg_hash = "a" * 64
    ctx = "b" * 64
    
    spec1 = derive_signing_spec(msg_hash, ctx, n_qubits=64)
    spec2 = derive_signing_spec(msg_hash, ctx, n_qubits=64)
    
    assert spec1 == spec2
    assert len(spec1) == 64
    
    # Check structure
    for s in spec1:
        assert s["basis"] in ["Z", "X"]
        if s["basis"] == "Z":
            assert s["state"] in ["|0>", "|1>"]
        else:
            assert s["state"] in ["|+>", "|->"]

def test_qds_signing_success():
    """Test full QDS signing flow with resource consumption."""
    session_id = "test_session"
    
    # Setup resources
    qpkd = QPKDSession(session_id)
    # We must mock get_session_auth_context since we skip actual distribution here
    qpkd.get_session_auth_context = lambda: "abcdef" * 10 
    
    manager = SessionResourceManager(session_id)
    manager.allocate_pairs(64, ResourceType.SIGNATURE_PAIR)
    
    msg_hash = "123456" * 10
    
    signature = QDSSigner.sign(
        message_hash=msg_hash,
        session_auth_context=qpkd.get_session_auth_context(),
        resource_manager=manager,
        session_id=session_id,
        sequence_number=1,
        n_qubits=64
    )
    
    assert signature.session_id == session_id
    assert signature.n_qubits == 64
    assert len(signature.teleported_states) == 64
    assert len(signature.correction_bits) == 128  # 2 bits per qubit (crz, crx)
    
    # Check that resources were consumed
    remaining = [k for k, v in manager.resources.items() if v.status.name == "UNUSED"]
    assert len(remaining) == 0

def test_qds_signing_resource_exhaustion():
    """Test signing fails if not enough Bell pairs are available."""
    session_id = "test_session"
    
    qpkd = QPKDSession(session_id)
    qpkd.get_session_auth_context = lambda: "abcdef" * 10
    
    manager = SessionResourceManager(session_id)
    manager.allocate_pairs(10, ResourceType.SIGNATURE_PAIR)  # Only 10 pairs
    
    with pytest.raises(ValueError, match="Not enough SIGNATURE_PAIR resources"):
        QDSSigner.sign(
            message_hash="123",
            session_auth_context="456",
            resource_manager=manager,
            session_id=session_id,
            sequence_number=1,
            n_qubits=64
        )

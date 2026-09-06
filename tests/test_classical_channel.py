import pytest
from src.classical_channel import ClassicalChannelAuth

def test_session_metadata_signing():
    """Test ML-DSA signing and verification of session metadata."""
    pub_hex, priv_key = ClassicalChannelAuth.generate_keys()
    
    session_id = "test_sess_123"
    challenge = "chal_abc"
    
    auth_tag = ClassicalChannelAuth.sign_session_metadata(session_id, challenge, priv_key)
    
    # Valid verification
    assert ClassicalChannelAuth.verify_session_metadata(session_id, challenge, auth_tag, pub_hex) is True
    
    # Invalid verification (tampered data)
    assert ClassicalChannelAuth.verify_session_metadata(session_id, "chal_bad", auth_tag, pub_hex) is False
    
    # Invalid verification (tampered tag)
    bad_tag = auth_tag[:-4] + "0000"
    assert ClassicalChannelAuth.verify_session_metadata(session_id, challenge, bad_tag, pub_hex) is False

def test_correction_bits_binding():
    """Test ML-DSA signing and verification of teleportation correction bits."""
    pub_hex, priv_key = ClassicalChannelAuth.generate_keys()
    
    correction_bits = "01100110" * 16  # 128 bits
    session_id = "test_sess_123"
    seq = 1
    
    auth_tag = ClassicalChannelAuth.sign_correction_bits(
        correction_bits, session_id, seq, priv_key
    )
    
    # Valid verification
    assert ClassicalChannelAuth.verify_correction_bits(
        correction_bits, session_id, seq, auth_tag, pub_hex
    ) is True
    
    # DoS Attack: Eve flips one correction bit
    tampered_bits = "1" + correction_bits[1:]
    assert ClassicalChannelAuth.verify_correction_bits(
        tampered_bits, session_id, seq, auth_tag, pub_hex
    ) is False

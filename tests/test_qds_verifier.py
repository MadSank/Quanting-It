import pytest
from src.qds_verifier import GCVerifier, VerificationOutcome, QDSVerifier
from src.qds_signer import GCSigner, GCSignature
from src.gc_keys import GCKeyGenerator, GCKeyPair, VerifierKeyRegister, PublicKeyCopy
from src.eve import Eve


def setup_gc_verifier_env(n_positions=16):
    key_pair = GCKeyGenerator.generate(n_positions=n_positions, fingerprint_qubits=8)
    reg = VerifierKeyRegister(owner="Bob")
    for i in range(n_positions):
        for b in (0, 1):
            reg.store(key_pair.distribute_copy(i, b, "Bob"))
    msg = b"TRANSFER_APPROVED"
    signature = GCSigner.sign(message=msg, key_pair=key_pair)
    verifier_env = {
        "key_pair": key_pair,
        "register": reg,
        "message": msg,
        "signature": signature,
        "n_positions": n_positions,
    }
    return verifier_env


def test_qds_verify_legitimate():
    """Legitimate signature verified against registered copies has 0 mismatches and ACC_1 outcome."""
    env = setup_gc_verifier_env(16)
    verifier = GCVerifier(acceptance_threshold=0.0, rejection_threshold=0.15)
    res = verifier.verify(
        signature=env["signature"],
        key_register=env["register"],
        message=env["message"],
    )

    assert res.outcome == VerificationOutcome.ACC_1
    assert res.n_failures == 0
    assert res.mismatch_rate == 0.0
    assert res.is_valid is True


def test_qds_verify_wrong_message():
    """Verifying with the wrong message fails immediately because message bits differ."""
    env = setup_gc_verifier_env(16)
    verifier = GCVerifier(acceptance_threshold=0.0, rejection_threshold=0.15)
    res = verifier.verify(
        signature=env["signature"],
        key_register=env["register"],
        message=b"WRONG_MESSAGE_CONTENT",
    )

    assert res.outcome == VerificationOutcome.REJ
    assert res.message_bits_match is False
    assert res.is_valid is False


def test_qds_verify_tampered_key():
    """Tampering with revealed keys causes SWAP test failures and signature rejection."""
    env = setup_gc_verifier_env(16)
    import os
    # Tamper with revealed keys across positions
    tampered_keys = list(env["signature"].revealed_keys)
    for idx in range(10):
        tampered_keys[idx] = os.urandom(len(tampered_keys[idx]))

    tampered_sig = GCSignature(
        message=env["signature"].message,
        message_bits=env["signature"].message_bits,
        n_positions=env["n_positions"],
        revealed_keys=tampered_keys,
        fingerprint_qubits=8,
        private_key_bits=128,
    )

    verifier = GCVerifier(acceptance_threshold=0.0, rejection_threshold=0.15)
    res = verifier.verify(
        signature=tampered_sig,
        key_register=env["register"],
        message=env["message"],
    )

    # With 10 invalid keys, probability of all 10 passing single shot is 0.5^10 < 0.001
    assert res.n_failures >= 1
    assert res.outcome == VerificationOutcome.REJ


def test_qds_verify_copy_exhaustion():
    """Verifying twice with the same register fails because copies are consumed (no-cloning)."""
    env = setup_gc_verifier_env(8)
    verifier = GCVerifier(acceptance_threshold=0.0, rejection_threshold=0.15)

    # First verification consumes the copies
    res1 = verifier.verify(
        signature=env["signature"],
        key_register=env["register"],
        message=env["message"],
    )
    assert res1.outcome == VerificationOutcome.ACC_1

    # Second verification fails: no available copies
    res2 = verifier.verify(
        signature=env["signature"],
        key_register=env["register"],
        message=env["message"],
    )
    assert res2.outcome == VerificationOutcome.REJ
    assert res2.n_failures == 8


def test_qds_verifier_alias():
    """Verify QDSVerifier is an alias for GCVerifier."""
    assert QDSVerifier is GCVerifier

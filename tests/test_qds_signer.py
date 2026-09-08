import pytest
from src.qds_signer import GCSigner, GCSignature, QDSSigner
from src.gc_keys import GCKeyGenerator, GCKeyPair


def test_encode_message_determinism():
    """Test that message encoding to M bits is deterministic."""
    msg = b"QUATINIT_TRANSACTION_PAYLOAD"
    bits1 = GCSigner.encode_message(msg, n_positions=32)
    bits2 = GCSigner.encode_message(msg, n_positions=32)

    assert bits1 == bits2
    assert len(bits1) == 32
    assert all(b in (0, 1) for b in bits1)


def test_encode_different_messages():
    """Different messages produce different bit sequences."""
    msg1 = b"PAYMENT_A"
    msg2 = b"PAYMENT_B"
    bits1 = GCSigner.encode_message(msg1, n_positions=32)
    bits2 = GCSigner.encode_message(msg2, n_positions=32)

    assert bits1 != bits2


def test_gc_signer_reveals_correct_keys():
    """Signer reveals Alice's private key k_{b_i}^i for each position i."""
    key_pair = GCKeyGenerator.generate(n_positions=16, fingerprint_qubits=8, private_key_bits=128)
    msg = b"HELLO GC QDS"

    sig = GCSigner.sign(
        message=msg,
        key_pair=key_pair,
        session_id="session_001",
        sequence_number=1,
    )

    assert isinstance(sig, GCSignature)
    assert sig.n_positions == 16
    assert len(sig.revealed_keys) == 16
    assert sig.session_id == "session_001"
    assert sig.sequence_number == 1

    # Verify that revealed key at position i matches k_{b_i}^i
    for i in range(16):
        expected_bit = sig.message_bits[i]
        expected_key = key_pair.private_keys[i].get_key_for_bit(expected_bit)
        assert sig.revealed_keys[i] == expected_key


def test_gc_signer_preserves_unrevealed_keys():
    """For each position, only the bit-chosen key is revealed; the complement is NOT."""
    key_pair = GCKeyGenerator.generate(n_positions=16, fingerprint_qubits=8, private_key_bits=128)
    msg = b"PARTIAL_REVELATION"

    sig = GCSigner.sign(message=msg, key_pair=key_pair)

    for i in range(16):
        chosen_bit = sig.message_bits[i]
        complement_bit = 1 - chosen_bit
        complement_key = key_pair.private_keys[i].get_key_for_bit(complement_bit)

        # The complement key must NOT be in revealed_keys for this position
        assert sig.revealed_keys[i] != complement_key


def test_qds_signer_alias_backward_compatibility():
    """Verify QDSSigner alias works as GCSigner."""
    assert QDSSigner is GCSigner

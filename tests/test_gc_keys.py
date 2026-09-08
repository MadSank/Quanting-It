"""
Test Suite: GC Keys — Key Generation, Copy Budget, Distribution
================================================================

Tests:
  - Key generation produces correct structure
  - Holevo security margin check
  - Copy budget enforcement
  - Copy exhaustion rejection
  - Copy reuse rejection
  - Distribution to verifiers
  - Excessive distribution detection
"""

import os
import pytest

from src.gc_keys import (
    GCKeyGenerator,
    GCKeyPair,
    GCPrivateKey,
    PublicKeyCopy,
    CopyBudget,
    CopyStatus,
    VerifierKeyRegister,
)


class TestKeyGeneration:
    """Tests for GC key pair generation."""

    def test_generate_default(self):
        """Generate default key pair with M=32, n=8, L=128."""
        kp = GCKeyGenerator.generate()
        assert kp.n_positions == 32
        assert kp.fingerprint_qubits == 8
        assert kp.private_key_length == 128
        assert kp.encoded_length == 256
        assert len(kp.private_keys) == 32

    def test_generate_custom(self):
        """Generate with custom parameters."""
        kp = GCKeyGenerator.generate(
            n_positions=8, fingerprint_qubits=6,
            private_key_bits=64, max_total_copies=2,
        )
        assert kp.n_positions == 8
        assert kp.fingerprint_qubits == 6
        assert kp.encoded_length == 64
        assert len(kp.private_keys) == 8

    def test_private_keys_independent(self):
        """k0 and k1 are different for each position."""
        kp = GCKeyGenerator.generate(n_positions=4)
        for pk in kp.private_keys:
            assert pk.k0 != pk.k1

    def test_private_key_length(self):
        """Private keys have correct byte length."""
        kp = GCKeyGenerator.generate(private_key_bits=128)
        for pk in kp.private_keys:
            assert len(pk.k0) == 16  # 128 bits = 16 bytes
            assert len(pk.k1) == 16

    def test_holevo_margin(self):
        """Holevo security margin L - T·n should be positive and correct."""
        kp = GCKeyGenerator.generate(
            private_key_bits=128, fingerprint_qubits=8, max_total_copies=4
        )
        assert kp.holevo_security_margin() == 128 - 4 * 8  # = 96
        assert kp.holevo_security_margin() > 0

    def test_insecure_parameters_rejected(self):
        """Parameters where L - T·n <= 0 should raise ValueError."""
        with pytest.raises(ValueError, match="Holevo security margin"):
            GCKeyGenerator.generate(
                private_key_bits=8, fingerprint_qubits=8, max_total_copies=2,
            )


class TestCopyBudget:
    """Tests for quantum public key copy budget enforcement."""

    def test_initial_budget(self):
        """Copy budget starts with correct values."""
        cb = CopyBudget(position=0, bit=0, max_copies=4)
        assert cb.remaining_copies == 4
        assert cb.distributed_copies == 0
        assert cb.consumed_copies == 0
        assert cb.can_distribute()

    def test_distribute(self):
        """Distributing decrements remaining copies."""
        cb = CopyBudget(position=0, bit=0, max_copies=2)
        cb.distribute()
        assert cb.remaining_copies == 1
        cb.distribute()
        assert cb.remaining_copies == 0

    def test_exhaustion(self):
        """Cannot distribute beyond max copies."""
        cb = CopyBudget(position=0, bit=0, max_copies=1)
        cb.distribute()
        assert not cb.can_distribute()
        with pytest.raises(RuntimeError, match="Copy budget exhausted"):
            cb.distribute()


class TestPublicKeyCopy:
    """Tests for individual public key copy management."""

    def test_consume(self):
        """Consuming a copy returns statevector and marks as consumed."""
        from src.qowf import encode, prepare_statevector
        k = os.urandom(16)
        cw = encode(k, 8)
        sv = prepare_statevector(cw, 8)
        copy = PublicKeyCopy(position=0, bit=0, statevector=sv, owner="Bob")
        returned_sv = copy.consume()
        assert copy.status == CopyStatus.CONSUMED
        assert returned_sv is sv

    def test_double_consume_rejected(self):
        """Cannot consume the same copy twice (no-cloning)."""
        from src.qowf import encode, prepare_statevector
        k = os.urandom(16)
        sv = prepare_statevector(encode(k, 8), 8)
        copy = PublicKeyCopy(position=0, bit=0, statevector=sv, owner="Bob")
        copy.consume()
        with pytest.raises(RuntimeError, match="already consumed"):
            copy.consume()


class TestVerifierKeyRegister:
    """Tests for verifier key storage and consumption."""

    def test_store_and_retrieve(self):
        """Store and retrieve a public key copy."""
        from src.qowf import encode, prepare_statevector
        k = os.urandom(16)
        sv = prepare_statevector(encode(k, 8), 8)
        reg = VerifierKeyRegister(owner="Bob")
        copy = PublicKeyCopy(position=0, bit=0, statevector=sv, owner="Bob")
        reg.store(copy)
        assert reg.has_available_copy(0, 0)

    def test_consume_marks_unavailable(self):
        """After consuming, copy is no longer available."""
        from src.qowf import encode, prepare_statevector
        k = os.urandom(16)
        sv = prepare_statevector(encode(k, 8), 8)
        reg = VerifierKeyRegister(owner="Bob")
        copy = PublicKeyCopy(position=0, bit=0, statevector=sv, owner="Bob")
        reg.store(copy)
        reg.consume_copy(0, 0)
        assert not reg.has_available_copy(0, 0)

    def test_consume_nonexistent_raises(self):
        """Consuming a copy that doesn't exist raises KeyError."""
        reg = VerifierKeyRegister(owner="Bob")
        with pytest.raises(KeyError):
            reg.consume_copy(0, 0)

    def test_duplicate_store_rejected(self):
        """Cannot store two copies for the same (position, bit)."""
        from src.qowf import encode, prepare_statevector
        k = os.urandom(16)
        sv = prepare_statevector(encode(k, 8), 8)
        reg = VerifierKeyRegister(owner="Bob")
        copy1 = PublicKeyCopy(position=0, bit=0, statevector=sv, owner="Bob")
        copy2 = PublicKeyCopy(position=0, bit=0, statevector=sv, owner="Bob")
        reg.store(copy1)
        with pytest.raises(RuntimeError, match="already has a copy"):
            reg.store(copy2)


class TestDistribution:
    """Tests for key distribution to verifiers."""

    def test_distribute_to_verifier(self):
        """Distribute keys to Bob creates a complete register."""
        kp = GCKeyGenerator.generate(n_positions=4, max_total_copies=4)
        reg = GCKeyGenerator.distribute_to_verifier(kp, "Bob")
        # Should have 4 positions × 2 bits = 8 copies
        assert len(reg.copies) == 8
        for i in range(4):
            for b in (0, 1):
                assert reg.has_available_copy(i, b)

    def test_distribute_to_two_verifiers(self):
        """Can distribute to Bob and Charlie within copy budget."""
        kp = GCKeyGenerator.generate(n_positions=4, max_total_copies=4)
        bob_reg = GCKeyGenerator.distribute_to_verifier(kp, "Bob")
        charlie_reg = GCKeyGenerator.distribute_to_verifier(kp, "Charlie")
        assert len(bob_reg.copies) == 8
        assert len(charlie_reg.copies) == 8

    def test_excessive_distribution_rejected(self):
        """Distribution beyond copy budget raises RuntimeError."""
        kp = GCKeyGenerator.generate(n_positions=4, max_total_copies=2)
        GCKeyGenerator.distribute_to_verifier(kp, "Bob")
        # Budget was 2 per key, Bob took 1 each. 
        # Distributing to Charlie should still work (uses copy 2)
        GCKeyGenerator.distribute_to_verifier(kp, "Charlie")
        # Third verifier would exceed budget
        with pytest.raises(RuntimeError, match="Copy budget exhausted"):
            GCKeyGenerator.distribute_to_verifier(kp, "Eve")

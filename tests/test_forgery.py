import pytest
import numpy as np
import os
from src.qds_verifier import GCVerifier, VerificationOutcome
from src.qds_signer import GCSigner, GCSignature
from src.gc_keys import GCKeyGenerator, GCKeyPair, VerifierKeyRegister
from src.eve import Eve
from src.threat_engine import GCForgeryModel, ForgeryModel


def test_gc_empirical_forgery_mismatch_rate():
    """
    Empirical validation of the Gottesman-Chuang forgery bound.
    When Eve generates random keys without knowing Alice's private keys,
    the SWAP test between |f_{k_eve}⟩ and stored public key |f_{k_alice}⟩
    has acceptance probability ~0.50 (mismatch rate ~50%).
    """
    n_positions = 16
    n_attempts = 15
    mismatches_collected = []

    for _ in range(n_attempts):
        # Generate fresh keys for each attempt
        key_pair = GCKeyGenerator.generate(n_positions=n_positions, fingerprint_qubits=8)
        reg = VerifierKeyRegister(owner="Bob")
        for i in range(n_positions):
            for b in (0, 1):
                reg.store(key_pair.distribute_copy(i, b, "Bob"))

        msg = b"TRANSFER $1,000,000"
        forged_sig = Eve.forge_gc_signature(message=msg, n_positions=n_positions, key_bytes=16)

        verifier = GCVerifier(acceptance_threshold=0.05, rejection_threshold=0.20)
        res = verifier.verify(signature=forged_sig, key_register=reg, message=msg)

        # For Bob, any forgery must be rejected (outcome must NOT be 1-ACC)
        assert res.outcome != VerificationOutcome.ACC_1
        mismatches_collected.append(res.mismatch_rate)

    mean_mismatch = float(np.mean(mismatches_collected))
    # Overlap ≈ 0 implies SWAP test fails ~50% of the time
    assert 0.35 <= mean_mismatch <= 0.65


def test_gc_forgery_bound_calculation():
    """Verify that GCForgeryModel computes the expected theoretical bound."""
    p_forge = GCForgeryModel.compute_forgery_bound(
        m_positions=32,
        threshold_fraction=0.05,
        overlap=0.15,
        key_bits=128,
        max_copies=4,
        fingerprint_qubits=8
    )
    # With 32 positions, threshold 5% (max 1 error) and p_error ~ 0.49:
    # Binom(32, 0.49) <= 1 error is < 1e-4
    assert p_forge < 1e-4

    sec_bits = GCForgeryModel.compute_security_level(
        m_positions=32,
        threshold_fraction=0.05
    )
    assert sec_bits >= 15


def test_holevo_key_secrecy_bound():
    """Verify Holevo's theorem accessible-information budget and entropy gap indicator."""
    acc_info = GCForgeryModel.holevo_accessible_information(max_copies=4, fingerprint_qubits=8)
    assert acc_info == 32  # T·n = 4 × 8 = 32 bits accessible information budget

    margin = GCForgeryModel.holevo_margin(key_bits=128, max_copies=4, fingerprint_qubits=8)
    assert margin == 96  # L - T·n = 128 - 32 = 96 bits of entropy gap

    # Positive entropy gap means key is not revealed; forgery is determined by SWAP test binomial distribution
    p_forge = GCForgeryModel.compute_forgery_bound(m_positions=32, threshold_fraction=0.05)
    assert p_forge < 1e-4

    # Depleted entropy gap (margin <= 0) collapses security to 1.0
    p_depleted = GCForgeryModel.compute_forgery_bound(
        m_positions=32, threshold_fraction=0.05, key_bits=32, max_copies=4, fingerprint_qubits=8
    )
    assert p_depleted == 1.0

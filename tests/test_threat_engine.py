import pytest
from src.threat_engine import ForgeryModel, ThreatScorer

def test_forgery_bound_computation():
    """Test the derived binomial bound for forgery probability."""
    # 64 qubits, 5% threshold (max 3 errors)
    p_forge = ForgeryModel.compute_forgery_bound(64, 0.05, adversary_success=0.75)
    # The probability of 64 independent 0.75-probability events yielding >= 61 successes
    # is around 1.8e-05 (~ 2^-15).
    assert p_forge < 1e-4
    
    sec_bits = ForgeryModel.compute_security_level(64, 0.05)
    assert sec_bits > 10

def test_optimal_threshold():
    """Test finding the optimal threshold for a target security level."""
    # To get 15 bits of security with 64 qubits, we can tolerate some errors
    threshold = ForgeryModel.optimal_threshold(64, target_security_bits=15)
    assert threshold > 0.0
    assert threshold < 0.25
    
    # Verify it gives at least 15 bits
    sec_bits = ForgeryModel.compute_security_level(64, threshold)
    assert sec_bits >= 15

def test_threat_scorer_accept():
    """Test ThreatScorer produces an ACCEPT verdict for clean inputs."""
    scorer = ThreatScorer(qds_threshold=0.05, e91_threshold=0.15)
    
    score = scorer.evaluate(
        qds_mismatch_rate=0.0,
        qds_n_qubits=64,
        qds_n_mismatches=0,
        correction_bits_valid=True,
        e91_error_rate=0.0,
        classical_hash_valid=True,
        session_valid=True,
        replay_valid=True,
        ml_dsa_valid=True
    )
    
    assert score.is_accepted is True
    assert score.overall_confidence == 1.0
    assert "ACCEPT" in score.threat_assessment
    assert score.protocol_model == "TWO_PARTY_QMAC"

def test_threat_scorer_reject_qds():
    """Test ThreatScorer rejects when QDS mismatch is too high."""
    scorer = ThreatScorer(qds_threshold=0.05, e91_threshold=0.15)
    
    score = scorer.evaluate(
        qds_mismatch_rate=0.25,  # Forgery attempt
        qds_n_qubits=64,
        qds_n_mismatches=16,
        correction_bits_valid=True,
        e91_error_rate=0.0,
        classical_hash_valid=True,
        session_valid=True,
        replay_valid=True,
        ml_dsa_valid=True
    )
    
    assert score.is_accepted is False
    assert score.overall_confidence < 0.5
    assert "REJECT" in score.threat_assessment
    assert "EXCEEDS tolerance" in score.threat_assessment

def test_threat_scorer_reject_classical():
    """Test ThreatScorer rejects when classical checks fail, even if QDS is fine."""
    scorer = ThreatScorer(qds_threshold=0.05, e91_threshold=0.15)
    
    score = scorer.evaluate(
        qds_mismatch_rate=0.0,
        qds_n_qubits=64,
        qds_n_mismatches=0,
        correction_bits_valid=False,  # Eve flipped a bit
        e91_error_rate=0.0,
        classical_hash_valid=True,
        session_valid=True,
        replay_valid=True,
        ml_dsa_valid=True
    )
    
    assert score.is_accepted is False
    assert score.overall_confidence < 0.5
    assert "REJECT" in score.threat_assessment
    assert "CORRECTION BITS TAMPERED" in score.threat_assessment

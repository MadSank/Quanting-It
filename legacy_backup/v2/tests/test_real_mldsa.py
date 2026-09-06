import pytest
from src.pq_signature import ML_DSA_SIGNER

def test_mldsa_valid_signature():
    pub, priv = ML_DSA_SIGNER.generate_keys()
    digest = "7b2a5bfb704fdf62952266dccf375a3b961129bbb4020fea6a82bbb144b15076"
    sig = ML_DSA_SIGNER.sign(digest, priv)
    assert ML_DSA_SIGNER.verify(digest, sig, pub)

def test_mldsa_tampered_message():
    pub, priv = ML_DSA_SIGNER.generate_keys()
    digest = "7b2a5bfb704fdf62952266dccf375a3b961129bbb4020fea6a82bbb144b15076"
    sig = ML_DSA_SIGNER.sign(digest, priv)
    bad_digest = "0000000000000000000000000000000000000000000000000000000000000000"
    assert not ML_DSA_SIGNER.verify(bad_digest, sig, pub)

def test_mldsa_tampered_signature():
    pub, priv = ML_DSA_SIGNER.generate_keys()
    digest = "7b2a5bfb704fdf62952266dccf375a3b961129bbb4020fea6a82bbb144b15076"
    sig = ML_DSA_SIGNER.sign(digest, priv)
    
    # Flip the last character in the hex string to a different hex char
    last_char = sig[-1]
    new_char = '0' if last_char != '0' else '1'
    bad_sig = sig[:-1] + new_char
    
    assert not ML_DSA_SIGNER.verify(digest, bad_sig, pub)

def test_mldsa_wrong_public_key():
    pub1, priv1 = ML_DSA_SIGNER.generate_keys()
    pub2, priv2 = ML_DSA_SIGNER.generate_keys()
    
    digest = "7b2a5bfb704fdf62952266dccf375a3b961129bbb4020fea6a82bbb144b15076"
    sig = ML_DSA_SIGNER.sign(digest, priv1)
    
    assert not ML_DSA_SIGNER.verify(digest, sig, pub2)

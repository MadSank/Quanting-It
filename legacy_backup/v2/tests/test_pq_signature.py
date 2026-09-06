from src.pq_signature import DEMO_PQ_SIGNER
def test_pq_sign_verify():
    pub, priv = DEMO_PQ_SIGNER.generate_keys()
    sig = DEMO_PQ_SIGNER.sign("hash", priv, pub)
    assert DEMO_PQ_SIGNER.verify("hash", sig, pub)

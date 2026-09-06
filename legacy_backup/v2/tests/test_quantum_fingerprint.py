from src.quantum_fingerprint import derive_fingerprint_binding, derive_fingerprint_specification, generate_correlated_bitstring, derive_session_auth_context
def test_binding():
    cbits = generate_correlated_bitstring(256)
    ctx = derive_session_auth_context(cbits, "sess", "chal")
    assert derive_fingerprint_binding("h", ctx, "sess", 1) is not None


from src.crypto import compute_message_hash

def test_hash_integrity():
    h1 = compute_message_hash("msg", "sess", "chal", 1)
    h2 = compute_message_hash("msg", "sess", "chal", 1)
    h3 = compute_message_hash("msg2", "sess", "chal", 1)
    assert h1 == h2
    assert h1 != h3

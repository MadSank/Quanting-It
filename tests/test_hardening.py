"""
Regression tests for the hardening pass (legacy v0 fixes and the v2 channel).

Each test pins one protection: if a later change weakens it, the test fails.
"""

import copy

import pytest

from src.crypto import compute_message_hash, generate_challenge
from src.gc_keys import GCKeyGenerator
from src.qds_signer import GCSigner
from src.qsc.channel import run_session
from src.qsc.wire import Adversary, Envelope


# ---------------------------------------------------------------------------
#  Legacy v0
# ---------------------------------------------------------------------------

def test_hash_fields_cannot_shift():
    """Moving characters between adjacent fields must change the hash."""
    a = compute_message_hash("ab", "c", "chal", 1)
    b = compute_message_hash("a", "bc", "chal", 1)
    c = compute_message_hash("msg", "sess", "chal", 12)
    d = compute_message_hash("msg", "sess", "chal1", 2)
    assert a != b
    assert c != d


def test_gc_key_pair_is_one_time():
    kp = GCKeyGenerator.generate(n_positions=8)
    GCSigner.sign(b"first", kp, session_id="s", sequence_number=1)
    with pytest.raises(RuntimeError):
        GCSigner.sign(b"second", kp, session_id="s", sequence_number=2)


def test_signature_bits_bound_to_session_and_slot():
    m = b"same message"
    base = GCSigner.encode_message(m, 32, GCSigner.binding_context("s1", 1))
    assert base != GCSigner.encode_message(m, 32, GCSigner.binding_context("s2", 1))
    assert base != GCSigner.encode_message(m, 32, GCSigner.binding_context("s1", 2))


def _legacy_pair():
    from src.alice import Alice
    from src.bob import Bob
    from src.classical_channel import ClassicalChannelAuth
    from src.e91_monitor import E91Monitor
    from src.session import SessionManager

    pub, priv = ClassicalChannelAuth.generate_keys()
    sm = SessionManager(); sm.start_session(generate_challenge())
    alice = Alice(sm, classical_priv_key=priv, classical_pub_key=pub, key_pair=GCKeyGenerator.generate())
    bob = Bob(sm, e91_monitor=E91Monitor(num_pairs=16), trusted_classical_pub_key=pub)
    bob.receive_public_keys(alice.distribute_public_keys(["Bob"], teleport=False)["Bob"])
    return alice, bob


def test_missing_ml_dsa_tag_is_rejected():
    alice, bob = _legacy_pair()
    pkt = alice.create_packet("pay 10 to carol")
    pkt.ml_dsa_signature = None
    res = bob.verify_packet(pkt)
    assert not res.threat_score.is_accepted
    assert res.rejection_code == "ML_DSA_INVALID"


def test_ml_dsa_covers_every_revealed_key():
    """Changing any one revealed key breaks the transcript signature."""
    alice, bob = _legacy_pair()
    pkt = alice.create_packet("pay 10 to carol")
    keys = list(pkt.qds_signature.revealed_keys)
    keys[-1] = bytes(len(keys[-1]))
    pkt.qds_signature.revealed_keys = keys
    res = bob.verify_packet(pkt)
    assert not res.threat_score.is_accepted
    assert res.rejection_code == "ML_DSA_INVALID"


def test_rejected_packet_does_not_use_up_its_sequence_number():
    alice, bob = _legacy_pair()
    good = alice.create_packet("pay 10 to carol")
    bad = copy.deepcopy(good)
    bad.message = "pay 10 to someone else"
    assert not bob.verify_packet(bad).threat_score.is_accepted
    assert bob.verify_packet(good).threat_score.is_accepted
    # and the same slot is refused once it has been accepted
    assert bob.verify_packet(copy.deepcopy(good)).rejection_code == "REPLAY_DETECTED"


# ---------------------------------------------------------------------------
#  v2 channel
# ---------------------------------------------------------------------------

MSGS = ["hello", "a longer second message for bob", "3"]


class _Edit(Adversary):
    """Applies one edit to the first envelope of a given kind."""
    def __init__(self, kind, edit):
        self.kind, self.edit, self.done = kind, edit, False

    def on_classical(self, env):
        if env.kind == self.kind and not self.done:
            self.done = True
            return self.edit(env)
        return env


def _flip_hex(h: str, i: int = 0) -> str:
    return h[:i] + ("0" if h[i] != "0" else "1") + h[i + 1:]


@pytest.fixture(scope="module")
def honest_v2():
    return run_session("v2", MSGS)


def test_v2_delivers_honestly_with_all_three_keys(honest_v2):
    assert not honest_v2.aborted
    assert honest_v2.accepted == MSGS
    assert set(honest_v2.key_sources) == {"qkd", "mlkem768", "x25519"}


def test_v2_wire_never_carries_plaintext(honest_v2):
    data = [e["payload"] for e in honest_v2.wire_log if e["kind"] == "data"]
    assert len(data) == len(MSGS)
    blob = str(data).encode().hex() + str(data)
    for m in MSGS:
        if len(m) > 2:
            assert m not in blob and m.encode().hex() not in blob


def test_v2_padding_hides_short_length_differences(honest_v2):
    sizes = {len(e["payload"]["ct"]) for e in honest_v2.wire_log if e["kind"] == "data"}
    assert len(sizes) == 1


def test_v2_never_falls_back_to_classical_only():
    from src.qsc.channel import VERSIONS
    cfg = VERSIONS["v2"]
    assert cfg.fallback == "none" and "mlkem768" in cfg.kem and cfg.min_secrets >= 2


def test_v2_rejects_modified_ciphertext():
    def edit(env):
        env.payload["ct"] = _flip_hex(env.payload["ct"], 10)
        return env
    rep = run_session("v2", MSGS, _Edit("data", edit))
    assert MSGS[0] not in rep.accepted and rep.rejected >= 1
    assert all(m in MSGS for m in rep.accepted)


def test_v2_rejects_packet_without_signature():
    def edit(env):
        env.payload.pop("sig", None)
        return env
    rep = run_session("v2", MSGS, _Edit("data", edit))
    assert MSGS[0] not in rep.accepted


class _Repeat(Adversary):
    """Delivers honestly, then hands Bob an extra copy of the first data packet."""
    def __init__(self):
        self.first = None

    def on_classical(self, env):
        if env.kind == "data" and self.first is None:
            self.first = copy.deepcopy(env)
        return env

    def forge(self):
        return [self.first] if self.first else []


def test_v2_accepts_each_packet_once():
    rep = run_session("v2", MSGS, _Repeat())
    assert rep.accepted == MSGS
    assert rep.rejected == 1


def test_v2_handshake_messages_are_authenticated():
    """Any change to a signed QKD message makes the QKD stage abort."""
    def edit(env):
        env.payload["bases"] = [1 - b for b in env.payload["bases"][:5]] + env.payload["bases"][5:]
        return env
    rep = run_session("v2", MSGS, _Edit("qkd_sift", edit))
    assert "qkd" not in rep.key_sources
    assert "signature" in rep.qkd_stats.get("abort", "")


def test_v2_aborts_if_kem_ciphertext_changes():
    def edit(env):
        env.payload["ct"] = _flip_hex(env.payload["ct"], 4)
        return env
    rep = run_session("v2", MSGS, _Edit("kem_ct", edit))
    assert rep.aborted and not rep.accepted

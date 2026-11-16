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


# ---------------------------------------------------------------------------
#  Architecture review fixes
# ---------------------------------------------------------------------------

def test_rejected_packet_does_not_burn_quantum_copies():
    """SWAP tests (which destroy copies) run only after the classical checks pass."""
    alice, bob = _legacy_pair()
    good = alice.create_packet("pay 10 to carol")
    bad = copy.deepcopy(good)
    bad.ml_dsa_signature = None
    res = bob.verify_packet(bad)
    assert not res.threat_score.is_accepted and res.details["qds_skipped"]
    consumed = [c for c in bob.key_register.copies.values() if c.status.name == "CONSUMED"]
    assert consumed == []
    assert bob.verify_packet(good).threat_score.is_accepted


class _DropFirstData(Adversary):
    def __init__(self):
        self.dropped = False

    def on_classical(self, env):
        if env.kind == "data" and not self.dropped:
            self.dropped = True
            return None
        return env


def test_v2_survives_a_lost_message():
    """A dropped packet no longer stalls the ratchet for the rest of the session."""
    rep = run_session("v2", MSGS, _DropFirstData())
    assert rep.accepted == MSGS[1:]


def test_v2_records_why_packets_were_rejected():
    def edit(env):
        env.payload["ct"] = _flip_hex(env.payload["ct"], 10)
        return env
    rep = run_session("v2", MSGS, _Edit("data", edit))
    assert rep.rejections.get("bad signature") == 1


def test_v2_aborts_if_hello_is_changed():
    def edit(env):
        env.payload["v"] = "v1"
        return env
    rep = run_session("v2", MSGS, _Edit("hello", edit))
    assert rep.aborted and not rep.accepted


# ---------------------------------------------------------------------------
#  Round 3 fixes and the v3 architecture
# ---------------------------------------------------------------------------

def test_qkd_verification_tag_matches_counted_leak(honest_v2):
    tags = [e["payload"]["hash"] for e in honest_v2.wire_log if e["kind"] == "qkd_verify"]
    assert tags and all(len(t) == 16 for t in tags)   # 64 bits, as counted


from src.qsc.v3 import Policy  # noqa: E402

REPLIES = ["got it", "see you there"]


@pytest.fixture(scope="module")
def honest_v3():
    return run_session("v3", MSGS, replies=REPLIES)


def test_v3_delivers_both_ways_with_all_three_keys(honest_v3):
    assert not honest_v3.aborted
    assert honest_v3.accepted == MSGS and honest_v3.replies_accepted == REPLIES
    assert set(honest_v3.key_sources) == {"qkd", "mlkem768", "x25519"}


def test_v3_directions_use_separate_keys(honest_v3):
    recs = [e["payload"] for e in honest_v3.wire_log if e["kind"] == "data"]
    a2b = {r["hdr"]["seq"]: r["ct"] for r in recs if r["hdr"]["dir"] == "A>B"}
    b2a = {r["hdr"]["seq"]: r["ct"] for r in recs if r["hdr"]["dir"] == "B>A"}
    assert a2b[1] != b2a[1]


class _Reflect(Adversary):
    """Hands Bob's own first record back to Bob."""
    def __init__(self):
        self.rec = None

    def on_classical(self, env):
        if env.kind == "data" and env.src == "Bob" and self.rec is None:
            self.rec = copy.deepcopy(env)
        return env

    def forge(self):
        if not self.rec:
            return []
        return [Envelope("Alice", "Bob", "data", self.rec.payload)]


def test_v3_rejects_a_record_sent_back_to_its_sender():
    rep = run_session("v3", MSGS, _Reflect(), replies=REPLIES)
    assert rep.accepted == MSGS
    assert rep.rejections.get("wrong session or direction") == 1


@pytest.mark.parametrize("kind,field", [("hello", "x25519"), ("reply", "ct"), ("finish", "fin")])
def test_v3_any_handshake_change_aborts(kind, field):
    def edit(env):
        env.payload[field] = _flip_hex(env.payload[field], 6)
        return env
    rep = run_session("v3", MSGS, _Edit(kind, edit), v3_policy=Policy(qkd="off"))
    assert rep.aborted and not rep.accepted


def _tamper_sift(env):
    env.payload["bases"] = [1 - b for b in env.payload["bases"][:5]] + env.payload["bases"][5:]
    return env


def test_v3_qkd_required_policy_aborts_without_photon_key():
    rep = run_session("v3", MSGS, _Edit("qkd_sift", _tamper_sift), v3_policy=Policy(qkd="required"))
    assert rep.aborted and "QKD required" in rep.abort_reason and not rep.accepted


def test_v3_qkd_preferred_policy_reports_post_quantum_only():
    rep = run_session("v3", MSGS, _Edit("qkd_sift", _tamper_sift), v3_policy=Policy(qkd="preferred"))
    assert rep.accepted == MSGS
    assert "qkd" not in rep.key_sources and "mlkem768" in rep.key_sources


def test_v3_replay_and_loss():
    rep = run_session("v3", MSGS, _Repeat(), v3_policy=Policy(qkd="off"))
    assert rep.accepted == MSGS and rep.rejections.get("replay") == 1
    rep = run_session("v3", MSGS, _DropFirstData(), v3_policy=Policy(qkd="off"))
    assert rep.accepted == MSGS[1:]


def test_v3_wipes_master_secret_after_handshake():
    from src.qsc.v3 import run_v3
    from src.qsc.channel import SessionReport
    from src.qsc.wire import Wire, PassiveTap
    w = Wire(PassiveTap())
    alice, bob = run_v3(["x"], w, SessionReport(version="v3"), policy=Policy(qkd="off"))
    assert alice.master is None and bob.master is None


def test_v3_wire_never_carries_plaintext(honest_v3):
    data = [e["payload"] for e in honest_v3.wire_log if e["kind"] == "data"]
    blob = str(data)
    for m in MSGS + REPLIES:
        if len(m) > 2:
            assert m not in blob and m.encode().hex() not in blob


def test_v3_checks_survive_python_optimise_mode():
    """No security check in v3 may rely on assert (stripped by python -O)."""
    import src.qsc.v3 as v3
    src_text = open(v3.__file__, encoding="utf-8").read()
    import re
    assert not re.search(r"^\s+assert ", src_text, re.MULTILINE)


def test_v3_rejects_out_of_order_handshake():
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from src.qsc.bb84 import ProtocolAbort
    from src.qsc.v3 import Party
    a, b = mldsa.MLDSA65PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
    bob = Party("B", b, a.public_key())
    with pytest.raises(ProtocolAbort):
        bob.on_finish({"sig": "00", "fin": "00"})


def test_v3_hello_must_name_the_right_parties():
    def edit(env):
        env.payload["id"] = "0" * 32
        return env
    rep = run_session("v3", MSGS, _Edit("hello", edit), v3_policy=Policy(qkd="off"))
    assert rep.aborted and "wrong parties" in rep.abort_reason


def test_error_correction_leak_stays_bounded():
    """A stale binary search used to cascade into wrong flips and leak far more
    parity than needed, occasionally leaving no secret key on a clean fibre."""
    for _ in range(6):
        rep = run_session("v3", ["x"])
        st = rep.qkd_stats
        assert "qkd" in rep.key_sources, st.get("abort")
        assert st["ec_leak"] < 0.2 * st["sifted"]

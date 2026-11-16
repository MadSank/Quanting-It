"""
Quantum-Safe Channel (QSC): versioned secure-messaging protocol used by the
red-team arena.

  v0  legacy Quatinit packet (GC-QDS signature + ML-DSA transcript tag),
      message travels in the clear. Adapter around src.alice / src.bob.
  v1+ encrypted channel: QKD (BB84) and/or post-quantum KEM key agreement,
      AEAD data plane. Each later version enables defences discovered
      through red-team rounds (see docs/RED_TEAM_LOG.md).

Every byte that crosses the network goes through Wire, so the adversary sees
and may alter all of it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass, field, replace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.qsc.bb84 import ClassicalLink, Endpoint, ProtocolAbort, QKDConfig, canon, run_bb84
from src.qsc.wire import Adversary, AttackContext, Envelope, PassiveTap, ShorOracle, Wire


@dataclass
class ChannelConfig:
    name: str
    qkd: QKDConfig | None = None
    kem: tuple = ()                 # subset of ("mlkem768", "x25519")
    fallback: str = "none"          # "x25519": classical DH if QKD aborts
    identity_auth: bool = False     # pinned ML-DSA identity keys sign handshake
    key_confirmation: bool = False
    replay_protection: bool = False
    pad_to: int = 0                 # pad plaintext to multiple of this many bytes
    ratchet: bool = False           # per-message symmetric ratchet (forward secrecy)
    sign_messages: bool = False     # ML-DSA signature on every data packet
    min_secrets: int = 1            # handshake aborts with fewer independent secrets
    description: str = ""


def _hkdf(ikm: bytes, salt: bytes, info: bytes, n: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=n, salt=salt, info=info).derive(ikm)


def _raw_pub(k) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass
class SessionReport:
    version: str
    sent: list = field(default_factory=list)
    accepted: list = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""
    abort_stage: str = ""
    key_sources: list = field(default_factory=list)
    qkd_stats: dict = field(default_factory=dict)
    rejected: int = 0
    rejections: dict = field(default_factory=dict)
    replies_accepted: list = field(default_factory=list)
    wire_log: list = field(default_factory=list)


class Identity:
    """Long-term ML-DSA-65 identity key (pinned by the peer out of band)."""

    def __init__(self, name):
        self.name = name
        self.sk = mldsa.MLDSA65PrivateKey.generate()
        self.pk = self.sk.public_key()


# ---------------------------------------------------------------------------
#  v1+ encrypted channel
# ---------------------------------------------------------------------------

MAX_SKIP = 64   # how far ahead a ratcheted receiver will step past lost messages


class _Receiver:
    def __init__(self, cfg: ChannelConfig, key: bytes, sid: str, peer_pk):
        self.cfg, self.sid, self.peer_pk = cfg, sid, peer_pk
        self.chain = key
        self.key = key
        self.seen: set = set()
        self.next_seq = 1
        self.skipped: dict[int, bytes] = {}   # message keys for gaps, deleted on use

    def _ratchet_key(self, seq: int):
        """Message key for seq plus the state to commit if it decrypts.
        Nothing changes until the caller commits, so a bad packet leaves no trace."""
        if seq < self.next_seq:
            if seq not in self.skipped:
                raise ValueError("replay")
            return self.skipped[seq], None
        if seq - self.next_seq > MAX_SKIP:
            raise ValueError("too far ahead")
        chain, skipped = self.chain, {}
        for i in range(self.next_seq, seq):
            skipped[i] = _hkdf(chain, b"", b"qsc msg key")
            chain = _hkdf(chain, b"", b"qsc chain")
        mk = _hkdf(chain, b"", b"qsc msg key")
        return mk, (_hkdf(chain, b"", b"qsc chain"), skipped)

    def handle(self, env: Envelope, report: SessionReport) -> None:
        try:
            p = env.payload
            hdr = p["hdr"]
            if hdr.get("sid") != self.sid or hdr.get("v") != self.cfg.name:
                raise ValueError("wrong session")
            seq = int(hdr["seq"])
            if seq < 1:
                raise ValueError("bad sequence")
            if self.cfg.replay_protection and seq in self.seen:
                raise ValueError("replay")
            if not self.cfg.ratchet and self.cfg.replay_protection and seq < self.next_seq:
                raise ValueError("replay")
            if self.cfg.sign_messages:
                try:
                    self.peer_pk.verify(bytes.fromhex(p["sig"]), canon({"hdr": hdr, "ct": p["ct"]}))
                except Exception:
                    raise ValueError("bad signature")
            commit = None
            if self.cfg.ratchet:
                mk, commit = self._ratchet_key(seq)
            else:
                mk = self.key
            try:
                pt = AESGCM(mk).decrypt(seq.to_bytes(12, "big"), bytes.fromhex(p["ct"]), canon(hdr))
            except Exception:
                raise ValueError("decryption failed")
            if self.cfg.pad_to:
                n = int.from_bytes(pt[:4], "big")
                if n > len(pt) - 4 or len(pt) % self.cfg.pad_to:
                    raise ValueError("bad padding")
                pt = pt[4:4 + n]
            text = pt.decode("utf-8")
            # all checks passed: commit state
            if self.cfg.ratchet:
                if commit is None:
                    del self.skipped[seq]
                else:
                    self.chain, gaps = commit
                    self.skipped.update(gaps)
            self.seen.add(seq)
            self.next_seq = max(self.next_seq, seq + 1)
            report.accepted.append(text)
        except Exception as e:
            report.rejected += 1
            reason = str(e) if isinstance(e, ValueError) else "malformed packet"
            report.rejections[reason] = report.rejections.get(reason, 0) + 1


class _Sender:
    def __init__(self, cfg: ChannelConfig, key: bytes, sid: str, sk):
        self.cfg, self.sid, self.sk = cfg, sid, sk
        self.chain = key
        self.key = key
        self.seq = 0

    def seal(self, message: str) -> dict:
        self.seq += 1
        pt = message.encode("utf-8")
        if self.cfg.pad_to:
            body = len(pt).to_bytes(4, "big") + pt
            body += b"\x00" * ((-len(body)) % self.cfg.pad_to)
            pt = body
        hdr = {"sid": self.sid, "seq": self.seq, "v": self.cfg.name}
        if self.cfg.ratchet:
            mk = _hkdf(self.chain, b"", b"qsc msg key")
            self.chain = _hkdf(self.chain, b"", b"qsc chain")
        else:
            mk = self.key
        ct = AESGCM(mk).encrypt(self.seq.to_bytes(12, "big"), pt, canon(hdr))
        out = {"hdr": hdr, "ct": ct.hex()}
        if self.cfg.sign_messages:
            out["sig"] = self.sk.sign(canon(out)).hex()
        return out


def _handshake(cfg: ChannelConfig, wire: Wire, alice: Identity, bob: Identity,
               report: SessionReport):
    sid = str(uuid.uuid4())
    hello = wire.send(Envelope("Alice", "Bob", "hello", {"sid": sid, "v": cfg.name}))
    if hello is None:
        raise ProtocolAbort("hello dropped", "hello")
    sid = hello.payload["sid"]  # Bob learns sid from the wire
    heard_v = hello.payload.get("v")
    if heard_v != cfg.name:  # Bob speaks exactly one version: no negotiation, no downgrade
        raise ProtocolAbort("unsupported version in hello", "hello")
    auth = cfg.identity_auth
    a_end = Endpoint("Alice", alice.sk, bob.pk, auth)
    b_end = Endpoint("Bob", bob.sk, alice.pk, auth)
    link = ClassicalLink(wire, a_end, b_end, sid)

    secrets_a, secrets_b, transcript = [], [], []
    # Bob contributes fresh randomness; the signed reply also echoes the version,
    # so a changed hello is caught before any key material is exchanged.
    nonce_b = os.urandom(16).hex()
    got = link.send("Bob", "Alice", "hello_ack", {"nonce": nonce_b, "v": heard_v, "sid": sid})
    if got.get("v") != cfg.name or got.get("sid") != sid:
        raise ProtocolAbort("version or session mismatch", "hello")
    transcript += [got["nonce"], cfg.name,
                   hashlib.sha3_256(_raw_pub(alice.pk)).hexdigest(),
                   hashlib.sha3_256(_raw_pub(bob.pk)).hexdigest()]

    if cfg.qkd is not None:
        qcfg = replace(cfg.qkd, authenticate=cfg.qkd.authenticate or auth)
        try:
            res = run_bb84(link, wire, qcfg)
            secrets_a.append(res.key); secrets_b.append(res.key)
            report.key_sources.append("qkd")
            report.qkd_stats = res.stats
        except ProtocolAbort as e:
            report.qkd_stats = {**e.stats, "abort": e.reason, "stage": e.stage}
            if cfg.fallback == "x25519":
                cfg = replace(cfg, kem=tuple(set(cfg.kem) | {"x25519"}))
            elif not cfg.kem:
                raise

    if "mlkem768" in cfg.kem:
        dk = mlkem.MLKEM768PrivateKey.generate()
        ek_hex = _raw_pub(dk.public_key()).hex()
        got = link.send("Bob", "Alice", "kem_ek", {"ek": ek_hex})
        ek = mlkem.MLKEM768PublicKey.from_public_bytes(bytes.fromhex(got["ek"]))
        ss_a, ct = ek.encapsulate()
        got = link.send("Alice", "Bob", "kem_ct", {"ct": ct.hex()})
        ss_b = dk.decapsulate(bytes.fromhex(got["ct"]))
        secrets_a.append(ss_a); secrets_b.append(ss_b)
        transcript += [ek_hex, ct.hex()]
        report.key_sources.append("mlkem768")

    if "x25519" in cfg.kem:
        a_x = x25519.X25519PrivateKey.generate(); b_x = x25519.X25519PrivateKey.generate()
        a_pub, b_pub = _raw_pub(a_x.public_key()).hex(), _raw_pub(b_x.public_key()).hex()
        ShorOracle.register(a_pub, a_x); ShorOracle.register(b_pub, b_x)
        got_b = link.send("Alice", "Bob", "x25519", {"pub": a_pub})
        got_a = link.send("Bob", "Alice", "x25519", {"pub": b_pub})
        secrets_a.append(a_x.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(got_a["pub"]))))
        secrets_b.append(b_x.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(got_b["pub"]))))
        transcript += [a_pub, b_pub]
        report.key_sources.append("x25519")

    if len(secrets_a) < cfg.min_secrets:
        raise ProtocolAbort("not enough independent key sources", "handshake")

    salt = hashlib.sha3_256(canon([sid] + transcript)).digest()
    info = canon(["qsc", cfg.name, report.key_sources])
    ka = _hkdf(b"".join(secrets_a), salt, info)
    kb = _hkdf(b"".join(secrets_b), salt, info)

    if cfg.key_confirmation:
        # Separate confirmation keys: the traffic key itself is never used as a MAC key.
        ca, cb = _hkdf(ka, salt, b"qsc confirm"), _hkdf(kb, salt, b"qsc confirm")
        ta = hmac.new(ca, b"confirm-A" + salt, hashlib.sha3_256).hexdigest()
        got = link.send("Alice", "Bob", "confirm", {"tag": ta})
        if not hmac.compare_digest(got["tag"], hmac.new(cb, b"confirm-A" + salt, hashlib.sha3_256).hexdigest()):
            raise ProtocolAbort("key confirmation failed", "confirm")
        tb = hmac.new(cb, b"confirm-B" + salt, hashlib.sha3_256).hexdigest()
        got = link.send("Bob", "Alice", "confirm", {"tag": tb})
        if not hmac.compare_digest(got["tag"], hmac.new(ca, b"confirm-B" + salt, hashlib.sha3_256).hexdigest()):
            raise ProtocolAbort("key confirmation failed", "confirm")
        ka, kb = _hkdf(ka, salt, b"qsc traffic"), _hkdf(kb, salt, b"qsc traffic")
    return sid, ka, kb


def _run_encrypted(cfg: ChannelConfig, messages: list[str], wire: Wire, report: SessionReport):
    alice, bob = Identity("Alice"), Identity("Bob")
    try:
        sid, ka, kb = _handshake(cfg, wire, alice, bob, report)
    except ProtocolAbort as e:
        report.aborted, report.abort_reason, report.abort_stage = True, e.reason, e.stage
        return
    tx = _Sender(cfg, ka, sid, alice.sk)
    rx = _Receiver(cfg, kb, sid, alice.pk)
    for m in messages:
        report.sent.append(m)
        env = wire.send(Envelope("Alice", "Bob", "data", tx.seal(m)))
        if env is not None:
            rx.handle(env, report)
    for env in wire.adversary.forge() or []:
        wire.log.append({"src": "Eve", "dst": "Bob", "kind": "injected", "payload": env.payload})
        rx.handle(env, report)


# ---------------------------------------------------------------------------
#  v0 legacy adapter
# ---------------------------------------------------------------------------

def _packet_to_wire(pkt) -> dict:
    sig = pkt.qds_signature
    return {
        "session_id": pkt.session_id, "sequence_number": pkt.sequence_number,
        "message": pkt.message, "message_hash": pkt.message_hash,
        "ml_dsa_signature": pkt.ml_dsa_signature,
        "qds": {"revealed_keys": [k.hex() for k in sig.revealed_keys],
                "message_bits": sig.message_bits, "n_positions": sig.n_positions,
                "fingerprint_qubits": sig.fingerprint_qubits,
                "private_key_bits": sig.private_key_bits},
    }


def _wire_to_packet(d: dict):
    from src.packet import SecurePacket
    from src.qds_signer import GCSignature
    q = d.get("qds") or {}
    sig = GCSignature(
        message=str(d["message"]).encode("utf-8"),
        message_bits=list(q.get("message_bits", [])),
        n_positions=int(q.get("n_positions", 32)),
        revealed_keys=[bytes.fromhex(k) for k in q.get("revealed_keys", [])],
        fingerprint_qubits=int(q.get("fingerprint_qubits", 8)),
        private_key_bits=int(q.get("private_key_bits", 128)),
        session_id=d["session_id"], sequence_number=int(d["sequence_number"]),
    )
    return SecurePacket(session_id=d["session_id"], sequence_number=int(d["sequence_number"]),
                        message=d["message"], message_hash=d["message_hash"],
                        qds_signature=sig, ml_dsa_signature=d.get("ml_dsa_signature"))


def _run_legacy(messages: list[str], wire: Wire, report: SessionReport):
    from src.alice import Alice
    from src.bob import Bob
    from src.classical_channel import ClassicalChannelAuth
    from src.crypto import generate_challenge
    from src.e91_monitor import E91Monitor
    from src.gc_keys import GCKeyGenerator
    from src.session import SessionManager

    pub, priv = ClassicalChannelAuth.generate_keys()
    sm_a = SessionManager(); sm_a.start_session(generate_challenge())
    s = sm_a.current_session
    tag = ClassicalChannelAuth.sign_session_metadata(s.session_id, s.challenge, priv)
    env = wire.send(Envelope("Alice", "Bob", "session", {"session_id": s.session_id,
                                                          "challenge": s.challenge, "tag": tag}))
    if env is None or not ClassicalChannelAuth.verify_session_metadata(
            env.payload["session_id"], env.payload["challenge"], env.payload["tag"], pub):
        report.aborted, report.abort_reason = True, "session negotiation failed"
        return
    sm_b = SessionManager(); sm_b.start_session(env.payload["challenge"])
    sm_b.current_session.session_id = env.payload["session_id"]

    alice = Alice(sm_a, classical_priv_key=priv, classical_pub_key=pub,
                  key_pair=GCKeyGenerator.generate())
    bob = Bob(sm_b, e91_monitor=E91Monitor(num_pairs=32), trusted_classical_pub_key=pub)
    report.key_sources.append("none (plaintext)")

    def deliver(payload):
        pkt = _wire_to_packet(payload)
        res = bob.verify_packet(pkt)
        if res.threat_score.is_accepted:
            report.accepted.append(pkt.message)
        else:
            report.rejected += 1

    for m in messages:
        report.sent.append(m)
        alice.key_pair = GCKeyGenerator.generate()       # one-time GC keys per message
        bob.receive_public_keys(alice.distribute_public_keys(["Bob"], teleport=False)["Bob"])
        env = wire.send(Envelope("Alice", "Bob", "data", _packet_to_wire(alice.create_packet(m))))
        if env is not None:
            try:
                deliver(env.payload)
            except Exception:
                report.rejected += 1
    for env in wire.adversary.forge() or []:
        wire.log.append({"src": "Eve", "dst": "Bob", "kind": "injected", "payload": env.payload})
        try:
            deliver(env.payload)
        except Exception:
            report.rejected += 1


# ---------------------------------------------------------------------------
#  Version registry
# ---------------------------------------------------------------------------

VERSIONS: dict[str, ChannelConfig | None] = {
    "v0": None,
    "v1": ChannelConfig(
        name="v1",
        qkd=QKDConfig(rng="mt", authenticate=False, privacy_amplification="none"),
        fallback="x25519",
        description="First draft: BB84 key (Python RNG, unauthenticated classical channel, "
                    "no privacy amplification) -> AES-256-GCM; falls back to X25519 if QKD aborts.",
    ),
    "v2": ChannelConfig(
        name="v2",
        qkd=QKDConfig(n_pulses=250000, rng="system", authenticate=True, decoy=True,
                      privacy_amplification="decoy", finite_size=True),
        kem=("mlkem768", "x25519"),
        fallback="none",
        identity_auth=True,
        key_confirmation=True,
        replay_protection=True,
        pad_to=64,
        ratchet=True,
        sign_messages=True,
        min_secrets=2,
        description="Hardened: every handshake message ML-DSA-signed with pinned keys; decoy-state "
                    "BB84 with finite-size privacy amplification; ML-KEM-768 + X25519 + QKD combined "
                    "by HKDF-SHA3; no classical-only fallback; key confirmation; per-message ratchet; "
                    "replay rejection; length padding; ML-DSA on every data packet.",
    ),
    # v3 is a different architecture (src/qsc/v3.py); this entry only names it.
    "v3": ChannelConfig(name="v3", description="Two independent parties; transcript-hashed hybrid "
                        "handshake signed once per side; BB84 mixed in under a QKD policy with "
                        "MAC-authenticated post-processing; per-direction keys, IVs and ratchets."),
}


def run_session(version: str, messages: list[str], adversary: Adversary | None = None,
                crqc: bool = False, replies: list[str] | None = None, v3_policy=None) -> SessionReport:
    adversary = adversary or PassiveTap()
    adversary.setup(AttackContext(version=version, shor=ShorOracle(crqc)))
    wire = Wire(adversary)
    report = SessionReport(version=version)
    if version == "v3":
        from src.qsc.v3 import run_v3
        run_v3(messages, wire, report, policy=v3_policy, replies=replies)
    elif VERSIONS[version] is None:
        _run_legacy(messages, wire, report)
    else:
        _run_encrypted(VERSIONS[version], messages, wire, report)
    report.wire_log = wire.log
    return report

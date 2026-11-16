"""
QSC v3: two independent parties, a transcript-hashed hybrid handshake, and a
per-direction record layer.

Design (after TLS 1.3 / hybrid post-quantum handshakes):

  A -> B  hello     version, nonce_a, X25519 share, ML-KEM-768 encapsulation key
  B -> A  reply     nonce_b, X25519 share, ML-KEM ciphertext,
                    ML-DSA signature over the transcript hash, Finished MAC
  A -> B  finish    ML-DSA signature over the transcript hash, Finished MAC

  Then, by policy, BB84 runs with its classical messages authenticated by
  per-direction MAC keys from the handshake, and its key is mixed into the
  master secret (HKDF-Extract). Policy "required" aborts without it,
  "preferred" continues post-quantum only and reports it, "off" skips it.

  Traffic keys and IVs are separate for each direction; every record has its
  own nonce (IV xor sequence number), a ratchet with a bounded skip window,
  padding, and a replay check.

Alice and Bob are separate objects. The only thing that crosses between them
is the JSON payload on the Wire, so each side checks everything it receives
against its own state.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field, replace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from src.qsc.bb84 import ClassicalLink, Endpoint, ProtocolAbort, QKDConfig, canon, run_bb84
from src.qsc.wire import Envelope, ShorOracle, Wire

VERSION = "v3"
MAX_SKIP = 64
PAD = 64


def _raw(k) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _extract(salt: bytes, ikm: bytes) -> bytes:
    # HKDF-Extract = HMAC(salt, ikm)
    return hmac.new(salt or bytes(32), ikm, hashlib.sha3_256).digest()


def _expand(prk: bytes, label: str, context: bytes, n: int = 32) -> bytes:
    info = canon(["qsc/v3", label]) + context
    return HKDFExpand(algorithm=hashes.SHA3_256(), length=n, info=info).derive(prk)


@dataclass
class Policy:
    qkd: str = "preferred"          # "required" | "preferred" | "off"
    qkd_config: QKDConfig = field(default_factory=lambda: QKDConfig(
        n_pulses=250000, rng="system", decoy=True, privacy_amplification="decoy", finite_size=True))


class Transcript:
    def __init__(self):
        self.h = hashlib.sha3_256()

    def add(self, kind: str, payload: dict) -> None:
        self.h.update(canon([kind, payload]))

    def digest(self) -> bytes:
        return self.h.copy().digest()


class Party:
    """One side of the conversation. Holds only its own secrets."""

    def __init__(self, role: str, identity_sk, peer_pk):
        if role not in ("A", "B"):
            raise ValueError("role must be A or B")
        self.role, self.sk, self.peer_pk = role, identity_sk, peer_pk
        # identity fingerprints go into the signed transcript
        self.my_id = hashlib.sha3_256(_raw(identity_sk.public_key())).hexdigest()[:32]
        self.peer_id = hashlib.sha3_256(_raw(peer_pk)).hexdigest()[:32]
        self.t = Transcript()
        self.master = None
        self.state = "start"
        self.qkd_used = False

    # ---- handshake -------------------------------------------------------
    def hello(self) -> dict:
        if not (self.role == "A" and self.state == "start"):
            raise ProtocolAbort("message out of order", "handshake")
        self.nonce = os.urandom(16).hex()
        self.x = x25519.X25519PrivateKey.generate()
        self.dk = mlkem.MLKEM768PrivateKey.generate()
        xp = _raw(self.x.public_key()).hex()
        ShorOracle.register(xp, self.x)
        msg = {"v": VERSION, "nonce": self.nonce, "x25519": xp, "ek": _raw(self.dk.public_key()).hex(),
               "id": self.my_id, "peer": self.peer_id}
        self.t.add("hello", msg); self.state = "sent_hello"
        return msg

    def on_hello(self, msg: dict) -> dict:
        if not (self.role == "B" and self.state == "start"):
            raise ProtocolAbort("message out of order", "handshake")
        if msg.get("v") != VERSION:
            raise ProtocolAbort("unsupported version", "hello")
        if msg.get("id") != self.peer_id or msg.get("peer") != self.my_id:
            raise ProtocolAbort("hello names the wrong parties", "hello")
        self.t.add("hello", msg)
        self.nonce_a = msg["nonce"]
        x = x25519.X25519PrivateKey.generate()
        xp = _raw(x.public_key()).hex()
        ShorOracle.register(xp, x)
        ss_x = x.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(msg["x25519"])))
        ss_k, ct = mlkem.MLKEM768PublicKey.from_public_bytes(bytes.fromhex(msg["ek"])).encapsulate()
        self.nonce = os.urandom(16).hex()
        core = {"nonce": self.nonce, "x25519": xp, "ct": ct.hex(), "id": self.my_id}
        self.t.add("reply-core", core)
        self._derive_handshake(ss_k + ss_x)
        th = self.t.digest()
        sig = self.sk.sign(canon(["B signs", th.hex()])).hex()
        fin = hmac.new(self.fin_b, th, hashlib.sha3_256).hexdigest()
        self.t.add("reply-auth", {"sig": sig, "fin": fin})
        self.state = "sent_reply"
        return {**core, "sig": sig, "fin": fin}

    def on_reply(self, msg: dict) -> dict:
        if not (self.role == "A" and self.state == "sent_hello"):
            raise ProtocolAbort("message out of order", "handshake")
        core = {k: msg[k] for k in ("nonce", "x25519", "ct", "id")}
        if core["id"] != self.peer_id:
            raise ProtocolAbort("reply from the wrong party", "reply")
        self.t.add("reply-core", core)
        ss_x = self.x.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(msg["x25519"])))
        ss_k = self.dk.decapsulate(bytes.fromhex(msg["ct"]))
        self.nonce_b = msg["nonce"]
        self._derive_handshake(ss_k + ss_x)
        th = self.t.digest()
        try:
            self.peer_pk.verify(bytes.fromhex(msg["sig"]), canon(["B signs", th.hex()]))
        except Exception:
            raise ProtocolAbort("Bob's signature did not verify", "reply")
        if not hmac.compare_digest(msg["fin"], hmac.new(self.fin_b, th, hashlib.sha3_256).hexdigest()):
            raise ProtocolAbort("Bob's Finished did not verify", "reply")
        self.t.add("reply-auth", {"sig": msg["sig"], "fin": msg["fin"]})
        th2 = self.t.digest()
        sig = self.sk.sign(canon(["A signs", th2.hex()])).hex()
        fin = hmac.new(self.fin_a, th2, hashlib.sha3_256).hexdigest()
        self.t.add("finish", {"sig": sig, "fin": fin})
        self._derive_master(); self.state = "established"
        return {"sig": sig, "fin": fin}

    def on_finish(self, msg: dict) -> None:
        if not (self.role == "B" and self.state == "sent_reply"):
            raise ProtocolAbort("message out of order", "handshake")
        th2 = self.t.digest()
        try:
            self.peer_pk.verify(bytes.fromhex(msg["sig"]), canon(["A signs", th2.hex()]))
        except Exception:
            raise ProtocolAbort("Alice's signature did not verify", "finish")
        if not hmac.compare_digest(msg["fin"], hmac.new(self.fin_a, th2, hashlib.sha3_256).hexdigest()):
            raise ProtocolAbort("Alice's Finished did not verify", "finish")
        self.t.add("finish", {"sig": msg["sig"], "fin": msg["fin"]})
        self._derive_master(); self.state = "established"

    def _derive_handshake(self, shared: bytes) -> None:
        self.hs = _extract(b"", shared)
        th = self.t.digest()
        self.fin_a = _expand(self.hs, "finished A", th)
        self.fin_b = _expand(self.hs, "finished B", th)

    def _derive_master(self) -> None:
        self.master = _extract(_expand(self.hs, "derived", b""), self.t.digest())
        self.sid = self.t.digest().hex()[:32]   # both sides compute it; nobody chooses it

    def qkd_mac_keys(self):
        th = self.t.digest()
        a2b, b2a = _expand(self.master, "qkd mac A>B", th), _expand(self.master, "qkd mac B>A", th)
        return (a2b, b2a) if self.role == "A" else (b2a, a2b)   # (send, recv)

    def mix_qkd(self, key: bytes | None) -> None:
        if key is not None:
            self.master = _extract(self.master, key); self.qkd_used = True
        th = self.t.digest() + (b"qkd" if self.qkd_used else b"pq-only")
        mine, theirs = ("A>B", "B>A") if self.role == "A" else ("B>A", "A>B")
        self.send_dir, self.recv_dir = mine, theirs
        self.tx = _Direction(_expand(self.master, "traffic " + mine, th), _expand(self.master, "iv " + mine, th, 12))
        self.rx = _Direction(_expand(self.master, "traffic " + theirs, th), _expand(self.master, "iv " + theirs, th, 12))
        self.master = None   # nothing long-lived left to steal once traffic keys exist

    # ---- records -----------------------------------------------------------
    def seal(self, text: str) -> dict:
        seq, mk = self.tx.next_send()
        pt = text.encode("utf-8")
        body = len(pt).to_bytes(4, "big") + pt
        body += b"\x00" * ((-len(body)) % PAD)
        hdr = {"v": VERSION, "sid": self.sid, "dir": self.send_dir, "seq": seq}
        ct = AESGCM(mk).encrypt(self.tx.nonce(seq), body, canon(hdr))
        return {"hdr": hdr, "ct": ct.hex()}

    def open(self, rec: dict) -> str:
        hdr = rec["hdr"]
        if hdr.get("v") != VERSION or hdr.get("sid") != self.sid or hdr.get("dir") != self.recv_dir:
            raise ValueError("wrong session or direction")
        seq = int(hdr["seq"])
        mk, commit = self.rx.key_for(seq)
        try:
            body = AESGCM(mk).decrypt(self.rx.nonce(seq), bytes.fromhex(rec["ct"]), canon(hdr))
        except Exception:
            raise ValueError("decryption failed")
        n = int.from_bytes(body[:4], "big")
        if n > len(body) - 4 or len(body) % PAD:
            raise ValueError("bad padding")
        text = body[4:4 + n].decode("utf-8")
        self.rx.commit(seq, commit)
        return text


class _Direction:
    """Keys for one direction: ratchet with a bounded skip window."""

    def __init__(self, chain: bytes, iv: bytes):
        self.chain, self.iv, self.next = chain, iv, 1
        self.skipped: dict[int, bytes] = {}

    def nonce(self, seq: int) -> bytes:
        return bytes(a ^ b for a, b in zip(self.iv, seq.to_bytes(12, "big")))

    @staticmethod
    def _step(chain: bytes):
        return _expand(chain, "msg", b""), _expand(chain, "chain", b"")

    def next_send(self):
        mk, self.chain = self._step(self.chain)
        seq = self.next; self.next += 1
        return seq, mk

    def key_for(self, seq: int):
        if seq < 1:
            raise ValueError("bad sequence")
        if seq < self.next:
            if seq not in self.skipped:
                raise ValueError("replay")
            return self.skipped[seq], None
        if seq - self.next > MAX_SKIP:
            raise ValueError("too far ahead")
        chain, gaps = self.chain, {}
        for i in range(self.next, seq):
            gaps[i], chain = self._step(chain)
        mk, chain = self._step(chain)
        return mk, (chain, gaps)

    def commit(self, seq: int, commit) -> None:
        if commit is None:
            del self.skipped[seq]
        else:
            self.chain, gaps = commit
            self.skipped.update(gaps)
            self.next = seq + 1
            # bound memory: forget gap keys that fell far behind
            for old in [k for k in self.skipped if k < self.next - MAX_SKIP]:
                del self.skipped[old]


# ---------------------------------------------------------------------------
#  Driver: shuttles payloads over the Wire between the two independent parties
# ---------------------------------------------------------------------------

def _deliver(wire: Wire, src: str, dst: str, kind: str, payload: dict) -> dict:
    env = wire.send(Envelope(src, dst, kind, payload))
    if env is None:
        raise ProtocolAbort(f"{kind} dropped", kind)
    if env.kind != kind:
        raise ProtocolAbort(f"unexpected message, wanted {kind}", kind)
    return env.payload


def establish(wire: Wire, alice: "Party", bob: "Party", policy: Policy, report) -> None:
    m1 = _deliver(wire, "Alice", "Bob", "hello", alice.hello())
    m2 = _deliver(wire, "Bob", "Alice", "reply", bob.on_hello(m1))
    m3 = _deliver(wire, "Alice", "Bob", "finish", alice.on_reply(m2))
    bob.on_finish(m3)
    if alice.sid != bob.sid:
        raise ProtocolAbort("transcripts differ", "finish")
    report.key_sources += ["mlkem768", "x25519"]

    key_a = key_b = None
    if policy.qkd != "off":
        a_send, a_recv = alice.qkd_mac_keys()
        b_send, b_recv = bob.qkd_mac_keys()
        link = ClassicalLink(wire, Endpoint("Alice", mac_send=a_send, mac_recv=a_recv),
                             Endpoint("Bob", mac_send=b_send, mac_recv=b_recv), alice.sid)
        try:
            res = run_bb84(link, wire, replace(policy.qkd_config, authenticate=True))
            key_a = key_b = res.key
            report.key_sources.append("qkd"); report.qkd_stats = res.stats
        except ProtocolAbort as e:
            report.qkd_stats = {**e.stats, "abort": e.reason, "stage": e.stage}
            if policy.qkd == "required":
                raise ProtocolAbort(f"QKD required but failed: {e.reason}", "qkd")
    alice.mix_qkd(key_a); bob.mix_qkd(key_b)


def run_v3(messages: list[str], wire: Wire, report, policy: Policy | None = None,
           replies: list[str] | None = None) -> tuple:
    policy = policy or Policy()
    a_id, b_id = mldsa.MLDSA65PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
    alice = Party("A", a_id, b_id.public_key())
    bob = Party("B", b_id, a_id.public_key())
    try:
        establish(wire, alice, bob, policy, report)
    except ProtocolAbort as e:
        report.aborted, report.abort_reason, report.abort_stage = True, e.reason, e.stage
        return alice, bob
    except Exception as e:  # malformed handshake input
        report.aborted, report.abort_reason, report.abort_stage = True, f"malformed handshake: {type(e).__name__}", "handshake"
        return alice, bob

    def receive(party, env, accepted):
        try:
            accepted.append(party.open(env.payload))
        except Exception as e:
            report.rejected += 1
            reason = str(e) if isinstance(e, ValueError) else "malformed packet"
            report.rejections[reason] = report.rejections.get(reason, 0) + 1

    for m in messages:
        report.sent.append(m)
        env = wire.send(Envelope("Alice", "Bob", "data", alice.seal(m)))
        if env is not None:
            receive(bob, env, report.accepted)
    for r in replies or []:
        env = wire.send(Envelope("Bob", "Alice", "data", bob.seal(r)))
        if env is not None:
            receive(alice, env, report.replies_accepted)
    for env in wire.adversary.forge() or []:
        wire.log.append({"src": "Eve", "dst": env.dst, "kind": "injected", "payload": env.payload})
        receive(alice if env.dst == "Alice" else bob, env, report.replies_accepted if env.dst == "Alice" else report.accepted)
    return alice, bob

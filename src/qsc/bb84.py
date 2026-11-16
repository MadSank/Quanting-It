"""
BB84 quantum key distribution over a hostile network.

Stages (every classical message goes through the Wire, so Eve sees and may
tamper with all of it):

  1. Quantum transmission of weak coherent pulses (optionally decoy states)
  2. Detection report + basis sifting
  3. Parameter estimation (QBER on a random sample; decoy-state bounds)
  4. Error correction (simplified Cascade, leakage counted)
  5. Verification hash
  6. Privacy amplification (Toeplitz universal hashing)

Feature flags in QKDConfig let the arena compare a naive first draft with
hardened variants.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import random
import secrets
from dataclasses import dataclass, field

import numpy as np

from src.qsc.physics import FibreModel, Pulse, Photon, bob_detect, poisson
from src.qsc.wire import Envelope, Wire


class ProtocolAbort(Exception):
    def __init__(self, reason: str, stage: str = "", stats: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.stage = stage
        self.stats = stats or {}


@dataclass
class QKDConfig:
    n_pulses: int = 40000
    mu: float = 0.5                     # signal mean photon number
    decoy: bool = False                 # decoy-state method (signal/weak/vacuum)
    nu: float = 0.1                     # weak decoy intensity
    p_signal: float = 0.7
    p_decoy: float = 0.2                # remainder = vacuum
    sample_fraction: float = 0.2
    qber_abort: float = 0.11
    rng: str = "system"                 # "mt" = Python random (first draft), "system" = CSPRNG
    authenticate: bool = False          # ML-DSA-sign every classical QKD message
    privacy_amplification: str = "none"  # "none" | "naive" | "decoy"
    finite_size: bool = False           # statistical fluctuation term on QBER
    eps: float = 1e-10
    min_key_bits: int = 256
    fibre: FibreModel = field(default_factory=FibreModel)


def h2(p: float) -> float:
    if p <= 0 or p >= 1:
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class Endpoint:
    """One party's view of the classical channel (signing/verifying)."""

    def __init__(self, name: str, sign_key=None, peer_pub=None, authenticate=False,
                 mac_send: bytes | None = None, mac_recv: bytes | None = None):
        self.name = name
        self.sign_key = sign_key
        self.peer_pub = peer_pub
        self.mac_send = mac_send      # per-direction MAC keys (v3): cheaper than a signature per message
        self.mac_recv = mac_recv
        self.authenticate = authenticate or mac_send is not None
        self.counter = 0


class ClassicalLink:
    def __init__(self, wire: Wire, a: Endpoint, b: Endpoint, sid: str):
        self.wire = wire
        self.ends = {a.name: a, b.name: b}
        self.sid = sid
        self.recv_counter = {a.name: 0, b.name: 0}

    def send(self, src: str, dst: str, kind: str, payload: dict) -> dict:
        ep = self.ends[src]
        body = dict(payload)
        if ep.authenticate:
            ep.counter += 1
            body["_ctr"] = ep.counter
            msg = canon({"sid": self.sid, "src": src, "dst": dst, "kind": kind, "body": body})
            if ep.mac_send is not None:
                body["_sig"] = hmac.new(ep.mac_send, msg, hashlib.sha3_256).hexdigest()
            else:
                body["_sig"] = ep.sign_key.sign(msg).hex()
        delivered = self.wire.send(Envelope(src, dst, kind, body))
        if delivered is None:
            raise ProtocolAbort(f"message {kind} dropped", kind)
        rcv = self.ends[dst]
        got = dict(delivered.payload)
        if rcv.authenticate:
            sig = got.pop("_sig", None)
            if (sig is None or delivered.kind != kind or delivered.src != src
                    or delivered.dst != dst):
                raise ProtocolAbort(f"unauthenticated {kind}", kind)
            msg = canon({"sid": self.sid, "src": src, "dst": dst, "kind": kind, "body": got})
            if rcv.mac_recv is not None:
                ok = hmac.compare_digest(str(sig), hmac.new(rcv.mac_recv, msg, hashlib.sha3_256).hexdigest())
            else:
                try:
                    rcv.peer_pub.verify(bytes.fromhex(sig), msg); ok = True
                except Exception:
                    ok = False
            if not ok:
                raise ProtocolAbort(f"bad signature on {kind}", kind)
            if got.get("_ctr", 0) <= self.recv_counter[dst]:
                raise ProtocolAbort(f"replayed {kind}", kind)
            self.recv_counter[dst] = got["_ctr"]
        return got


def _rng(cfg: QKDConfig):
    if cfg.rng == "mt":
        return random.Random()          # seeded from os.urandom but predictable from outputs
    return secrets.SystemRandom()


def toeplitz_hash(bits: np.ndarray, out_len: int, seed: bytes) -> np.ndarray:
    n = len(bits)
    need = n + out_len - 1
    stream = b""
    ctr = 0
    while len(stream) * 8 < need:
        stream += hashlib.sha256(seed + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    diag = np.unpackbits(np.frombuffer(stream, dtype=np.uint8))[:need].astype(np.int64)
    # T[i, j] = diag[i - j + n - 1]
    idx = (np.arange(out_len)[:, None] - np.arange(n)[None, :]) + n - 1
    T = diag[idx]
    return (T @ bits.astype(np.int64)) % 2


def bits_to_bytes(bits) -> bytes:
    arr = np.array(bits, dtype=np.uint8)
    pad = (-len(arr)) % 8
    arr = np.concatenate([arr, np.zeros(pad, dtype=np.uint8)])
    return np.packbits(arr).tobytes()


@dataclass
class QKDResult:
    key: bytes
    stats: dict


def run_bb84(link: ClassicalLink, wire: Wire, cfg: QKDConfig, A="Alice", B="Bob") -> QKDResult:
    ra, rb = _rng(cfg), _rng(cfg)
    stats: dict = {}

    # ---- 1. quantum transmission -------------------------------------------
    link.send(A, B, "qkd_start", {"n_pulses": cfg.n_pulses, "decoy": cfg.decoy})
    a_bits, a_bases, a_int = [], [], []
    pulses = []
    for slot in range(cfg.n_pulses):
        bit, basis = ra.getrandbits(1), ra.getrandbits(1)
        if cfg.decoy:
            u = ra.random()
            level = 0 if u < cfg.p_signal else (1 if u < cfg.p_signal + cfg.p_decoy else 2)
        else:
            level = 0
        mean = (cfg.mu, cfg.nu, 0.0)[level]
        n = poisson(mean, ra) if mean > 0 else 0
        a_bits.append(bit); a_bases.append(basis); a_int.append(level)
        pulses.append(Pulse.prepare(basis, bit, n, slot))

    if wire.has_quantum_hook():
        arrived = wire.adversary.on_quantum(pulses)
        if len(arrived) != len(pulses):
            raise ProtocolAbort("quantum channel desynchronised", "quantum")
    else:
        arrived = [cfg.fibre.propagate(p, rb) for p in pulses]

    det_slots, b_bases, b_bits = [], [], []
    for slot, p in enumerate(arrived):
        basis = rb.getrandbits(1)
        r = bob_detect(p, basis, cfg.fibre, rb)
        if r is not None:
            det_slots.append(slot); b_bases.append(basis); b_bits.append(r)
    stats["detections"] = len(det_slots)

    # ---- 2. sifting --------------------------------------------------------
    got = link.send(B, A, "qkd_detect", {"slots": det_slots, "bases": b_bases})
    slots_a, bases_from_b = got["slots"], got["bases"]
    if len(slots_a) != len(bases_from_b):
        raise ProtocolAbort("malformed detection report", "sift")
    sift_payload = {"bases": [a_bases[s] for s in slots_a if 0 <= s < cfg.n_pulses]}
    if cfg.decoy:
        sift_payload["intensity"] = [a_int[s] for s in slots_a if 0 <= s < cfg.n_pulses]
    got_b = link.send(A, B, "qkd_sift", sift_payload)

    # Alice's sifted positions (her view)
    a_keep = [i for i, s in enumerate(slots_a) if 0 <= s < cfg.n_pulses and a_bases[s] == bases_from_b[i]]
    # Bob's sifted positions (his view)
    b_keep = [i for i in range(len(det_slots)) if i < len(got_b["bases"]) and got_b["bases"][i] == b_bases[i]]
    a_sift = [(i, a_bits[slots_a[i]], a_int[slots_a[i]]) for i in a_keep]
    b_int = got_b.get("intensity", [0] * len(det_slots))
    b_sift = [(i, b_bits[i], b_int[i] if i < len(b_int) else 0) for i in b_keep]
    stats["sifted"] = len(a_sift)

    # ---- 3. parameter estimation ------------------------------------------
    # Decoy / vacuum bits are fully revealed; signal bits are sampled.
    a_sig = [(i, bit) for (i, bit, lv) in a_sift if lv == 0]
    n_sample = int(len(a_sig) * cfg.sample_fraction)
    sample_pos = sorted(ra.sample(range(len(a_sig)), n_sample)) if n_sample else []
    sample_idx = [a_sig[j][0] for j in sample_pos]
    got = link.send(A, B, "qkd_sample", {"idx": sample_idx})
    b_map = {i: bit for (i, bit, _) in b_sift}
    b_sample = [b_map.get(i, 0) for i in got["idx"]]
    reveal = {"bits": b_sample}
    if cfg.decoy:
        reveal["decoy_idx"] = [i for (i, _, lv) in b_sift if lv != 0]
        reveal["decoy_bits"] = [b_map[i] for i in reveal["decoy_idx"]]
    got = link.send(B, A, "qkd_reveal", reveal)
    a_map = {i: bit for (i, bit, _) in a_sift}
    errs = sum(1 for i, bb in zip(sample_idx, got["bits"]) if a_map.get(i) != bb)
    qber = errs / max(1, len(sample_idx))
    stats["qber"] = qber
    stats["sample"] = len(sample_idx)
    qber_u = qber
    if cfg.finite_size and sample_idx:
        qber_u = qber + math.sqrt(math.log(1 / cfg.eps) / (2 * len(sample_idx)))
    stats["qber_upper"] = qber_u

    single_photon_bits = None
    if cfg.decoy:
        single_photon_bits, e1 = _decoy_bounds(cfg, a_int, slots_a, bases_from_b, a_bases,
                                               a_map, got, stats)
    decision = "abort" if qber > cfg.qber_abort else "continue"
    if cfg.decoy and (single_photon_bits is None or single_photon_bits <= 0):
        decision = "abort"
    link.send(A, B, "qkd_decision", {"qber": qber, "decision": decision})
    if decision == "abort":
        raise ProtocolAbort(f"QBER {qber:.3f} / decoy check failed", "estimation", stats)

    sampled = set(sample_idx)
    a_key = [a_map[i] for (i, _, lv) in a_sift if lv == 0 and i not in sampled]
    b_key = [b_map[i] for (i, _, lv) in b_sift if lv == 0 and i not in sampled]
    if len(a_key) != len(b_key):
        raise ProtocolAbort("sifted key length mismatch (tampered sifting)", "sift")
    a_key, b_key = np.array(a_key, dtype=np.int64), np.array(b_key, dtype=np.int64)

    # ---- 4. error correction (Cascade with backtracking) --------------------
    leak = 0
    k = max(8, int(0.73 / max(qber, 0.01)))
    passes = []          # (blocks, alice_parities, index -> block id)
    for pass_no in range(4):
        perm_seed = ra.getrandbits(64)
        got = link.send(A, B, "ec_perm", {"pass": pass_no, "seed": perm_seed, "k": k})
        perm = list(range(len(a_key)))
        if pass_no:
            random.Random(got["seed"]).shuffle(perm)
        blocks = [perm[s:s + int(got["k"])] for s in range(0, len(perm), int(got["k"]))]
        a_par = [int(a_key[b].sum() % 2) for b in blocks]
        got = link.send(A, B, "ec_parity", {"parities": a_par})
        leak += len(blocks)
        par = list(got["parities"])[: len(blocks)] + [0] * max(0, len(blocks) - len(got["parities"]))
        where = {}
        for bi, b in enumerate(blocks):
            for j in b:
                where[j] = bi
        passes.append((blocks, par, where))
        todo = {(pass_no, bi): blocks[bi] for bi in range(len(blocks))
                if int(b_key[blocks[bi]].sum() % 2) != par[bi]}
        rounds = 0
        while todo and rounds < 200:
            rounds += 1
            items = list(todo.items())
            reqs = [idx[: len(idx) // 2] for _, idx in items]
            got_r = link.send(B, A, "ec_query", {"q": [[int(x) for x in h] for h in reqs]})
            ans = [int(a_key[np.array(h, dtype=np.int64)].sum() % 2) if h else 0 for h in got_r["q"]]
            got_a = link.send(A, B, "ec_answer", {"p": ans})
            leak += len(ans)
            nxt = {}
            touched = set()   # blocks whose parity changed during this round
            for ((key_, idx), half, pa) in zip(items, reqs, got_a["p"]):
                if key_ in touched:
                    # this round's answer for it predates a flip inside it: the
                    # restart decision was already made when the flip happened
                    continue
                left_bad = int(b_key[half].sum() % 2) != pa
                part = half if left_bad else idx[len(idx) // 2:]
                if len(part) > 1:
                    nxt[key_] = part
                    continue
                j = part[0]
                b_key[j] ^= 1
                # every block containing j changed parity: restart its search from
                # the whole block if it now mismatches, otherwise drop it
                for q, (qb, qpar, qwhere) in enumerate(passes):
                    bi = qwhere.get(j)
                    if bi is None or (q, bi) == key_:
                        continue
                    touched.add((q, bi))
                    if int(b_key[qb[bi]].sum() % 2) != qpar[bi]:
                        nxt[(q, bi)] = qb[bi]
                    else:
                        nxt.pop((q, bi), None)
            todo = nxt
        k *= 2
    stats["ec_leak"] = leak

    # ---- 5. verification ---------------------------------------------------
    # 64-bit tag: failure probability 2^-64, and exactly the 64 bits counted
    # as leaked below (a full 256-bit hash would leak more than is accounted).
    VERIFY_TAG_HEX = 16
    salt = secrets.token_hex(16)
    ha = hmac.new(bytes.fromhex(salt), bits_to_bytes(a_key), hashlib.sha256).hexdigest()[:VERIFY_TAG_HEX]
    got = link.send(A, B, "qkd_verify", {"salt": salt, "hash": ha})
    hb = hmac.new(bytes.fromhex(got["salt"]), bits_to_bytes(b_key), hashlib.sha256).hexdigest()[:VERIFY_TAG_HEX]
    ok = hmac.compare_digest(hb, got["hash"])
    link.send(B, A, "qkd_verify_ack", {"ok": ok})
    if not ok:
        raise ProtocolAbort("error correction failed", "verify")
    leak += 4 * VERIFY_TAG_HEX  # verification tag leakage, in bits

    # ---- 6. privacy amplification ------------------------------------------
    n = len(a_key)
    if cfg.privacy_amplification == "none":
        key = hashlib.sha256(bits_to_bytes(a_key)).digest()
        stats["final_bits"] = 256
        stats["secure_bits_estimate"] = None
        return QKDResult(key, stats)

    margin = 2 * math.log2(1 / cfg.eps)
    if cfg.privacy_amplification == "decoy" and single_photon_bits is not None:
        # GLLP: only single-photon contributions are secret.
        m = int(single_photon_bits * (1 - h2(e1)) - leak - margin)
    else:
        # Naive: assumes every detection came from a single photon.
        m = int(n * (1 - h2(qber_u)) - leak - margin)
    stats["final_bits"] = m
    if m < cfg.min_key_bits:
        link.send(A, B, "pa", {"abort": True})
        raise ProtocolAbort(f"insufficient secret key ({m} bits)", "pa", stats)
    seed = secrets.token_bytes(32)
    got = link.send(A, B, "pa", {"seed": seed.hex(), "m": m})
    ka = toeplitz_hash(a_key, m, seed)
    kb = toeplitz_hash(b_key, int(got["m"]), bytes.fromhex(got["seed"]))
    if not np.array_equal(ka, kb):
        raise ProtocolAbort("privacy amplification mismatch", "pa")
    return QKDResult(hashlib.sha3_256(bits_to_bytes(ka)).digest(), stats)


def _decoy_bounds(cfg, a_int, slots_a, bases_from_b, a_bases, a_map, reveal, stats):
    """Weak+vacuum decoy bounds (Lo-Ma-Chen 2005 / Ma et al. 2005)."""
    mu, nu = cfg.mu, cfg.nu
    sent = [0, 0, 0]
    for lv in a_int:
        sent[lv] += 1
    det = [0, 0, 0]
    for s in slots_a:
        if 0 <= s < cfg.n_pulses:
            det[a_int[s]] += 1
    Q = [det[i] / max(1, sent[i]) for i in range(3)]
    # Decoy-intensity sifted error rates from fully revealed bits
    errs = {1: [0, 0], 2: [0, 0]}
    rmap = dict(zip(reveal.get("decoy_idx", []), reveal.get("decoy_bits", [])))
    for i, s in enumerate(slots_a):
        if 0 <= s < cfg.n_pulses and a_int[s] != 0 and a_bases[s] == bases_from_b[i] and i in rmap:
            errs[a_int[s]][0] += int(a_map.get(i) != rmap[i])
            errs[a_int[s]][1] += 1
    Q_mu, Q_nu, Y0 = Q
    E_mu = stats["qber"]
    e0 = 0.5
    Y1_L = (mu / (mu * nu - nu * nu)) * (
        Q_nu * math.exp(nu) - Q_mu * math.exp(mu) * nu * nu / (mu * mu)
        - (mu * mu - nu * nu) / (mu * mu) * Y0)
    stats.update({"Q_mu": Q_mu, "Q_nu": Q_nu, "Y0": Y0, "Y1_L": Y1_L})
    if Y1_L <= 0:
        stats["single_photon_bits"] = 0
        return 0, 0.5
    Q1_L = Y1_L * mu * math.exp(-mu)
    e1_U = min(0.5, (E_mu * Q_mu * math.exp(mu) - e0 * Y0) / (Y1_L * mu))
    if cfg.finite_size:
        e1_U = min(0.5, e1_U + math.sqrt(math.log(1 / cfg.eps) / (2 * max(1, stats["sample"]))))
    frac1 = Q1_L / max(Q_mu, 1e-12)
    n_signal_sifted = sum(1 for i, s in enumerate(slots_a)
                          if 0 <= s < cfg.n_pulses and a_int[s] == 0 and a_bases[s] == bases_from_b[i])
    n_key = n_signal_sifted - stats["sample"]
    stats.update({"Q1_L": Q1_L, "e1_U": e1_U, "single_photon_fraction": frac1})
    stats["single_photon_bits"] = int(frac1 * n_key)
    return int(frac1 * n_key), e1_U

"""
Network model: classical wire, quantum fibre hook, adversary interface and a
simulated cryptographically-relevant quantum computer (CRQC) for
"harvest-now, decrypt-later" analysis.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Envelope:
    src: str
    dst: str
    kind: str
    payload: dict

    def to_json(self) -> dict:
        return {"src": self.src, "dst": self.dst, "kind": self.kind, "payload": self.payload}


class Adversary:
    """Base class for Eve. Override any hook. Default = passive wiretap."""

    name = "passive"

    def setup(self, ctx: "AttackContext") -> None:
        self.ctx = ctx

    def on_quantum(self, pulses: list) -> list:
        """Receives Alice's pulses at her output port. Return the list of
        pulses (same length, None = blocked) that reach Bob's detector.
        If you return pulses you must also model loss yourself; the honest
        fibre loss is applied only when this hook is not overridden."""
        raise NotImplementedError

    def on_classical(self, env: Envelope):
        """Called for every classical message. Return the Envelope to
        deliver (possibly modified), or None to drop it."""
        return env

    def recover(self, wire_log: list[dict]) -> list[str]:
        """After the session (and optionally years later with a CRQC):
        return guesses for the plaintexts Alice sent."""
        return []

    def forge(self) -> list[Envelope]:
        """Optional: extra envelopes to inject to Bob after the session's
        honest traffic (e.g. replays, forgeries)."""
        return []


class PassiveTap(Adversary):
    pass


class ShorOracle:
    """Simulated CRQC. Breaks discrete-log / factoring based public keys
    (X25519, ECDSA, RSA) by looking up the private key that the simulator
    registered at key-generation time. It has NO power against lattice
    schemes (ML-KEM, ML-DSA), hash functions, or AES-256 beyond Grover's
    sqrt speed-up (still 2^128 for AES-256)."""

    _registry: dict[str, Any] = {}

    @classmethod
    def register(cls, public_hex: str, private_obj: Any) -> None:
        cls._registry[public_hex] = private_obj

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.queries = 0

    def break_x25519(self, public_hex: str):
        if not self.enabled:
            raise PermissionError("CRQC not available in this scenario")
        self.queries += 1
        return self._registry.get(public_hex)

    def break_mlkem(self, public_hex: str):
        raise NotImplementedError("No known quantum algorithm breaks ML-KEM (Module-LWE)")


@dataclass
class AttackContext:
    version: str
    shor: ShorOracle
    notes: dict = field(default_factory=dict)  # scratch space for the attacker


class Wire:
    """Classical channel. Every envelope is logged (Eve sees everything)
    and passed through the adversary hook."""

    def __init__(self, adversary: Adversary | None = None):
        self.adversary = adversary or PassiveTap()
        self.log: list[dict] = []

    def send(self, env: Envelope) -> Envelope | None:
        # Eve sees a deep copy so she cannot mutate party state by reference.
        self.log.append(json.loads(json.dumps(env.to_json())))
        delivered = self.adversary.on_classical(copy.deepcopy(env))
        return delivered

    def has_quantum_hook(self) -> bool:
        return type(self.adversary).on_quantum is not Adversary.on_quantum

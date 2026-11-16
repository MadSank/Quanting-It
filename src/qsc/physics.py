"""
Photon-level physics model for prepare-and-measure QKD (BB84 family).

This is a fast numpy/pure-python model, not a Qiskit circuit, because QKD
needs tens of thousands of pulses per session. Each pulse emitted by Alice
is a weak coherent pulse: its photon number follows Poisson(mu). Every photon
in a pulse carries the same (basis, bit) encoding.

The adversary (Eve) controls the fibre between Alice and Bob. She can:
  * count photons non-destructively (QND measurement)  -> Pulse.photon_count
  * split one photon off a multi-photon pulse          -> Pulse.split()
  * measure a photon in a basis of her choice          -> Photon.measure()
  * block a pulse, or forward a pulse over a lossless line
  * prepare and inject her own pulses                  -> Pulse.prepare()

She can NOT read a photon's encoding without measuring it. The private
attributes (_basis, _bit) are off-limits to attack code by the arena rules
(the judge greps attack sources for them).

Bases: 0 = Z (rectilinear), 1 = X (diagonal).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

_sysrand = secrets.SystemRandom()


class Photon:
    __slots__ = ("_basis", "_bit")

    def __init__(self, basis: int, bit: int):
        self._basis = basis
        self._bit = bit

    def measure(self, basis: int) -> int:
        """Projective measurement. Wrong basis -> uniformly random result,
        and the photon collapses into the measured basis/result."""
        if basis == self._basis:
            return self._bit
        result = _sysrand.getrandbits(1)
        self._basis, self._bit = basis, result
        return result


@dataclass
class Pulse:
    photons: list = field(default_factory=list)
    # Index of the pulse in Alice's emission sequence (public timing info).
    slot: int = 0

    @property
    def photon_count(self) -> int:
        """Non-demolition photon-number measurement (allowed for Eve)."""
        return len(self.photons)

    def split(self) -> "Photon | None":
        """Remove one photon from the pulse (photon-number-splitting)."""
        if not self.photons:
            return None
        return self.photons.pop()

    @staticmethod
    def prepare(basis: int, bit: int, n_photons: int = 1, slot: int = 0) -> "Pulse":
        return Pulse([Photon(basis, bit) for _ in range(n_photons)], slot)


def poisson(mu: float, rng) -> int:
    """Knuth Poisson sampler (mu is small, < 1)."""
    import math
    L = math.exp(-mu)
    k, p = 0, 1.0
    while True:
        p *= rng.random()
        if p <= L:
            return k
        k += 1


@dataclass
class FibreModel:
    """Honest channel + detector parameters."""
    transmittance: float = 0.20     # eta: fibre loss * detector efficiency (~35 km)
    misalignment: float = 0.015     # intrinsic bit-flip probability at Bob
    dark_count: float = 1e-5        # per-slot dark count probability

    def propagate(self, pulse: Pulse, rng) -> Pulse:
        survivors = [p for p in pulse.photons if rng.random() < self.transmittance]
        return Pulse(survivors, pulse.slot)


def bob_detect(pulse: Pulse | None, basis: int, fibre: FibreModel, rng):
    """Bob's threshold detector. Returns bit or None (no click).

    Multi-photon arrivals that disagree produce a double click which is
    squashed to a random bit (standard squashing model)."""
    results = []
    if pulse is not None:
        for ph in pulse.photons:
            r = ph.measure(basis)
            if rng.random() < fibre.misalignment:
                r ^= 1
            results.append(r)
    if not results:
        if rng.random() < fibre.dark_count:
            return rng.getrandbits(1)
        return None
    if all(r == results[0] for r in results):
        return results[0]
    return rng.getrandbits(1)

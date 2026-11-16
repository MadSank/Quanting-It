"""
CHSH Bell-Test Experiment Module for Quatinit.

Implements the Clauser-Horne-Shimony-Holt (CHSH) Bell inequality test
to verify quantum entanglement and demonstrate non-locality violation
or its degradation under noise and eavesdropping attacks.

Authoritative Sign Convention and Settings:
    S = E(a, b) - E(a, b') + E(a', b) + E(a', b')
    Initial Bell state: |Φ+⟩ = (|00⟩ + |11⟩) / √2
    Alice measurement angles: a = 0, a' = π/2
    Bob measurement angles:   b = π/4, b' = 3π/4
    Observable: M(θ) = cos(θ)Z + sin(θ)X

Basis rotation to standard computational basis:
    R_y(-θ) maps eigenstates of M(θ) to {|0⟩, |1⟩}.
    Eigenvalue of |0⟩ is +1; eigenvalue of |1⟩ is -1.

Ideal Theoretical Expectations:
    E(a, b)    = cos(0 - π/4)    = +1/√2 ≈ +0.7071
    E(a, b')   = cos(0 - 3π/4)   = -1/√2 ≈ -0.7071
    E(a', b)   = cos(π/2 - π/4)  = +1/√2 ≈ +0.7071
    E(a', b')  = cos(π/2 - 3π/4) = +1/√2 ≈ +0.7071
    S_ideal    = 1/√2 - (-1/√2) + 1/√2 + 1/√2 = 4/√2 = 2√2 ≈ 2.8284

Bounds:
    Classical local-hidden-variable bound: |S| <= 2.0
    Quantum Tsirelson bound:               |S| <= 2√2 ≈ 2.8284
"""

import math
import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, Tuple, List
import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error
from scipy.stats import norm

# Standard authoritative angles and bounds
ALICE_ANGLES = {
    "a": 0.0,
    "a_prime": math.pi / 2.0,
}

BOB_ANGLES = {
    "b": math.pi / 4.0,
    "b_prime": 3.0 * math.pi / 4.0,
}

CLASSICAL_BOUND = 2.0
TSIRELSON_BOUND = 2.0 * math.sqrt(2.0)  # ≈ 2.82842712474619


@dataclass
class CorrelationResult:
    """Measurement outcomes and correlation for a single (Alice, Bob) setting."""
    setting_name: str
    alice_setting: str
    bob_setting: str
    alice_angle: float
    bob_angle: float
    correlation: float
    uncertainty: float
    counts: Dict[str, int]
    shots: int
    n_same: int
    n_diff: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CHSHResult:
    """Full results of a 4-setting CHSH Bell test."""
    s_value: float
    uncertainty: float
    confidence_interval_95: Tuple[float, float]
    classical_bound: float = CLASSICAL_BOUND
    tsirelson_bound: float = TSIRELSON_BOUND
    violates_classical: bool = False
    sigma_violation: float = 0.0
    p_value_classical: float = 1.0
    correlations: Dict[str, CorrelationResult] = field(default_factory=dict)
    execution_mode: str = "IDEAL_SIMULATOR"
    backend_name: str = "aer_simulator"
    job_id: Optional[str] = None
    shots: int = 4096
    attack_type: str = "NONE"
    attack_params: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["correlations"] = {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in self.correlations.items()}
        return d


def theoretical_correlations(
    angles_a: Optional[Dict[str, float]] = None,
    angles_b: Optional[Dict[str, float]] = None,
) -> Dict[str, float]:
    """
    Computes ideal quantum correlation E(θA, θB) = cos(θA - θB)
    for state |Φ+⟩ and observable M(θ) = cos(θ)Z + sin(θ)X.
    """
    a_dict = angles_a or ALICE_ANGLES
    b_dict = angles_b or BOB_ANGLES

    return {
        "E(a,b)": math.cos(a_dict["a"] - b_dict["b"]),
        "E(a,b')": math.cos(a_dict["a"] - b_dict["b_prime"]),
        "E(a',b)": math.cos(a_dict["a_prime"] - b_dict["b"]),
        "E(a',b')": math.cos(a_dict["a_prime"] - b_dict["b_prime"]),
    }


def theoretical_s(
    angles_a: Optional[Dict[str, float]] = None,
    angles_b: Optional[Dict[str, float]] = None,
) -> float:
    """
    Computes theoretical CHSH S = E(a, b) - E(a, b') + E(a', b) + E(a', b').
    Under standard settings: S = 1/√2 - (-1/√2) + 1/√2 + 1/√2 = 2√2.
    """
    th = theoretical_correlations(angles_a, angles_b)
    return th["E(a,b)"] - th["E(a,b')"] + th["E(a',b)"] + th["E(a',b')"]


def build_chsh_circuit(
    alice_angle: float,
    bob_angle: float,
    attack_type: str = "NONE",
    attack_params: Optional[Dict[str, Any]] = None,
) -> QuantumCircuit:
    """
    Builds a 2-qubit circuit for one CHSH measurement setting.

    Circuit stages:
    1. Entanglement generation:
       |00⟩ -> H(0) -> CX(0, 1) produces |Φ+⟩ = (|00⟩ + |11⟩) / √2.
    2. Transmission channel / Attack:
       - NONE: Clean channel.
       - DEPOLARIZING_NOISE: Channel includes an identity gate on qubit 1
         targeted by a depolarizing noise model during execution.
       - INTERCEPT_RESEND: Eve intercepts qubit 1, measures in basis θ_E,
         collapsing entanglement, and resends prepared eigenstate R_y(θ_E)|m⟩.
    3. Basis rotations:
       Alice rotates qubit 0 by R_y(-alice_angle).
       Bob rotates qubit 1 by R_y(-bob_angle).
    4. Computational basis measurement:
       Qubit 0 measured into classical bit 0 (Alice).
       Qubit 1 measured into classical bit 1 (Bob).
    """
    params = attack_params or {}
    attack_upper = attack_type.upper()

    if attack_upper == "INTERCEPT_RESEND":
        # We need 2 qubits and 2 classical bits for final Alice/Bob measurement.
        # Eve performs mid-circuit projective measurement on qubit 1.
        qc = QuantumCircuit(2, 2)
        # 1. State preparation
        qc.h(0)
        qc.cx(0, 1)

        # 2. Eve intercept-resend attack on qubit 1
        eve_angle = float(params.get("eve_angle", 0.0))
        # Rotate to Eve's basis
        qc.ry(-eve_angle, 1)
        # Eve measures qubit 1 mid-circuit (projecting qubit 1 and collapsing entanglement)
        # We measure into classical bit 1 temporarily, but Bob will measure qubit 1 later.
        qc.measure(1, 1)
        # Resend: rotate back to state space so Bob receives eigenstate |m⟩ in Eve's basis
        qc.ry(eve_angle, 1)

        # 3. Alice and Bob measurement basis rotations
        qc.ry(-alice_angle, 0)
        qc.ry(-bob_angle, 1)

        # 4. Final measurements
        qc.measure(0, 0)  # Alice's measurement
        qc.measure(1, 1)  # Bob's measurement (overwrites bit 1 with Bob's result)
        return qc

    elif attack_upper == "DEPOLARIZING_NOISE":
        qc = QuantumCircuit(2, 2)
        qc.h(0)
        qc.cx(0, 1)
        # Transmitted qubit 1 passes through channel (represented by id gate)
        qc.id(1)
        # Basis rotations
        qc.ry(-alice_angle, 0)
        qc.ry(-bob_angle, 1)
        # Measurement
        qc.measure(0, 0)
        qc.measure(1, 1)
        return qc

    else:
        # Clean channel
        qc = QuantumCircuit(2, 2)
        qc.h(0)
        qc.cx(0, 1)
        qc.ry(-alice_angle, 0)
        qc.ry(-bob_angle, 1)
        qc.measure(0, 0)
        qc.measure(1, 1)
        return qc


def compute_correlation(counts: Dict[str, int]) -> Tuple[float, float, int, int, int]:
    """
    Computes expectation value E = (N_same - N_diff) / N_total
    and its standard error from empirical measurement counts.

    In Qiskit 2-qubit measurement bitstrings 'ba':
        b = qubit 1 (Bob, classical bit 1)
        a = qubit 0 (Alice, classical bit 0)
    Same outcome (both +1 or both -1): '00' or '11'
    Opposite outcome (+1,-1 or -1,+1): '01' or '10'

    Returns:
        (E, std_err, n_same, n_diff, n_total)
    """
    n_same = counts.get("00", 0) + counts.get("11", 0)
    n_diff = counts.get("01", 0) + counts.get("10", 0)
    n_total = n_same + n_diff

    if n_total == 0:
        return 0.0, 0.0, 0, 0, 0

    E = (n_same - n_diff) / float(n_total)

    # Binomial variance of p = N_same / N_total: Var(E) = (1 - E^2) / N_total
    variance = max(0.0, 1.0 - E * E) / float(n_total)
    std_err = math.sqrt(variance)

    return E, std_err, n_same, n_diff, n_total


def run_chsh_experiment(
    shots: int = 4096,
    attack_type: str = "NONE",
    attack_params: Optional[Dict[str, Any]] = None,
    backend_executor: Optional[Any] = None,
    seed_simulator: Optional[int] = None,
) -> CHSHResult:
    """
    Runs the complete 4-setting CHSH experiment.

    Settings executed:
        1. (a, b):       Alice=0,    Bob=π/4
        2. (a, b'):      Alice=0,    Bob=3π/4
        3. (a', b):      Alice=π/2,  Bob=π/4
        4. (a', b'):     Alice=π/2,  Bob=3π/4

    Calculates:
        S = E(a, b) - E(a, b') + E(a', b) + E(a', b')
        ΔS = √( (ΔE1)^2 + (ΔE2)^2 + (ΔE3)^2 + (ΔE4)^2 )
    """
    params = attack_params or {}
    attack_upper = attack_type.upper()

    settings_meta = [
        ("E(a,b)", "a", "b", ALICE_ANGLES["a"], BOB_ANGLES["b"]),
        ("E(a,b')", "a", "b_prime", ALICE_ANGLES["a"], BOB_ANGLES["b_prime"]),
        ("E(a',b)", "a_prime", "b", ALICE_ANGLES["a_prime"], BOB_ANGLES["b"]),
        ("E(a',b')", "a_prime", "b_prime", ALICE_ANGLES["a_prime"], BOB_ANGLES["b_prime"]),
    ]

    circuits = []
    for _, _, _, th_a, th_b in settings_meta:
        qc = build_chsh_circuit(
            alice_angle=th_a,
            bob_angle=th_b,
            attack_type=attack_upper,
            attack_params=params,
        )
        circuits.append(qc)

    # Execution handling
    counts_list: List[Dict[str, int]] = []
    backend_name = "aer_simulator"
    execution_mode = "IDEAL_SIMULATOR"
    job_id = None

    if backend_executor is not None:
        exec_res = backend_executor.execute(
            circuits=circuits,
            shots=shots,
            attack_type=attack_upper,
            attack_params=params,
        )
        counts_list = exec_res["counts"]
        backend_name = exec_res.get("backend_name", "custom_backend")
        execution_mode = exec_res.get("execution_mode", "CUSTOM")
        job_id = exec_res.get("job_id", None)
    else:
        # Local Aer execution
        if attack_upper == "DEPOLARIZING_NOISE":
            execution_mode = "NOISY_SIMULATOR"
            noise_strength = float(params.get("noise_strength", 0.1))
            safe_noise = max(0.0, min(0.75, noise_strength))
            noise_model = NoiseModel()
            if safe_noise > 0.0:
                err = depolarizing_error(safe_noise, 1)
                noise_model.add_all_qubit_quantum_error(err, ["id"])
            sim = AerSimulator(noise_model=noise_model)
        else:
            sim = AerSimulator()
            if attack_upper == "INTERCEPT_RESEND":
                execution_mode = "INTERCEPT_RESEND_SIMULATOR"

        for qc in circuits:
            job = sim.run(qc, shots=shots, seed_simulator=seed_simulator)
            res = job.result()
            counts_list.append(res.get_counts())

    # Process correlation results
    corr_dict: Dict[str, CorrelationResult] = {}
    corrs: List[float] = []
    errs: List[float] = []

    for idx, (name, a_set, b_set, th_a, th_b) in enumerate(settings_meta):
        counts = counts_list[idx]
        E, std_err, n_same, n_diff, n_total = compute_correlation(counts)
        corr_res = CorrelationResult(
            setting_name=name,
            alice_setting=a_set,
            bob_setting=b_set,
            alice_angle=th_a,
            bob_angle=th_b,
            correlation=E,
            uncertainty=std_err,
            counts=counts,
            shots=n_total,
            n_same=n_same,
            n_diff=n_diff,
        )
        corr_dict[name] = corr_res
        corrs.append(E)
        errs.append(std_err)

    # S = E(a,b) - E(a,b') + E(a',b) + E(a',b')
    e_ab, e_abp, e_apb, e_apbp = corrs[0], corrs[1], corrs[2], corrs[3]
    s_val = e_ab - e_abp + e_apb + e_apbp

    # Uncertainty propagation: ΔS = √( ∑ (ΔE_i)^2 )
    s_unc = math.sqrt(sum(e * e for e in errs))

    # 95% Confidence Interval (z ≈ 1.95996)
    z_95 = 1.959963984540054
    ci_low = s_val - z_95 * s_unc
    ci_high = s_val + z_95 * s_unc

    # Classical violation test
    # Null hypothesis: S <= 2.0
    sigma_violation = (s_val - CLASSICAL_BOUND) / s_unc if s_unc > 1e-12 else 0.0
    p_value = float(norm.sf(sigma_violation)) if s_unc > 1e-12 else (0.0 if s_val > CLASSICAL_BOUND else 1.0)
    violates = bool(s_val > CLASSICAL_BOUND and (s_val - 2.0 * s_unc) > CLASSICAL_BOUND)

    return CHSHResult(
        s_value=s_val,
        uncertainty=s_unc,
        confidence_interval_95=(ci_low, ci_high),
        classical_bound=CLASSICAL_BOUND,
        tsirelson_bound=TSIRELSON_BOUND,
        violates_classical=violates,
        sigma_violation=sigma_violation,
        p_value_classical=p_value,
        correlations=corr_dict,
        execution_mode=execution_mode,
        backend_name=backend_name,
        job_id=job_id,
        shots=shots,
        attack_type=attack_upper,
        attack_params=params,
    )


def run_chsh_comparison(
    shots: int = 4096,
    noise_strength: float = 0.25,
    eve_angle: float = 0.0,
    seed_simulator: Optional[int] = None,
) -> Dict[str, CHSHResult]:
    """
    Runs side-by-side CHSH experiments under identical shot counts:
    1. Clean channel (ideal Bell state)
    2. Depolarizing noise (physical degradation)
    3. Intercept-Resend attack (entanglement breaking)

    Returns a dict with keys: 'CLEAN', 'DEPOLARIZING', 'INTERCEPT_RESEND'.
    """
    clean_res = run_chsh_experiment(
        shots=shots,
        attack_type="NONE",
        seed_simulator=seed_simulator,
    )

    noise_res = run_chsh_experiment(
        shots=shots,
        attack_type="DEPOLARIZING_NOISE",
        attack_params={"noise_strength": noise_strength},
        seed_simulator=seed_simulator,
    )

    attack_res = run_chsh_experiment(
        shots=shots,
        attack_type="INTERCEPT_RESEND",
        attack_params={"eve_angle": eve_angle},
        seed_simulator=seed_simulator,
    )

    return {
        "CLEAN": clean_res,
        "DEPOLARIZING": noise_res,
        "INTERCEPT_RESEND": attack_res,
    }

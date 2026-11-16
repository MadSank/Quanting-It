"""
Backend Execution Manager for Quatinit.

Manages execution across local Aer simulators (ideal and noisy) and genuine
IBM Quantum hardware (QPUs) using qiskit-ibm-runtime.

Strict Safety and Verification Guarantees:
- Default is IDEAL_SIMULATOR (local, fast, zero cost).
- Hardware execution REQUIRES explicit confirmation (confirmed=True).
- Credentials are NEVER hardcoded or logged; retrieved from environment
  or interactive session securely.
- NEVER silently falls back to simulation when hardware execution fails.
- Preserves genuine backend metadata, job IDs, and retrieved counts.
"""

import os
import enum
from typing import Dict, Any, Optional, List, Tuple
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error


class ExecutionMode(str, enum.Enum):
    IDEAL_SIMULATOR = "IDEAL_SIMULATOR"
    NOISY_SIMULATOR = "NOISY_SIMULATOR"
    IBM_HARDWARE = "IBM_HARDWARE"


class BackendManager:
    """
    Manages circuit execution on simulators and IBM Quantum hardware.
    """

    def __init__(
        self,
        mode: ExecutionMode = ExecutionMode.IDEAL_SIMULATOR,
        backend_name: Optional[str] = None,
        ibm_token: Optional[str] = None,
        ibm_instance: Optional[str] = None,
        noise_strength: float = 0.1,
    ):
        self.mode = mode
        self.backend_name = backend_name
        self._ibm_token = ibm_token
        self.ibm_instance = ibm_instance
        self.noise_strength = noise_strength

    def get_token(self) -> Optional[str]:
        """Retrieves IBM Quantum API token from parameter or environment variables."""
        if self._ibm_token:
            return self._ibm_token
        return os.environ.get("QISKIT_IBM_TOKEN") or os.environ.get("IBM_QUANTUM_TOKEN")

    def validate_ibm_environment(self) -> Tuple[bool, str]:
        """
        Validates whether qiskit-ibm-runtime is installed and credentials exist.
        Returns (is_valid, message).
        """
        try:
            import qiskit_ibm_runtime  # noqa: F401
        except ImportError:
            return False, "qiskit-ibm-runtime is not installed. Install via: pip install qiskit-ibm-runtime"

        token = self.get_token()
        if not token:
            # Check if saved account exists
            try:
                from qiskit_ibm_runtime import QiskitRuntimeService
                saved = QiskitRuntimeService.saved_accounts()
                if not saved:
                    return False, "No IBM Quantum API token found in environment (QISKIT_IBM_TOKEN) or saved accounts."
            except Exception:
                return False, "No IBM Quantum API token found in environment (QISKIT_IBM_TOKEN)."

        return True, "IBM Quantum environment is valid and ready."

    def execute(
        self,
        circuits: List[QuantumCircuit],
        shots: int = 4096,
        attack_type: str = "NONE",
        attack_params: Optional[Dict[str, Any]] = None,
        confirmed: bool = False,
        seed_simulator: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes a batch of circuits under the configured mode.

        Returns:
            {
                "counts": List[Dict[str, int]],
                "backend_name": str,
                "execution_mode": str,
                "job_id": Optional[str],
                "metadata": Dict[str, Any]
            }
        """
        params = attack_params or {}

        if self.mode == ExecutionMode.IDEAL_SIMULATOR:
            sim = AerSimulator()
            counts_list = []
            for qc in circuits:
                job = sim.run(qc, shots=shots, seed_simulator=seed_simulator)
                counts_list.append(job.result().get_counts())

            return {
                "counts": counts_list,
                "backend_name": "aer_simulator_ideal",
                "execution_mode": ExecutionMode.IDEAL_SIMULATOR.value,
                "job_id": None,
                "metadata": {"shots": shots},
            }

        elif self.mode == ExecutionMode.NOISY_SIMULATOR:
            noise_val = float(params.get("noise_strength", self.noise_strength))
            safe_noise = max(0.0, min(0.75, noise_val))
            noise_model = NoiseModel()
            if safe_noise > 0.0:
                err = depolarizing_error(safe_noise, 1)
                noise_model.add_all_qubit_quantum_error(err, ["id"])

            sim = AerSimulator(noise_model=noise_model)
            counts_list = []
            for qc in circuits:
                job = sim.run(qc, shots=shots, seed_simulator=seed_simulator)
                counts_list.append(job.result().get_counts())

            return {
                "counts": counts_list,
                "backend_name": "aer_simulator_noisy",
                "execution_mode": ExecutionMode.NOISY_SIMULATOR.value,
                "job_id": None,
                "metadata": {
                    "shots": shots,
                    "noise_model": "depolarizing",
                    "noise_strength": safe_noise,
                },
            }

        elif self.mode == ExecutionMode.IBM_HARDWARE:
            # Explicit confirmation requirement
            if not confirmed:
                raise ValueError(
                    "Explicit user confirmation is required before submitting jobs to IBM Quantum hardware. "
                    "Set confirmed=True to proceed with QPU submission."
                )

            # Check dependency and credentials
            valid, msg = self.validate_ibm_environment()
            if not valid:
                raise RuntimeError(f"Cannot execute on IBM Quantum Hardware: {msg}")

            from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
            from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager

            token = self.get_token()
            init_kwargs: Dict[str, Any] = {"channel": "ibm_quantum"}
            if token:
                init_kwargs["token"] = token
            if self.ibm_instance:
                init_kwargs["instance"] = self.ibm_instance

            try:
                service = QiskitRuntimeService(**init_kwargs)
            except Exception as e:
                raise RuntimeError(f"Failed to authenticate with IBM Quantum: {e}") from e

            # Select backend
            backend_target = self.backend_name
            if not backend_target or backend_target == "least_busy":
                try:
                    target_backend = service.least_busy(simulator=False, operational=True)
                    backend_target = target_backend.name
                except Exception as e:
                    raise RuntimeError(f"Failed to query least busy IBM QPU: {e}") from e
            else:
                try:
                    target_backend = service.backend(backend_target)
                except Exception as e:
                    raise RuntimeError(f"Backend '{backend_target}' not found or unavailable: {e}") from e

            # Transpile circuits to Target Instruction Set Architecture (ISA)
            pm = generate_preset_pass_manager(backend=target_backend, optimization_level=1)
            isa_circuits = pm.run(circuits)

            # Execute via SamplerV2 primitive
            sampler = Sampler(mode=target_backend)
            job = sampler.run(isa_circuits, shots=shots)
            job_id = job.job_id()
            result = job.result()

            # Extract counts from SamplerV2 output
            counts_list = []
            for pub_result in result:
                # SamplerV2 returns BitArray data per classical register
                # Typically data.c or data.meas or first available bitarray
                pub_counts = {}
                data_dict = getattr(pub_result, "data", {})
                for field_name in dir(data_dict):
                    if field_name.startswith("_"):
                        continue
                    val = getattr(data_dict, field_name)
                    if hasattr(val, "get_counts"):
                        pub_counts = val.get_counts()
                        break
                if not pub_counts and hasattr(pub_result, "get_counts"):
                    pub_counts = pub_result.get_counts()
                counts_list.append(pub_counts)

            return {
                "counts": counts_list,
                "backend_name": backend_target,
                "execution_mode": ExecutionMode.IBM_HARDWARE.value,
                "job_id": job_id,
                "metadata": {
                    "shots": shots,
                    "target_backend": backend_target,
                },
            }

        else:
            raise ValueError(f"Unknown execution mode: {self.mode}")

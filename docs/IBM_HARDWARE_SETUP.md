# IBM Quantum Hardware Setup & Execution Guide for Quatinit

This guide explains how to configure and optionally execute genuine Clauser-Horne-Shimony-Holt (CHSH) Bell tests on IBM Quantum physical processors (QPUs).

---

## 1. Overview & Architectural Scope

Quatinit includes a complete, physically validated CHSH Bell inequality experiment engine (`src/chsh.py`) and multi-backend execution manager (`src/backend_manager.py`).

### Scientific Scope
- **What CHSH Measures**: The CHSH experiment tests the Bell parameter:
  $$S = E(a,b) - E(a,b') + E(a',b) + E(a',b')$$
  across four complementary measurement angles (Alice: $a=0, a'=\pi/2$; Bob: $b=\pi/4, b'=3\pi/4$).
  - Classical local-hidden-variable theories: $|S| \le 2.0$.
  - Quantum entangled Bell state $|\Phi^+\rangle$: $S = 2\sqrt{2} \approx 2.8284$ (Tsirelson bound).
  - A statistically significant violation ($S > 2.0$) certifies genuine non-locality and entanglement over the channel.
  - Channel decoherence (depolarizing noise) and eavesdropping (intercept-resend) collapse $S \le 2.0$, alerting the detection layer.
- **What Remains Outside Scope**: The CHSH Bell test validates entanglement and channel integrity. It does **not** replace the full Gottesman-Chuang Quantum Digital Signature (QDS) protocol, nor does it guarantee security against unmodeled physical side-channel attacks or denial of service.

---

## 2. Installation & Prerequisites

Local simulation via Qiskit Aer is the default and requires no external accounts or internet connection.

To enable physical execution on real IBM Quantum QPUs:

```bash
# Activate your virtual environment
.venv\Scripts\activate   # Windows
# or: source .venv/bin/activate  # Linux/macOS

# Install the IBM Quantum Runtime client
pip install "qiskit-ibm-runtime>=0.30.0"
```

---

## 3. Secure Credential Configuration

Never hardcode IBM Quantum API tokens in source code, commit them to version control, or print them in log messages.

### Option A: Environment Variable (Recommended)
Set the environment variable in your terminal before launching the application:

```powershell
# Windows PowerShell
$env:QISKIT_IBM_TOKEN = "your_actual_ibm_quantum_api_token"
```

```bash
# Linux / macOS Bash
export QISKIT_IBM_TOKEN="your_actual_ibm_quantum_api_token"
```

### Option B: Local `.env` File
Create a `.env` file in the project root (`d:\quatinit\.env`). Quatinit's `.gitignore` already excludes `.env` from git:

```ini
QISKIT_IBM_TOKEN=your_actual_ibm_quantum_api_token
```

### Option C: IBM Quantum Disk Credentials
Save credentials locally via the official CLI/SDK:

```python
from qiskit_ibm_runtime import QiskitRuntimeService

QiskitRuntimeService.save_account(
    channel="ibm_quantum",
    token="your_actual_ibm_quantum_api_token",
    overwrite=True,
)
```

---

## 4. Explicit Confirmation Requirement

To prevent accidental consumption of IBM Quantum queue credits, accidental network requests, or automated test charges, hardware execution **strictly requires explicit user confirmation**:
- In the Python API: `confirmed=True` must be passed to `BackendManager.execute()` or `run_chsh_experiment()`.
- In the Streamlit UI: The checkbox `"I explicitly confirm submission to real IBM Quantum hardware"` must be checked.
- If unconfirmed, execution raises a `ValueError` with an informative error message. The system **never** silently falls back to a simulator.

---

## 5. Running Experiments Locally

### Via Python API
```python
from src.chsh import run_chsh_experiment, run_chsh_comparison
from src.backend_manager import BackendManager, ExecutionMode

# 1. Fast local simulation (Noise-Free Bell Violation)
ideal_res = run_chsh_experiment(shots=4096, attack_type="NONE")
print(f"Ideal Simulation: S = {ideal_res.s_value:.3f} ± {ideal_res.uncertainty:.3f}")
print(f"Violates Classical Bound (S > 2.0): {ideal_res.violates_classical}")

# 2. 3-Way Comparative Experiment (Clean vs Depolarizing vs Intercept-Resend)
comparison = run_chsh_comparison(shots=4096, noise_strength=0.30)
for mode, res in comparison.items():
    print(f"{mode}: S = {res.s_value:.3f} (Violates: {res.violates_classical})")

# 3. IBM Quantum Hardware Execution (Requires Token & Confirmation)
bm = BackendManager(
    mode=ExecutionMode.IBM_HARDWARE,
    backend_name="least_busy",  # or "ibm_sherbrooke", "ibm_kyiv", etc.
)
hardware_res = run_chsh_experiment(
    shots=4096,
    backend_executor=bm,
)
print(f"IBM Hardware QPU: S = {hardware_res.s_value:.3f} ± {hardware_res.uncertainty:.3f}")
print(f"Job ID: {hardware_res.job_id}")
```

### Via Streamlit UI
1. Launch the application:
   ```powershell
   .venv\Scripts\streamlit run app.py
   ```
2. Navigate to **Tab 4: E91 BELL-CORRELATION MONITORING & QUANTUM TRANSPORT**.
3. Under **CHSH BELL INEQUALITY TEST & NON-LOCALITY VERIFICATION**:
   - Select **Execution Platform**: `Local Aer Simulator` or `Genuine IBM Quantum QPU`.
   - Adjust shot count and disturbance mode.
   - For hardware, enter token and tick confirmation.
   - Click **RUN CHSH BELL TEST** or **RUN 3-WAY COMPARISON**.
   - Download complete experimental results via the JSON export button.

---

## 6. Common Failure Modes and Troubleshooting

| Symptom | Cause | Resolution |
| :--- | :--- | :--- |
| `ImportError: qiskit-ibm-runtime is not installed` | Missing package in environment | Run `pip install qiskit-ibm-runtime` |
| `ValueError: Explicit user confirmation is required` | Safeguard tripped | Pass `confirmed=True` in code or check the confirmation box in UI |
| `RuntimeError: No IBM Quantum API token found` | Missing credentials | Set `QISKIT_IBM_TOKEN` environment variable or enter token in UI |
| Long queue wait times | Free tier QPU backends may be congested | Select `least_busy` backend or run during off-peak hours |
| $S \approx 2.4 - 2.6$ on real QPU | Physical gate & readout noise on real qubits | Normal on NISQ devices without error mitigation; still exceeds classical 2.0 |

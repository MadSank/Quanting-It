"""
Blue-team sender CLI: send real messages through a protocol version over an
honest (passively tapped) network.

    python -m redteam.sender --version v1 --msg "hello" --msg "world" --name run1
    python -m redteam.sender --version v1 --file my_messages.txt --name run2

Writes
  redteam/captures/<name>.wire.json     what an eavesdropper recorded (public)
  redteam/secrets/<name>.truth.json     ground truth: sent + accepted (secret)
and prints a delivery report (latency, QKD stats, failures).

Add --noise to simulate a worse fibre (QBER stress), --pulses to change the
QKD block size.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from src.qsc import channel  # noqa: E402
from src.qsc.channel import VERSIONS, run_session  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="v1", choices=list(VERSIONS))
    ap.add_argument("--msg", action="append", default=[])
    ap.add_argument("--file")
    ap.add_argument("--name", default=None)
    ap.add_argument("--noise", type=float, default=None, help="fibre misalignment error, e.g. 0.05")
    ap.add_argument("--loss", type=float, default=None, help="fibre transmittance, e.g. 0.05")
    a = ap.parse_args()

    msgs = list(a.msg)
    if a.file:
        msgs += [l.rstrip("\n") for l in Path(a.file).read_text(encoding="utf-8").splitlines() if l.strip()]
    if not msgs:
        ap.error("no messages")

    cfg = VERSIONS[a.version]
    if cfg is not None and cfg.qkd is not None and (a.noise is not None or a.loss is not None):
        fib = cfg.qkd.fibre
        fib = replace(fib, misalignment=a.noise if a.noise is not None else fib.misalignment,
                      transmittance=a.loss if a.loss is not None else fib.transmittance)
        channel.VERSIONS[a.version] = replace(cfg, qkd=replace(cfg.qkd, fibre=fib))

    t0 = time.time()
    rep = run_session(a.version, msgs)
    dt = time.time() - t0
    name = a.name or f"{a.version}_{int(t0)}"
    (ROOT / "captures").mkdir(exist_ok=True)
    (ROOT / "secrets").mkdir(exist_ok=True)
    (ROOT / "captures" / f"{name}.wire.json").write_text(
        json.dumps({"version": a.version, "wire": rep.wire_log}, indent=1), encoding="utf-8")
    (ROOT / "secrets" / f"{name}.truth.json").write_text(
        json.dumps({"sent": rep.sent, "accepted": rep.accepted}, indent=1, ensure_ascii=False),
        encoding="utf-8")
    print(json.dumps({
        "version": a.version, "seconds": round(dt, 3), "aborted": rep.aborted,
        "abort_reason": rep.abort_reason, "sent": len(rep.sent), "accepted": len(rep.accepted),
        "intact": rep.sent == rep.accepted, "rejected": rep.rejected,
        "key_sources": rep.key_sources, "qkd": rep.qkd_stats,
        "wire_messages": len(rep.wire_log), "capture": f"redteam/captures/{name}.wire.json",
    }, indent=1))


if __name__ == "__main__":
    main()

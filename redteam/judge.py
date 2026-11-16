"""
Red-team judge. Runs an attack plugin against one or more protocol versions
with secret messages the attacker never sees, and scores it.

    python -m redteam.judge redteam/attacks/my_attack.py --versions v0 v1 --trials 3

An attack plugin is a .py file defining `class Attack(src.qsc.wire.Adversary)`.

WARNING: plugins run as ordinary Python with your user's full permissions.
The lint below catches rule breaks, it is not a sandbox. Only run plugins
you wrote or have read.

Scores per version (averaged over trials):
  confidentiality_break  fraction of Alice's plaintexts Eve reproduced exactly
  forgeries_accepted     messages Bob accepted that Alice never sent (or extra replays)
  detected               session aborted or Bob rejected at least one packet
  delivered              fraction of Alice's messages Bob accepted intact
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import re
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from src.qsc.channel import VERSIONS, run_session  # noqa: E402

FORBIDDEN = [
    r"\._bit\b", r"\._basis\b", r"_registry", r"redteam[/\\.]secrets", r"secrets[/\\]corpus",
    r"\bimport\s+gc\b", r"\bgc\.get_objects", r"\binspect\b", r"_getframe", r"\bctypes\b",
    r"report\.sent", r"\bsys\.modules\b", r"__closure__", r"f_locals", r"f_back",
]

DEFAULT_CORPUS = [
    "Wire 25,000 to account ending 4471 before noon",
    "The vault code changes to 8812 tonight",
    "Meet at the north gate, 21:00, bring the drive",
    "Board approved the merger; announce Friday",
    "patient 0193 results: negative",
]


def load_corpus() -> list[str]:
    p = ROOT / "secrets" / "corpus.json"
    if p.exists():
        data = json.loads(p.read_text(encoding="utf-8"))
        if data:
            return data
    return DEFAULT_CORPUS


def lint_attack(src: str) -> list[str]:
    return [pat for pat in FORBIDDEN if re.search(pat, src)]


def load_attack(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Attack


def score_trial(rep, guesses) -> dict:
    sent = Counter(rep.sent)
    acc = Counter(rep.accepted)
    forged = sum((acc - sent).values())
    delivered = sum((acc & sent).values())
    g = set(guesses or [])
    broken = sum(1 for m in rep.sent if m in g)
    return {
        "confidentiality_break": broken / max(1, len(rep.sent)) if rep.sent else 0.0,
        "forgeries_accepted": forged,
        "detected": bool(rep.aborted or rep.rejected),
        "aborted": rep.aborted,
        "abort_reason": rep.abort_reason,
        "delivered": delivered / max(1, len(rep.sent)) if rep.sent else 0.0,
        "key_sources": rep.key_sources,
        "qkd": {k: rep.qkd_stats.get(k) for k in ("qber", "detections", "final_bits", "abort",
                                                  "single_photon_fraction", "Y1_L")
                if k in rep.qkd_stats},
    }


def judge(attack_path: Path, versions: list[str], trials: int, msgs_per_trial: int = 3,
          seed: int | None = None) -> dict:
    src = attack_path.read_text(encoding="utf-8")
    bad = lint_attack(src)
    if bad:
        return {"attack": attack_path.name, "error": f"forbidden constructs: {bad}"}
    Attack = load_attack(attack_path)
    corpus = load_corpus()
    rng = random.Random(seed)
    out = {"attack": attack_path.name, "name": getattr(Attack, "name", attack_path.stem),
           "versions": {}}
    for v in versions:
        rows = []
        for _ in range(trials):
            msgs = rng.sample(corpus, min(msgs_per_trial, len(corpus)))
            eve = Attack()
            t0 = time.time()
            try:
                rep = run_session(v, msgs, eve)
                eve.ctx.shor.enabled = True      # harvest-now, decrypt-later
                try:
                    guesses = eve.recover(rep.wire_log)
                except Exception:
                    guesses = []
                    traceback.print_exc()
                row = score_trial(rep, guesses)
                row["crqc_queries"] = eve.ctx.shor.queries
            except Exception as e:
                traceback.print_exc()
                row = {"error": repr(e)}
            row["seconds"] = round(time.time() - t0, 2)
            rows.append(row)
        ok = [r for r in rows if "error" not in r]
        agg = {
            "confidentiality_break": round(sum(r["confidentiality_break"] for r in ok) / max(1, len(ok)), 3),
            "forgeries_accepted": sum(r["forgeries_accepted"] for r in ok),
            "detected_rate": round(sum(r["detected"] for r in ok) / max(1, len(ok)), 3),
            "abort_rate": round(sum(r["aborted"] for r in ok) / max(1, len(ok)), 3),
            "delivered": round(sum(r["delivered"] for r in ok) / max(1, len(ok)), 3),
            "errors": len(rows) - len(ok),
        }
        out["versions"][v] = {"summary": agg, "trials": rows}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("attack", nargs="+")
    ap.add_argument("--versions", nargs="+", default=list(VERSIONS))
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--save", action="store_true", help="write redteam/results/<attack>.json")
    a = ap.parse_args()
    for path in a.attack:
        res = judge(Path(path), a.versions, a.trials)
        if "error" in res:
            print(res["attack"], "REJECTED:", res["error"])
            continue
        print(f"\n== {res['attack']} ({res['name']})")
        for v, d in res["versions"].items():
            s = d["summary"]
            print(f"  {v}: conf_break={s['confidentiality_break']:.2f} forged={s['forgeries_accepted']} "
                  f"detected={s['detected_rate']:.2f} aborted={s['abort_rate']:.2f} "
                  f"delivered={s['delivered']:.2f} errors={s['errors']}")
            for t in d["trials"][:1]:
                print("     sample:", {k: t.get(k) for k in ("abort_reason", "key_sources", "qkd", "crqc_queries")})
        if a.save:
            (ROOT / "results").mkdir(exist_ok=True)
            (ROOT / "results" / (Path(path).stem + ".json")).write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()

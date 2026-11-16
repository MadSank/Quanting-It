"""Example attack: passive wiretap that greps for plaintext on the wire."""

from src.qsc.wire import Adversary


class Attack(Adversary):
    name = "passive-grep"

    def recover(self, wire_log):
        out = []
        for env in wire_log:
            msg = env["payload"].get("message")
            if isinstance(msg, str):
                out.append(msg)
        return out

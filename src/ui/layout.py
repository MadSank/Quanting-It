"""Reusable layout pieces for the Quatinit console (HTML rendered via st.markdown)."""

from __future__ import annotations

from html import escape

import streamlit as st

_MARK = (
    '<svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">'
    '<circle cx="9" cy="9" r="7.25" fill="none" stroke="currentColor" stroke-width="1.5"/>'
    '<ellipse cx="9" cy="9" rx="7.25" ry="2.6" fill="none" stroke="currentColor" stroke-width="1" opacity=".6"/>'
    '<circle cx="9" cy="9" r="1.8" fill="currentColor"/></svg>'
)


def _md(html: str) -> None:
    st.markdown(html, unsafe_allow_html=True)


def hero(session_id: str, seq: int, chips: list[tuple[str, str]]) -> None:
    chip_html = "".join(f'<span class="status-badge status-badge-{k}">{escape(t)}</span>' for k, t in chips)
    _md(f"""
<div class="q-hero">
  <div>
    <div class="q-wordmark">{_MARK}<span>Quatinit</span></div>
    <h1>Quantum digital signature console</h1>
    <p class="q-lede">Gottesman–Chuang signatures verified by destructive SWAP tests, carried over a
    teleportation channel and watched by a Bell-correlation monitor.</p>
  </div>
  <div class="q-context">
    <div class="q-kv">session <b>{escape(session_id)}</b> &nbsp;·&nbsp; seq <b>{seq}</b></div>
    <div>{chip_html}</div>
  </div>
</div>""")


def _node(name: str, role: str, color_var: str) -> str:
    return (f'<div class="q-node" style="--dot: var(--q-{color_var})"><span class="q-who">{name}</span>'
            f'<span class="q-role">{role}</span></div>')


def _link(caption: str, kind: str = "") -> str:
    return f'<div class="q-link {kind}"><div class="q-wire"></div><span class="q-cap">{caption}</span></div>'


def channel_flow(attack_name: str | None = None, rejection_code: str = "", layer: str = "") -> None:
    if attack_name:
        body = (_node("Alice", "signer", "alice") + _link("classical + quantum", "hostile")
                + _node("Eve", escape(attack_name).replace("_", " ").lower(), "eve")
                + _link("tampered", "hostile") + _node("Bob", "verifier", "bob"))
        status = (f'<span class="status-badge status-badge-reject">Interception detected</span>'
                  f'<span>rejection <b>{escape(rejection_code)}</b></span>'
                  f'<span>caught at <b>{escape(layer)}</b></span>')
        cls = "q-flow attacked"
    else:
        body = (_node("Alice", "signer", "alice") + _link("teleportation · quantum", "quantum")
                + _node("Bob", "verifier", "bob") + _link("transfer · classical")
                + _node("Charlie", "arbiter", "charlie"))
        status = ('<span class="status-badge status-badge-accept">Channel clear</span>'
                  '<span>no adversarial disturbance on the last verification</span>')
        cls = "q-flow"
    _md(f'<div class="{cls}">{body}</div><div class="q-flow-status">{status}</div>')


def page_header(step: int, total: int, eyebrow: str, title: str, lede: str = "") -> None:
    lede_html = f"<p>{lede}</p>" if lede else ""
    _md(f"""<div class="q-page"><div class="q-eyebrow"><span class="q-dash"></span>
<span class="q-step">{step:02d} / {total:02d}</span><span>{escape(eyebrow)}</span></div>
<h2>{escape(title)}</h2>{lede_html}</div>""")


def section(title: str, num: str | None = None, note: str = "") -> None:
    num_html = f'<span class="q-num">{escape(num)}</span>' if num else ""
    note_html = f'<span class="q-note">{escape(note)}</span>' if note else ""
    _md(f'<div class="q-section">{num_html}<span class="q-title">{escape(title)}</span>{note_html}</div>')


def side_label(text: str) -> None:
    _md(f'<div class="q-side-label">{escape(text)}</div>')


def params(rows: list[tuple[str, str]]) -> None:
    _md("".join(f'<div class="q-param"><span>{k}</span><b>{v}</b></div>' for k, v in rows))

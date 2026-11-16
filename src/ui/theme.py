"""Design tokens and global stylesheet for the Quatinit console.

One source of truth for colour: CSS custom properties are generated from the
PALETTES dict below (dark only: Streamlit native widgets follow
.streamlit/config.toml, so a CSS-only light mode cannot restyle them), and matplotlib charts read the same values via chart_colors().
Legacy class names used throughout app.py (soc-card, status-badge-*, mono-data,
pipeline-step) are restyled here rather than rewritten.
"""

from __future__ import annotations

import streamlit as st

PALETTES = {
    "DARK": {
        "bg": "#0B0E13", "surface": "#12161D", "surface-2": "#181D26", "sidebar": "#0E1218",
        "line": "#232A35", "line-strong": "#344050", "control": "#4A5568",
        "text": "#E7EAF0", "text-2": "#A3ACBA", "text-3": "#7A8496",
        "accent": "#5EC2B7", "accent-hi": "#86D9CF", "accent-fill": "#2F8F86",
        "accent-tint": "rgba(94, 194, 183, 0.10)",
        "accept": "#5FB08C", "accept-tint": "rgba(95, 176, 140, 0.10)",
        "reject": "#E0605C", "reject-text": "#EF8481", "reject-tint": "rgba(224, 96, 92, 0.10)",
        "warn": "#E0B04C", "warn-tint": "rgba(224, 176, 76, 0.10)",
        "alice": "#8FB3FF", "bob": "#5EC2B7", "charlie": "#C9A86A", "eve": "#E0605C",
        "grid": "#1E2530",
    },
}

FONT_SANS = '"IBM Plex Sans", "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif'
FONT_MONO = '"IBM Plex Mono", "Cascadia Mono", Consolas, monospace'


def chart_colors(theme: str = "DARK") -> dict:
    """Palette for matplotlib figures so charts match the page."""
    p = PALETTES.get(theme, PALETTES["DARK"])
    return {
        "fig": p["surface"], "axes": p["surface"], "text": p["text"], "muted": p["text-2"],
        "grid": p["grid"], "line": p["line-strong"], "accent": p["accent"],
        "accept": p["accept"], "reject": p["reject"], "warn": p["warn"], "alice": p["alice"],
    }


def _vars(theme: str) -> str:
    p = PALETTES.get(theme, PALETTES["DARK"])
    return "\n".join(f"    --q-{k}: {v};" for k, v in p.items())


_CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

:root {
__VARS__
    --q-sans: __SANS__;
    --q-mono: __MONO__;
    --q-r: 6px;
    /* aliases for inline styles written against the old palette */
    --text-main: var(--q-text); --text-muted: var(--q-text-2); --text-bright: var(--q-accent);
    --bg-card: var(--q-surface); --border-subtle: var(--q-line); --border-accent: var(--q-accent);
    --border-alert: var(--q-reject); --border-success: var(--q-accept);
    --card-alert-bg: var(--q-reject-tint); --card-success-bg: var(--q-accept-tint);
    --badge-accept-bg: var(--q-accept-tint); --badge-accept-text: var(--q-accept); --badge-accept-border: var(--q-accept);
    --badge-reject-bg: var(--q-reject-tint); --badge-reject-text: var(--q-reject-text); --badge-reject-border: var(--q-reject);
    --badge-info-bg: var(--q-accent-tint); --badge-info-text: var(--q-accent); --badge-info-border: var(--q-accent);
    --badge-warn-bg: var(--q-warn-tint); --badge-warn-text: var(--q-warn); --badge-warn-border: var(--q-warn);
}

/* ---------- canvas ---------- */
.stApp { background: var(--q-bg); color: var(--q-text); font-family: var(--q-sans); }
header[data-testid="stHeader"] { background: transparent; }
.main .block-container, [data-testid="stMainBlockContainer"] {
    max-width: 1360px; padding-top: 1.5rem; padding-bottom: 4rem;
}
section[data-testid="stSidebar"] { background: var(--q-sidebar); border-right: 1px solid var(--q-line); }
section[data-testid="stSidebar"] [data-testid="stSidebarContent"] { padding-top: 0.5rem; }
html, body, [class*="css"], .stMarkdown, p, li, label { font-family: var(--q-sans); }
p, li { line-height: 1.6; }

h1, h2, h3, h4, h5, h6 { font-family: var(--q-sans) !important; color: var(--q-text) !important; letter-spacing: -0.01em; }
h2 { font-size: 1.3rem !important; font-weight: 600 !important; }
h3 { font-size: 1.1rem !important; font-weight: 600 !important; margin-top: 1.6rem !important; }
h4 { font-size: 1rem !important; font-weight: 600 !important; margin-top: 1.4rem !important; }
h5 { font-size: 0.8rem !important; font-weight: 600 !important; text-transform: uppercase;
     letter-spacing: 0.06em; color: var(--q-text-3) !important; margin-top: 0.4rem !important; }
code { font-family: var(--q-mono) !important; font-size: 0.85em; }
hr { border-color: var(--q-line) !important; margin: 1.1rem 0 !important; }

/* ---------- tabs ---------- */
.stTabs [data-baseweb="tab-list"] {
    gap: 2px; border-bottom: 1px solid var(--q-line); flex-wrap: wrap;
}
.stTabs [data-baseweb="tab"] {
    height: 42px; padding: 0 14px; font-weight: 500; font-size: 0.9rem;
    color: var(--q-text-2); background: transparent; border-radius: 0;
}
.stTabs [data-baseweb="tab"] p { font-size: 0.9rem; }
.stTabs [data-baseweb="tab"]:hover { color: var(--q-text); background: var(--q-accent-tint); }
.stTabs [aria-selected="true"] { color: var(--q-text) !important; }
.stTabs [data-baseweb="tab-highlight"] { background-color: var(--q-accent) !important; height: 2px; }
.stTabs [data-baseweb="tab-border"] { display: none; }

/* ---------- controls ---------- */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
    border-radius: var(--q-r); border: 1px solid var(--q-control); background: var(--q-surface);
    color: var(--q-text); font-weight: 500; transition: border-color .15s, background .15s;
}
.stButton > button:hover { border-color: var(--q-accent); color: var(--q-text); background: var(--q-accent-tint); }
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
    background: var(--q-accent-fill); border-color: var(--q-accent-fill); color: #fff;
}
.stButton > button[kind="primary"]:hover { filter: brightness(1.08); color: #fff; }
.stButton > button:focus-visible { outline: 2px solid var(--q-accent); outline-offset: 2px; }
[data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="select"] > div {
    border-radius: var(--q-r) !important;
}

/* ---------- metrics ---------- */
div[data-testid="stMetric"] {
    background: var(--q-surface); border: 1px solid var(--q-line); border-radius: var(--q-r);
    padding: 12px 14px;
}
div[data-testid="stMetricLabel"] p { font-size: 0.74rem !important; text-transform: uppercase;
    letter-spacing: 0.05em; color: var(--q-text-3) !important; font-weight: 500; }
div[data-testid="stMetricValue"] { font-family: var(--q-mono) !important; font-size: 1.4rem !important;
    font-weight: 500 !important; color: var(--q-text) !important; font-variant-numeric: tabular-nums; }
section[data-testid="stSidebar"] div[data-testid="stMetric"] { padding: 8px 12px; }
section[data-testid="stSidebar"] div[data-testid="stMetricValue"] { font-size: 1.1rem !important; }

/* ---------- containers ---------- */
[data-testid="stExpander"] details { border: 1px solid var(--q-line); border-radius: var(--q-r); background: var(--q-surface); }
[data-testid="stDataFrame"] { border: 1px solid var(--q-line); border-radius: var(--q-r); }
[data-testid="stAlert"] { border-radius: var(--q-r); }

/* ---------- legacy card classes, restyled ---------- */
.soc-card, .soc-card-accent, .soc-card-alert, .soc-card-success {
    background: var(--q-surface); border: 1px solid var(--q-line); border-radius: var(--q-r);
    padding: 18px 20px; margin-bottom: 14px; color: var(--q-text);
}
.soc-card h4 { margin-top: 0 !important; font-size: 0.95rem !important; color: var(--q-text) !important; }
.soc-card h4[style] { color: var(--q-text) !important; }
.soc-card p { color: var(--q-text-2) !important; font-size: 0.9rem !important; margin-bottom: 12px; }
.soc-card-accent { border-left: 3px solid var(--q-accent); }
.soc-card-alert { background: var(--q-reject-tint); border-color: var(--q-reject); border-left-width: 3px; }
.soc-card-success { background: var(--q-accept-tint); border-color: var(--q-accept); border-left-width: 3px; }

.status-badge {
    display: inline-flex; align-items: center; gap: 6px; padding: 3px 9px; border-radius: 999px;
    font-family: var(--q-mono); font-size: 0.72rem; font-weight: 500; letter-spacing: 0.02em;
    border: 1px solid var(--q-line-strong); color: var(--q-text-2); background: transparent;
    margin: 2px 4px 2px 0; text-transform: none;
}
.status-badge::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.status-badge-accept { color: var(--q-accept) !important; border-color: color-mix(in srgb, var(--q-accept) 45%, transparent) !important; background: var(--q-accept-tint) !important; }
.status-badge-reject { color: var(--q-reject-text) !important; border-color: color-mix(in srgb, var(--q-reject) 45%, transparent) !important; background: var(--q-reject-tint) !important; }
.status-badge-info { color: var(--q-accent) !important; border-color: color-mix(in srgb, var(--q-accent) 40%, transparent) !important; background: var(--q-accent-tint) !important; }
.status-badge-warn { color: var(--q-warn) !important; border-color: color-mix(in srgb, var(--q-warn) 45%, transparent) !important; background: var(--q-warn-tint) !important; }
.status-badge-neutral { color: var(--q-text-2) !important; }

.mono-data { font-family: var(--q-mono); font-size: 0.84rem; letter-spacing: 0; color: var(--q-text); }
.pipeline-step, .pipeline-step-failed { border-left: 2px solid var(--q-accent); padding-left: 14px; margin-bottom: 12px; }
.pipeline-step-failed { border-left-color: var(--q-reject); }

/* ---------- new components ---------- */
.q-hero { display: flex; justify-content: space-between; align-items: flex-end; gap: 24px;
    flex-wrap: wrap; padding: 6px 0 18px; border-bottom: 1px solid var(--q-line); margin-bottom: 18px; }
.q-wordmark { font-family: var(--q-mono); font-size: 0.78rem; letter-spacing: 0.14em; text-transform: uppercase;
    color: var(--q-accent); display: flex; align-items: center; gap: 10px; }
.q-wordmark svg { display: block; }
.q-hero h1 { font-size: 1.9rem !important; font-weight: 600 !important; margin: 6px 0 4px !important;
    padding: 0 !important; line-height: 1.2; }
.q-hero .q-lede { color: var(--q-text-2); font-size: 0.95rem; max-width: 62ch; margin: 0; }
.q-context { display: flex; flex-direction: column; align-items: flex-end; gap: 8px; }
.q-context .q-kv { font-family: var(--q-mono); font-size: 0.8rem; color: var(--q-text-3); }
.q-context .q-kv b { color: var(--q-text); font-weight: 500; }

.q-flow { display: flex; align-items: center; gap: 0; background: var(--q-surface); border: 1px solid var(--q-line);
    border-radius: var(--q-r); padding: 14px 18px; margin-bottom: 8px; overflow-x: auto; }
.q-flow.attacked { border-color: color-mix(in srgb, var(--q-reject) 55%, var(--q-line)); }
.q-node { display: flex; flex-direction: column; min-width: 92px; }
.q-node .q-who { font-weight: 600; font-size: 0.92rem; display: flex; align-items: center; gap: 7px; white-space: nowrap; }
.q-node .q-who::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--dot); }
.q-node .q-role { font-family: var(--q-mono); font-size: 0.7rem; color: var(--q-text-3); text-transform: uppercase; letter-spacing: 0.06em; }
.q-link { flex: 1; min-width: 60px; display: flex; flex-direction: column; align-items: center; padding: 0 10px; }
.q-link .q-wire { width: 100%; height: 2px; background: var(--q-line-strong); position: relative; }
.q-link.quantum .q-wire { background: repeating-linear-gradient(90deg, var(--q-accent) 0 6px, transparent 6px 10px); }
.q-link.hostile .q-wire { background: var(--q-reject); }
.q-link .q-cap { font-family: var(--q-mono); font-size: 0.68rem; color: var(--q-text-3); margin-top: 6px; white-space: nowrap; }
.q-link.hostile .q-cap { color: var(--q-reject-text); }
.q-flow-status { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; font-size: 0.84rem;
    color: var(--q-text-2); margin: 4px 0 20px; }
.q-flow-status b { color: var(--q-text); font-weight: 500; font-family: var(--q-mono); font-size: 0.8rem; }

.q-page { margin: 8px 0 18px; }
.q-eyebrow { font-family: var(--q-mono); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.1em;
    color: var(--q-text-3); display: flex; align-items: center; gap: 8px; }
.q-eyebrow .q-step { color: var(--q-accent); }
.q-eyebrow .q-dash { width: 14px; height: 2px; background: var(--q-accent); display: inline-block; }
.q-page h2 { margin: 6px 0 4px !important; padding: 0 !important; font-size: 1.45rem !important; }
.q-page p { color: var(--q-text-2); max-width: 75ch; margin: 0; font-size: 0.95rem; }
.q-section { display: flex; align-items: baseline; gap: 10px; margin: 26px 0 10px; padding-bottom: 6px;
    border-bottom: 1px solid var(--q-line); }
.q-section .q-num { font-family: var(--q-mono); font-size: 0.75rem; color: var(--q-accent); }
.q-section .q-title { font-weight: 600; font-size: 1.02rem; color: var(--q-text); }
.q-section .q-note { margin-left: auto; font-size: 0.8rem; color: var(--q-text-3); }
.q-side-label { font-family: var(--q-mono); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em;
    color: var(--q-text-3); margin: 18px 0 8px; }
.q-param { display: flex; justify-content: space-between; gap: 10px; font-size: 0.84rem; padding: 5px 0;
    border-bottom: 1px dashed var(--q-line); color: var(--q-text-2); }
.q-param b { font-family: var(--q-mono); font-weight: 500; color: var(--q-text); }

@media (max-width: 760px) {
    .q-hero h1 { font-size: 1.5rem !important; }
    .q-context { align-items: flex-start; }
    .q-flow { flex-direction: column; align-items: stretch; gap: 0; }
    .q-link { flex-direction: row; gap: 10px; padding: 6px 0 6px 3px; min-width: 0; }
    .q-link .q-wire { width: 2px; height: 22px; flex: none; }
    .q-link.quantum .q-wire { background: repeating-linear-gradient(180deg, var(--q-accent) 0 5px, transparent 5px 9px); }
    .q-link .q-cap { margin-top: 0; }
    .q-node { flex-direction: row; align-items: baseline; gap: 10px; }
    .main .block-container, [data-testid="stMainBlockContainer"] { padding-left: 1rem; padding-right: 1rem; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
"""


def inject_css(theme: str = "DARK") -> None:
    css = (_CSS.replace("__VARS__", _vars(theme))
           .replace("__SANS__", FONT_SANS).replace("__MONO__", FONT_MONO))
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

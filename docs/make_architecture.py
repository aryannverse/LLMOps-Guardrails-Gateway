"""Regenerates docs/architecture.png (python docs/make_architecture.py)."""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon, Rectangle

fig, ax = plt.subplots(figsize=(15, 7.6))
ax.set_xlim(0, 15); ax.set_ylim(0, 7.6); ax.axis("off")


def box(x, y, w, h, title, sub="", fc="#FFFFFF", ec="#37474F", tc="#102027"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12", fc=fc, ec=ec, lw=1.6))
    if not sub:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=10.5, fontweight="bold", color=tc)
        return
    ax.text(x + w / 2, y + h - 0.26, title, ha="center", va="center", fontsize=10.5, fontweight="bold", color=tc)
    ax.text(x + w / 2, (y + h - 0.45) / 2 + y / 2, sub, ha="center", va="center", fontsize=8.3, color="#37474F",
            linespacing=1.25)


def arrow(x1, y1, x2, y2, label="", color="#37474F", ls="-", lx=0, ly=0.15):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=14, lw=1.6, color=color, ls=ls))
    if label:
        ax.text((x1 + x2) / 2 + lx, (y1 + y2) / 2 + ly, label, ha="center", fontsize=8.2, color=color, fontweight="bold")


# trust boundary
ax.add_patch(Rectangle((2.55, 0.25), 9.3, 6.75, fill=False, ls="--", lw=1.3, ec="#78909C"))
ax.text(2.7, 6.8, "Local trust boundary - runs 100% on CPU, no PII leaves this box", fontsize=9, color="#546E7A",
        style="italic")
ax.add_patch(Rectangle((2.85, 3.05), 6.45, 3.35, fc="#F5F7FA", ec="#90A4AE", lw=1.1))
ax.text(3.0, 6.17, "FastAPI  POST /secure-chat", fontsize=10, fontweight="bold", color="#263238")

box(0.15, 4.6, 2.1, 1.1, "Client / App", "prompt (untrusted)", fc="#ECEFF1")
box(0.15, 2.95, 2.1, 1.25, "RAG / web / email", "retrieved context\n(indirect-injection surface)", fc="#ECEFF1")
box(3.1, 4.05, 2.55, 1.7, "Stage 1", "PII sanitiser\ncompiled regex +\nLuhn / Verhoeff checks\n-> <REDACTED_EMAIL>...",
    fc="#E8F5E9", ec="#2E7D32")
box(6.1, 4.05, 2.95, 1.7, "Stage 2", "DeBERTa-v3 classifier\nP(injection) for prompt\nand every context doc\n512-token sliding windows",
    fc="#E3F2FD", ec="#1565C0")
dx, dy = 8.0, 3.55
ax.add_patch(Polygon([[dx - 0.95, dy], [dx, dy + 0.42], [dx + 0.95, dy], [dx, dy - 0.42]], fc="#FFF8E1", ec="#F9A825", lw=1.6))
ax.text(dx, dy, "max score > tau\n(tau = 0.85)", ha="center", va="center", fontsize=8.3, fontweight="bold")

box(9.65, 4.75, 2.0, 1.15, "HTTP 403", "blocked, zero LLM\ntokens spent", fc="#FFEBEE", ec="#C62828", tc="#B71C1C")
box(12.3, 2.85, 2.55, 1.4, "Groq LLM", "openai/gpt-oss-20b\nsanitised + approved\ntext only", fc="#F3E5F5", ec="#6A1B9A")
box(9.65, 2.05, 2.0, 1.0, "HTTP 200", "response +\nredaction report", fc="#E8F5E9", ec="#2E7D32")
box(3.1, 0.55, 3.7, 1.35, "Telemetry", "append-only JSONL\nSHA-256 hash chain (tamper-evident)", fc="#FFFDE7", ec="#9E9D24")
box(7.6, 0.55, 3.9, 1.35, "Stage 3", "Streamlit dashboard: requests, blocks,\nPII redacted, P95 overhead, audit trail",
    fc="#E0F2F1", ec="#00695C")

arrow(2.25, 5.15, 3.1, 4.95)
arrow(2.25, 3.6, 3.1, 4.3)
arrow(5.65, 4.9, 6.1, 4.9)
arrow(dx, 4.05, dx, dy + 0.42)
arrow(dx + 0.55, dy + 0.2, 9.65, 5.0, "yes", "#C62828", lx=0.35, ly=-0.25)
arrow(dx + 0.95, dy, 12.3, dy, "no: forward", "#2E7D32", lx=0.4, ly=0.1)
arrow(12.9, 2.85, 11.65, 2.55, color="#6A1B9A")
ax.text(12.35, 4.35, "external provider", fontsize=8, color="#6A1B9A", style="italic")
arrow(dx, dy - 0.42, 5.4, 1.9, "every decision logged", "#9E9D24", lx=-0.6, ly=0.05)
arrow(6.8, 1.22, 7.6, 1.22, color="#00695C")
ax.text(7.5, 7.25, "Dual-Layer Zero-Trust LLMOps Security Gateway", ha="center", fontsize=14, fontweight="bold",
        color="#102027")
out = Path(__file__).with_name("architecture.png")
fig.savefig(out, dpi=170, bbox_inches="tight", facecolor="white")
print("saved", out)

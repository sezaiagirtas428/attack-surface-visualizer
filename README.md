# Attack Surface Visualizer

Attack Surface Visualizer is a **local, read-only** Windows security assessment tool that helps you understand how exposed a system is from an attacker’s perspective.

It focuses on **visibility and exposure signals** (attack surface discovery) rather than exploitation.

> ⚠️ This tool does **not** perform exploitation, active scanning, or configuration changes.  
> It only inspects existing system state and reports potential exposure indicators.

---

## What does it analyze?

The tool inspects common Windows attack surface components such as:

- Local administrator and privileged group memberships
- Services and configurations that may increase exposure
- Autorun / persistence-related entries
- Presence and relevance of Living-off-the-Land Binaries (LOLBins)
- Other host-level indicators that can support attack path reasoning

Results are presented in a structured, analyst-friendly format to support both offensive simulation and defensive hardening decisions.

---

## Who is this for?

-  **Red team / pentest labs**: quick host discovery and initial exposure review
-  **Blue team / defenders**: visibility into local misconfigurations and risky signals
-  **Students**: learning Windows attack paths and security fundamentals

---

## Quick Start (recommended)

Run directly from PowerShell:

```powershell
iwr -useb https://raw.githubusercontent.com/sezaiagirtas428/attack-surface-visualizer/main/run.ps1 | iex

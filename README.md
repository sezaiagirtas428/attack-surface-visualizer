# Attack Surface Visualizer

Attack Surface Visualizer is a local, read-only Windows security assessment tool
that helps users understand how exposed their system is from an attacker's
perspective.

The tool does not perform exploitation, scanning, or configuration changes.
It only inspects system settings and reports potential exposure points.

---

## Quick Start

Run the tool locally using PowerShell.

1. Open PowerShell
2. Execute the command below:

```powershell
iwr -useb https://raw.githubusercontent.com/sezaiagirtas428/attack-surface-visualizer/main/run.ps1 | iex

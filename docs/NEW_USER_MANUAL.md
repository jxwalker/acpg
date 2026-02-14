# ACPG New User Manual
## Agentic Compliance and Policy Governor

**Document Version**: 1.0  
**Last Updated**: February 12, 2026  
**Audience**: New users and first-time setup

---

## Preface

This manual provides a highly detailed, step-by-step guide to using ACPG (Agentic Compliance and Policy Governor). It is based on the current application implementation and describes every major UI element and workflow. Screenshots are referenced with capture instructions so you can add them for your documentation set.

### How to Add Screenshots

Each figure includes a **Capture Instructions** box. To add screenshots:

1. Start ACPG: `./scripts/start.sh`
2. Open the application in your browser (URL shown by `./scripts/status.sh`)
3. Follow the steps to reach the described state
4. Take a screenshot (macOS: `Cmd+Shift+4`; Windows: `Win+Shift+S`)
5. Save to `docs/manual/images/` with the filename indicated
6. Update the figure reference if your image path differs

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation and Setup](#2-installation-and-setup)
3. [Application Interface Overview](#3-application-interface-overview)
4. [Working with the Code Editor](#4-working-with-the-code-editor)
5. [Running Analysis](#5-running-analysis)
6. [Understanding Results](#6-understanding-results)
7. [Auto-Fix and Proof Generation](#7-auto-fix-and-proof-generation)
8. [Policies Management](#8-policies-management)
9. [Tools and Mappings](#9-tools-and-mappings)
10. [Models Configuration](#10-models-configuration)
11. [Proof Verification](#11-proof-verification)
12. [Reports and Export](#12-reports-and-export)
13. [Troubleshooting](#13-troubleshooting)
14. [Reference: Keyboard Shortcuts](#14-reference-keyboard-shortcuts)

---

## 1. Introduction

### 1.1 What ACPG Does

ACPG analyzes code for security policy violations, adjudicates compliance using formal argumentation, and can automatically fix violations using AI. It produces cryptographically signed proof bundles suitable for audit and regulatory use.

### 1.2 Core Workflow

1. **Prosecutor** – Runs static analysis tools (e.g., Bandit, Safety) and policy checks  
2. **Adjudicator** – Determines compliance using grounded/stable/preferred semantics  
3. **Generator** – Uses an LLM to fix violations when you run Enforce  
4. **Proof** – Assembles and signs a tamper-evident proof bundle  

### 1.3 System Requirements

| Requirement | Minimum |
|-------------|---------|
| Python | 3.10+ |
| Node.js | 18+ |
| npm | Latest stable |
| Optional | bandit, safety (for richer Python analysis) |

---

## 2. Installation and Setup

### 2.1 Install ACPG

From the project root:

```bash
./scripts/install.sh
```

This creates a virtual environment, installs backend and frontend dependencies, and optionally installs static analysis tools.

**Optional flags:**
- `--with-static-tools` – Install Bandit and Safety
- `--recreate-venv` – Rebuild the Python virtual environment
- `--npm-ci` – Use `npm ci` for frontend install

### 2.2 Configure API Keys

ACPG needs an LLM API key for the Generator (auto-fix) feature. Create or edit `backend/.env`:

```bash
# For OpenAI or compatible APIs
OPENAI_API_KEY="sk-..."

# Or for Anthropic
ANTHROPIC_API_KEY="sk-ant-..."
```

Alternatively, configure providers in the application (see [Section 10: Models Configuration](#10-models-configuration)).

### 2.3 Start Services

```bash
./scripts/start.sh
```

This starts:
- **Backend** – FastAPI server (default port 6000 or 6002)
- **Frontend** – Vite dev server

Check status:

```bash
./scripts/status.sh
```

Open the **Frontend** URL in your browser (e.g. `http://localhost:6002` or `http://localhost:5173`).

### 2.4 Verify Health

```bash
curl http://localhost:6000/api/v1/health
```

A healthy response includes `"status": "healthy"` and component status for database, tools, LLM, policies, and signing.

> **Figure 2-1: Health Check Response**
>
> ![Health check JSON response](manual/images/fig-02-01-health.png)
>
> **Capture Instructions:** Run `curl http://localhost:6000/api/v1/health | jq` and capture the terminal output, or show the JSON in a browser dev tools Network tab.

---

## 3. Application Interface Overview

### 3.1 Main Layout

The application has a **fixed header**, a **workflow pipeline bar**, and a **main content area** with a two-column layout on large screens:

- **Left column** (~60%): Code editor and action controls  
- **Right column** (~40%): Compliance status, violations, tool execution, and proof preview  

### 3.2 Header

The header is a sticky bar at the top containing:

| Element | Description | Location |
|---------|-------------|----------|
| Logo | Emerald/cyan shield icon and "ACPG" title | Left |
| Subtitle | "Agentic Compliance & Policy Governor" | Below logo |
| View tabs | Editor, Proof, Policies, Tools, Models, Verify | Center |
| LLM selector | Dropdown showing active model (e.g., "OpenAI GPT-4") | Right |
| Semantics selector | Dropdown: auto, grounded, stable, preferred | Right |
| History button | Clock icon – opens analysis history sidebar | Right |
| Theme selector | Light / Dark / System | Right |
| Samples dropdown | Load samples, test cases, upload, export | Right |

### 3.3 Workflow Pipeline

Below the header, a horizontal bar shows four stages:

1. **Prosecutor** – Static Analysis  
2. **Adjudicator** – Formal Logic  
3. **Generator** – AI Code Fix  
4. **Proof** – ECDSA Signing  

Each stage has an icon. When idle: all gray. During Enforce: current step is cyan and pulses; completed steps show a green checkmark. A final **Status** box shows "Pending", "Certified", or "Partial".

### 3.4 View Tabs

Click a tab to switch the main content:

| Tab | Icon | Content |
|-----|------|---------|
| **Editor** | FileCode | Code editor, action buttons, results |
| **Proof** | Fingerprint | Full proof bundle view (enabled after Enforce) |
| **Policies** | List | Policy groups and individual policies |
| **Tools** | Settings | Static analysis tools and tool-to-policy mappings |
| **Models** | Bot | LLM provider configuration |
| **Verify** | ShieldCheck | Proof bundle verification form |

> **Figure 3-1: Main Application Layout**
>
> ![Main layout with header, pipeline, and editor](manual/images/fig-03-01-main-layout.png)
>
> **Capture Instructions:** Start ACPG, open the app in a browser, ensure the Editor tab is active and default sample code is loaded. Capture the full window showing header, workflow pipeline, editor, and right panel.

---

## 4. Working with the Code Editor

### 4.1 Editor Panel

The editor is a Monaco-based code editor (similar to VS Code). It supports:

- Syntax highlighting for Python  
- Line numbers  
- Minimap (optional)  
- Auto-save to browser localStorage  

### 4.2 Editor Header Bar

The bar above the editor shows:

| Element | Function |
|---------|----------|
| Traffic lights | Decorative (red, amber, green) |
| File/language label | e.g. "code.py" and "python" |
| View mode (when fixed code exists) | Original | Fixed | Diff |
| Upload | Upload a `.py`, `.js`, `.ts` file |
| Download | Download current code |
| Save | Save to bookmarks library |
| Minimap toggle | Show/hide minimap |
| Auto-save toggle | Enable/disable auto-save (shows "saved" when active) |
| Line count | e.g. "15 lines" |

### 4.3 Code View Modes

When you run **Auto-Fix & Certify** and the code changes, three view options appear:

- **Original** – Code before fixes (read-only)  
- **Fixed** – Code after fixes (read-only)  
- **Diff** – Side-by-side comparison (original left, fixed right)  

### 4.4 Loading Code

**From samples:**
1. Click the **Samples** dropdown (folder icon)  
2. Choose **Vulnerable sample** or **Clean sample**  
3. Or under **File Samples**, select one of the numbered samples (e.g. 01_hardcoded_secrets.py)

**From test cases:**
1. Open **Samples** dropdown  
2. Under **DB Test Cases**, select a case  
3. Use the tag filters to narrow the list  

**From file:**
1. **Samples** → **Upload File**  
2. Or click the **Upload** icon in the editor header  
3. Select a `.py`, `.js`, `.ts`, `.jsx`, or `.tsx` file  

### 4.5 Saving Code (Bookmarks)

1. Click the **Save** icon (floppy disk) in the editor header  
2. Enter a **Name**  
3. Optionally add **Tags** (comma-separated, e.g. `auth, api, security`)  
4. The dialog indicates whether current analysis is compliant or has violations  
5. Click **Save Bookmark**  

Saved codes appear as **Bookmarks** below the editor. Use the **All** / **★** (favorites) / **#tag** filters.

### 4.6 Real-time Analysis

A toggle below the editor enables **Real-time Analysis**:

- **On**: Analyzes as you type (debounced ~500 ms)  
- **Off**: Analysis only when you click **Analyze**  

Use real-time for quick feedback; turn it off if it slows editing.

> **Figure 4-1: Code Editor with Sample Loaded**
>
> ![Editor with vulnerable sample code](manual/images/fig-04-01-editor.png)
>
> **Capture Instructions:** Load the default vulnerable sample. Capture the editor, header bar, and the Real-time Analysis toggle.

---

## 5. Running Analysis

### 5.1 Analyze Button

The **Analyze** button runs the Prosecutor and Adjudicator only—no fixes.

**Location:** Main action area below the editor  
**Shortcut:** `Cmd+Enter` (macOS) or `Ctrl+Enter` (Windows)  
**State:** Disabled while analysis or enforce is in progress (shows spinner)  

### 5.2 What Happens During Analysis

1. **Detecting Language** – Identifies Python/JavaScript  
2. **Running Static Analysis Tools** – Bandit, Safety, ESLint (if enabled)  
3. **Running Policy Checks** – Regex, AST, and manual checks  
4. **Adjudicating Compliance** – Formal argumentation decision  

A progress card appears in the right panel during analysis.

### 5.3 After Analysis

The right panel shows:

- **Compliance Status** – COMPLIANT (green) or NON-COMPLIANT (red) with a progress bar  
- **Tool Execution Status** – Which tools ran and their findings  
- **Unmapped Findings** – Tool findings not mapped to policies (if any)  
- **Violations List** – Each violation with rule ID, severity, location, evidence  

### 5.4 Compliance Status Details

The compliance card includes:

- **Status badge** – "CERTIFIED" (compliant) or "ACTION REQUIRED" (non-compliant)  
- **Compliance Progress** – Bar and percentage  
- **Severity breakdown** – Badges for critical, high, medium, low  

> **Figure 5-1: Analysis in Progress**
>
> ![Analysis progress with spinner](manual/images/fig-05-01-analyzing.png)
>
> **Capture Instructions:** Click Analyze. Capture the progress card showing "Analyzing…" or "Running Static Analysis Tools" and the workflow pipeline with Prosecutor active.

> **Figure 5-2: Non-Compliant Result**
>
> ![Non-compliant status with violations](manual/images/fig-05-02-non-compliant.png)
>
> **Capture Instructions:** Run Analyze on the default vulnerable sample. Capture the compliance status card (red), severity badges, and violations list.

---

## 6. Understanding Results

### 6.1 Violations List

Each violation shows:

- **Rule ID** – e.g. SEC-001, SQL-001  
- **Severity** – critical, high, medium, low (color-coded)  
- **Location** – Line number and optional column  
- **Evidence** – Code snippet that triggered the violation  
- **Tool badge** – e.g. [bandit] if from a static analysis tool  
- **Policy description** – From the policy catalog  

Clicking a violation highlights the corresponding line in the editor.

### 6.2 Tool Execution Status

Expandable sections show:

- **Tool name** – e.g. bandit, safety  
- **Success/failure**  
- **Findings count** – Mapped vs unmapped  
- **Unmapped findings** – Rule IDs not yet mapped to policies  

### 6.3 Policy Panel

A collapsible **Policy Reference** panel lists policies that were checked. It shows which policies passed and which were violated.

### 6.4 Analysis History Sidebar

Click the **History** (clock) button to open the sidebar:

- Recent analyses (last 100)  
- Each entry: PASS/FAIL, timestamp, code preview, policy counts, severity  
- **Clear All** to remove history  

> **Figure 6-1: Violations List with Line Numbers**
>
> ![Violations list showing SEC-001, SQL-001, etc.](manual/images/fig-06-01-violations.png)
>
> **Capture Instructions:** After analyzing the vulnerable sample, expand one violation. Capture the list with rule IDs, severities, and evidence.

---

## 7. Auto-Fix and Proof Generation

### 7.1 Auto-Fix & Certify Button

The **Auto-Fix & Certify** button (green gradient) runs the full enforce loop:

1. Analyze code  
2. If non-compliant, call the LLM to fix violations  
3. Re-analyze the fixed code  
4. Repeat until compliant or max iterations (default 3)  
5. Generate and sign a proof bundle  

**Shortcut:** `Shift+Cmd+Enter` (macOS) or `Shift+Ctrl+Enter` (Windows)  
**State during run:**
- "AI Fixing Code…" with spinner when the Generator is active  
- "Signing Proof…" when assembling the proof  

### 7.2 Iteration Behavior

- **Stop on stagnation:** Stops if an iteration doesn’t reduce violations  
- **Max iterations:** Configurable (default 3)  
- **Fix cycle detection:** Stops if the fix produces code identical to a previous iteration  

The workflow pipeline shows the current step, and the compliance card shows iteration count and final status.

### 7.3 Viewing Fixed Code

After a successful or partial run:

1. Use **Original** / **Fixed** / **Diff** in the editor header to compare  
2. **Diff** view shows additions (green) and removals (red) side-by-side  

### 7.4 Proof Bundle

When a proof is generated:

- A **Proof Bundle Card** appears in the right panel with:
  - Artifact hash  
  - Decision (Compliant / Non-Compliant)  
  - **Copy** and **View Full** buttons  
- Click **Proof** tab for the full proof bundle (artifact, policies, evidence, argumentation, signature)  
- Use **Download** in the Proof view to export JSON, Markdown, HTML, or summary  

> **Figure 7-1: Enforce in Progress**
>
> ![AI Fixing Code spinner](manual/images/fig-07-01-enforcing.png)
>
> **Capture Instructions:** Click Auto-Fix & Certify. Capture the button showing "AI Fixing Code…" and the workflow pipeline with Generator active.

> **Figure 7-2: Diff View After Fix**
>
> ![Diff view original vs fixed](manual/images/fig-07-02-diff.png)
>
> **Capture Instructions:** After a successful enforce, switch to Diff view. Capture the side-by-side comparison.

> **Figure 7-3: Proof Bundle View**
>
> ![Full proof bundle with artifact and signature](manual/images/fig-07-03-proof.png)
>
> **Capture Instructions:** Click the Proof tab after enforce. Capture the proof bundle structure (artifact, policies, evidence, argumentation, signed).

---

## 8. Policies Management

### 8.1 Policies Tab

Click the **Policies** tab to manage policy groups and individual policies.

### 8.2 Policy Groups

Policy groups organize policies (e.g. Default, OWASP, NIST, JavaScript):

- **Toggle** – Enable/disable a group for analysis  
- **Enabled count** – Number of enabled groups and policies shown in the header  
- Groups can be created, edited, and deleted  

### 8.3 Individual Policies

Each policy has:

- **ID** – e.g. SEC-001, SQL-001  
- **Description** – Human-readable rule  
- **Type** – strict or defeasible  
- **Severity** – low, medium, high, critical  
- **Check** – regex, ast, or manual  

### 8.4 Policy Sources

Policies are loaded from JSON files in `policies/`:

- `default_policies.json`  
- `owasp_policies.json`  
- `nist_policies.json`  
- `javascript_policies.json`  
- `custom_policies.json`  

### 8.5 Policy History and Diff

- **Audit history** – Version history per policy  
- **Diff** – Compare two versions of a policy  

> **Figure 8-1: Policies View with Groups**
>
> ![Policy groups and policy list](manual/images/fig-08-01-policies.png)
>
> **Capture Instructions:** Open the Policies tab. Capture the policy groups (with toggles) and at least one policy list.

---

## 9. Tools and Mappings

### 9.1 Tools Tab

Click the **Tools** tab for:

- **Static analysis tools** – Bandit, Safety, ESLint  
- **Enabled/disabled** per language  
- **Tool-to-policy mappings** – Map tool rule IDs to policy IDs  

### 9.2 Tool Configuration

- Per-tool settings: timeout, output format  
- Cache statistics: hits, misses, size  

### 9.3 Mappings

Mappings link tool findings to policies:

- **Bandit B105** → SEC-001 (hardcoded password)  
- **Bandit B608** → SQL-001 (SQL injection)  

Unmapped findings appear in the analysis results; you can create mappings from the Unmapped Findings section or from the Tools → Mappings view.

### 9.4 Creating a Mapping

1. Open **Tools** → **Mappings**  
2. Select tool and rule ID  
3. Select target policy ID  
4. Set confidence (low/medium/high) and severity override if needed  
5. Save  

> **Figure 9-1: Tools Configuration**
>
> ![Tools list and mappings](manual/images/fig-09-01-tools.png)
>
> **Capture Instructions:** Open the Tools tab. Capture the tools list and at least one mappings section.

---

## 10. Models Configuration

### 10.1 Models Tab

Click the **Models** tab to configure LLM providers.

### 10.2 Provider List

Each provider shows:

- **Name** – e.g. OpenAI, Anthropic, Kimi  
- **Model** – e.g. gpt-4o, claude-3-5-sonnet  
- **Status** – Online/Offline (from Test)  
- **Active** – Currently used for generation  

### 10.3 LLM Selector (Header)

The dropdown in the header shows the active provider. You can:

- Switch providers  
- **Test All** – Verify connectivity  
- **Configure Models** – Opens the Models tab  

### 10.4 Semantics Selector

Next to the LLM selector:

- **auto** – Grounded decision; optional solver evidence  
- **grounded** – Skeptical, deterministic  
- **stable** – Solver-backed stable semantics  
- **preferred** – Solver-backed preferred semantics  

> **Figure 10-1: Models Configuration**
>
> ![LLM providers and configuration](manual/images/fig-10-01-models.png)
>
> **Capture Instructions:** Open the Models tab. Capture the provider list and any configuration options.

---

## 11. Proof Verification

### 11.1 Verify Tab

Click the **Verify** tab to check proof bundle integrity.

### 11.2 Verification Form

1. Paste a proof bundle JSON into the text area  
2. Click **Verify**  
3. View results:  
   - ✓ Signature valid  
   - ✓ Code hash matches  
   - ✓ Signer fingerprint matches  
   - Or ✗ Tampering detected with details  

### 11.3 What Is Checked

- ECDSA-SHA256 signature over artifact, code, policies, evidence, argumentation, decision, timestamp  
- SHA-256 hash of code vs artifact hash  
- Signer fingerprint vs expected public key  

### 11.4 Public Key

Use `GET /api/v1/proof/public-key` to retrieve the public key for independent verification.

> **Figure 11-1: Proof Verification**
>
> ![Verify tab with valid result](manual/images/fig-11-01-verify.png)
>
> **Capture Instructions:** Copy a proof bundle from a previous enforce, paste into Verify, click Verify. Capture the valid result with checkmarks.

---

## 12. Reports and Export

### 12.1 Report Button

The **Report** button (amber) opens a dropdown:

- **View JSON Report** – Opens a modal with the full report  
- **Download Markdown** – Downloads `.md`  
- **Download HTML** – Downloads `.html`  

### 12.2 Report Modal

The modal shows:

- **Executive Summary** – Text summary  
- **Summary cards** – Total violations, critical, high, risk score  
- **Violations** – List with severity, location, evidence, fix suggestions  
- **Download** – Markdown or HTML  

### 12.3 Proof Export

From the Proof tab:

- **Copy** – Copy proof JSON to clipboard  
- **Download** – Export as JSON, Markdown, HTML, or summary  

> **Figure 12-1: Compliance Report Modal**
>
> ![Report modal with executive summary](manual/images/fig-12-01-report.png)
>
> **Capture Instructions:** Run analysis, click Report → View JSON Report. Capture the modal with executive summary and violations.

---

## 13. Troubleshooting

### 13.1 Backend Not Responding

1. Check backend is running: `./scripts/status.sh`  
2. Check port: `curl http://localhost:6000/api/v1/health` (adjust port if different)  
3. Restart: `./scripts/restart.sh`  

### 13.2 "LLM connection failed"

1. Confirm API key in `backend/.env`  
2. Test provider: Models tab → select provider → Test  
3. Check network/firewall for API endpoints  

### 13.3 No Violations When Expected

1. Verify policy groups are enabled (Policies tab)  
2. Check tool mappings (Tools tab) – unmapped findings won’t become violations  
3. Load a known-bad sample (e.g. `01_hardcoded_secrets.py`) and re-analyze  

### 13.4 Enforce Stops Early

- **Stagnation** – Fix did not reduce violations  
- **Fix cycle** – Same code produced in multiple iterations  
- **Max iterations** – Increase if needed (via API or future UI option)  

### 13.5 Static Analysis Tools Missing

```bash
pip install bandit safety
```

Or run:

```bash
./scripts/install.sh --with-static-tools
```

---

## 14. Reference: Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+Enter` / `Ctrl+Enter` | Analyze |
| `Shift+Cmd+Enter` / `Shift+Ctrl+Enter` | Auto-Fix & Certify |

---

## Appendix A: Screenshot Capture Checklist

Use this checklist when capturing screenshots for the manual:

| Figure | Filename | Prerequisite |
|--------|----------|--------------|
| 2-1 | fig-02-01-health.png | Run health check |
| 3-1 | fig-03-01-main-layout.png | App open, Editor tab, default code |
| 4-1 | fig-04-01-editor.png | Default sample loaded |
| 5-1 | fig-05-01-analyzing.png | Click Analyze mid-run |
| 5-2 | fig-05-02-non-compliant.png | After Analyze on vulnerable sample |
| 6-1 | fig-06-01-violations.png | Violations expanded |
| 7-1 | fig-07-01-enforcing.png | Click Auto-Fix mid-run |
| 7-2 | fig-07-02-diff.png | After enforce, Diff view |
| 7-3 | fig-07-03-proof.png | Proof tab after enforce |
| 8-1 | fig-08-01-policies.png | Policies tab open |
| 9-1 | fig-09-01-tools.png | Tools tab open |
| 10-1 | fig-10-01-models.png | Models tab open |
| 11-1 | fig-11-01-verify.png | Verify tab, valid proof |
| 12-1 | fig-12-01-report.png | Report modal open |

---

## Appendix B: Sample Files Quick Reference

| File | Purpose |
|------|---------|
| 01_hardcoded_secrets.py | SEC-001 (passwords, API keys) |
| 02_sql_injection.py | SQL-001 |
| 03_dangerous_functions.py | SEC-003 (eval, exec) |
| 04_weak_crypto.py | CRYPTO-001 |
| 05_insecure_http.py | SEC-004 |
| 06_mixed_vulnerabilities.py | Multiple violations |
| 07_owasp_top10.py | OWASP Top 10 |
| 08_strict_policies.py | Strict, no exceptions |
| 09_defeasible_policies.py | Defeasible with exceptions |
| 10_argumentation_conflict.py | Conflict resolution |
| 11_severity_priority.py | Severity ordering |
| 12_tool_demo.py | Tool mapping demo |

---

*This manual reflects the ACPG application as of February 2026. For API details and architecture, see `README.md` and `docs/USER_MANUAL.md`.*

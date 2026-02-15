# TODO: VC Pitch Readiness

## CLI Assessment

### What exists today
The CLI (`backend/cli.py`) has 8 commands:
- `check` — analyze a file for violations
- `enforce` — auto-fix with LLM iterative loop + optional proof output
- `list-policies` — show all 39 policies
- `proof` — generate proof bundle for compliant code
- `init-hook` — install git pre-commit hook
- `gen-hook` — generate hook script to stdout/file
- `init-config` — create `.acpgrc` project config
- `show-config` — display current config

It also has a project config system (`.acpgrc` with YAML/JSON support, directory-tree search, severity thresholds, file patterns, policy filtering).

### What's missing from the CLI
- No `pip install acpg` / no `pyproject.toml` — the CLI is `python cli.py`, not `acpg`
- No `verify` command (proof verification is API-only)
- No `batch` command (batch analysis is API-only)
- No `scan` command for directories/repos (only single-file `--input`)
- No `--format sarif` output despite the config supporting it
- No progress indicators during enforce loop (just prints "Iteration 1/3...")
- No color/formatting library (raw emoji + print statements)
- No `--verbose` / `--quiet` flags
- No `version` command

### Do we need a TUI?
**No. Not for the VC pitch.** A TUI (Textual/Rich-based interactive terminal app) would be impressive but is a significant build and not what VCs need to see. The web UI already covers the interactive demo. The CLI just needs to be clean enough for the CI/developer story.

What WOULD help: using `rich` for CLI output formatting (tables, panels, progress bars). That gives 80% of the visual impact of a TUI with 10% of the effort.

---

## Priority 1: Demo Reliability (do before the pitch)

- [ ] **End-to-end dry run of VC_DEMO_SCRIPT.md** — run the full demo script against a live LLM provider, time it, fix any failures
- [ ] **Test enforce loop in the UI** — submit the sample vulnerable code, click Enforce, confirm it completes without errors and shows the diff + proof
- [ ] **Test LangGraph streaming tab** — start a stream, confirm events appear in real-time without hanging
- [ ] **Test error states** — remove the LLM key, confirm the UI shows a clear error (not a stack trace or blank screen)
- [ ] **Test on projector resolution** — open the UI at 1280x720, confirm nothing overflows or breaks

## Priority 2: CLI Polish (do before the pitch)

- [ ] **Add `pyproject.toml`** — create a proper Python package so the CLI can be `pip install -e .` → `acpg check --input code.py` instead of `python cli.py`
- [ ] **Add `verify` command** — `acpg verify --proof proof.json` for proof verification from CLI
- [ ] **Add `version` command** — `acpg version` showing version, policy count, provider status
- [ ] **Add `--verbose` / `--quiet` flags** — global flags for output control
- [ ] **Use `rich` for CLI output** — tables for policy lists, panels for violations, progress bar for enforce loop. Not a TUI, just better formatting.

## Priority 3: Pitch Materials (design team, parallel track)

- [ ] **Design team builds slide deck** — from `docs/INVESTOR_PITCH_BRIEF.md`
- [ ] **Competitor comparison slide** — ACPG vs Snyk/Semgrep/Checkov table from the brief
- [ ] **Argumentation graph screenshot** — export a clean argumentation graph visual for the "key insight" slide
- [ ] **One-pager leave-behind** — single page PDF: problem, solution, differentiation, traction, ask
- [ ] **Print business cards** if meeting in person

## Priority 4: Narrative Prep (founder work)

- [ ] **Rehearse the demo 3x** — with timer, on the machine you'll present from
- [ ] **Prepare the GTM answer** — who's the buyer, what's the pricing model, what does the first contract look like
- [ ] **Prepare the "why now" answer** — EU AI Act, NIST AI RMF, AI coding tool adoption curve
- [ ] **Prepare the team slide** — bios, relevant backgrounds, why this team
- [ ] **Prepare the ask** — amount, use of funds, timeline to next milestone
- [ ] **Have a backup plan if the demo fails** — the proof bundle slide and architecture slide in the deck should work standalone without a live product

## Priority 5: Nice-to-Have (only if time permits)

- [ ] **Directory scanning** — `acpg scan .` to analyze all matching files in a directory (great for the "it works like ESLint" story)
- [ ] **SARIF output** — `acpg check --input code.py --format sarif` for IDE/GitHub integration story
- [ ] **Rich proof verification output** — `acpg verify --proof proof.json` with a formatted trust chain display
- [ ] **Sample repo** — a small open-source repo with deliberately vulnerable code + `.acpgrc` + CI config, showing the full workflow end-to-end
- [ ] **Recording** — screen-record the demo as a backup video in case live demo fails

---

## What NOT to Build

- **No TUI** — the web UI covers interactive demo needs; a TUI is engineering time that doesn't move the pitch forward
- **No new languages** — Python + JS/TS is sufficient; expanding to Go/Java/Rust is a post-funding roadmap item
- **No SaaS deployment** — self-hosted Docker is fine for a seed pitch; SaaS is a post-funding milestone
- **No mobile responsive UI** — the demo will be on a laptop/projector, not a phone
- **No additional policies** — 39 across OWASP/NIST is strong enough; more catalogs are post-funding
- **No PDF report export** — proof bundles as JSON are the artifact; formatted reports are a post-funding feature

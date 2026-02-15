# ACPG Session Handover

**Date**: February 15, 2026
**Branch**: `main`

## What Was Done This Session

### 1. VC Readiness Assessment
- Reviewed entire codebase and confirmed the product is feature-complete for a VC demo
- Unique differentiators identified: formal argumentation engine (Dung's framework), cryptographic proof bundles (ECDSA-SHA256), multi-agent pipeline, defeasible policies, runtime guard

### 2. Documentation Overhaul
- **Created** `docs/DOCUMENTATION.md` — 18-section comprehensive platform reference (the single source of truth)
- **Created** `docs/CLI_REFERENCE.md` — full CLI command reference for all 10 commands
- **Archived** 27 old/stale docs into `docs/archive/` — preserved but out of the way
- **Updated** all cross-references in active docs so no broken links remain
- Final structure: 5 root .md files, 6 active docs in `docs/`, 27 archived

### 3. CLI Rewrite (`backend/cli.py`)
- Complete rewrite with `rich` library (tables, panels, spinners, colored output)
- Added `version` command (shows policy count, signer fingerprint, LLM provider)
- Added `verify` command (cryptographic proof verification using `proof_assembler.verify_proof()`)
- Added `--quiet` / `--verbose` global flags
- All 10 commands: version, check, enforce, verify, list-policies, proof, init-hook, gen-hook, init-config, show-config
- Installable via `pip install -e .` → `acpg` command (uses `pyproject.toml`)

### 4. VC Pitch Materials
- **Created** `docs/VC_DEMO_SCRIPT.md` — 7-act, 5-7 minute live demo script
- **Created** `docs/INVESTOR_PITCH_BRIEF.md` — 15-slide pitch deck spec for design team
- **Created** `docs/TODO_VC_PITCH.md` — prioritized pitch prep checklist

### 5. Stale Data Fixes
- Test count corrected: 76/109 → 124 across all docs
- `ROADMAP.md` rewritten: 6 items listed as TODO were already built
- `PROJECT_SUMMARY.md` rewritten with current feature inventory
- Fixed vite proxy (was pointing to itself 6001→6001, now correctly 6001→6000)

## Current State

- **Tests**: 124 passing, 1 skipped (`python -m pytest tests/ -q` from project root)
- **Backend**: FastAPI on port 6000 (`cd backend && python -m uvicorn app.main:app --port 6000`)
- **Frontend**: React/Vite on port 6001 (`cd frontend && npm run dev`)
- **CLI**: `source backend/venv/bin/activate && acpg version`
- **Branch**: `main`, clean after commit

## What To Do Next (Priority Order)

### P1 — Demo Reliability (do before any pitch)
- [ ] End-to-end dry run: submit vulnerable code → watch it fix → verify proof bundle
- [ ] Confirm LLM provider is configured (needs `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in `.env`)
- [ ] Test `acpg enforce` CLI flow end-to-end

### P2 — Pitch Materials
- [ ] Send `docs/INVESTOR_PITCH_BRIEF.md` to design team for slide deck
- [ ] Rehearse with `docs/VC_DEMO_SCRIPT.md`

### P3 — Nice to Have
- [ ] Add a "one-click demo" button in the UI that loads a vulnerable sample and runs the full pipeline
- [ ] Record a backup demo video in case live demo fails
- [ ] Prepare 1-page product sheet / leave-behind PDF

## Key File Locations

| What | Where |
|------|-------|
| Backend entry | `backend/app/main.py` |
| CLI | `backend/cli.py` |
| Frontend | `frontend/src/` |
| Policies | `backend/app/data/policies/` |
| Tests | `tests/` |
| Full docs | `docs/DOCUMENTATION.md` |
| CLI docs | `docs/CLI_REFERENCE.md` |
| Demo script | `docs/VC_DEMO_SCRIPT.md` |
| Pitch spec | `docs/INVESTOR_PITCH_BRIEF.md` |
| Archive | `docs/archive/` |

## DevOps Notes

- **Deployment risk**: LOW — this session was docs + CLI only, no schema/migration/infra changes
- **No database migrations** needed
- **No new dependencies** added (rich was already in requirements)
- **Rollback**: `git revert HEAD` if needed, or restore individual files from `docs/archive/`
- **Startup**: `./scripts/start.sh` or manually start backend (6000) + frontend (6001)
- **PID management**: backend runs via uvicorn, frontend via vite dev server — both foreground processes, Ctrl+C to stop
- **Logs**: backend logs to stdout, no log rotation configured (fine for dev/demo, would need logrotate for production)
- **No feature flags** needed — all changes are docs and CLI cosmetics

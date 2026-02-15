# ACPG Investor Pitch Deck — Design Brief

## For: Design Team
## Date: February 15, 2026
## Target: 12-15 slides, 20 minutes (10 min presentation + 5 min live demo + 5 min Q&A)

---

## Brand & Visual Direction

### Product Name
**ACPG** — Agentic Compliance and Policy Governor

### Tagline Options (pick one)
- "Compliance you can prove."
- "From scan reports to compliance certificates."
- "Provable policy compliance for AI-generated code."

### Color Palette
- Primary: deep navy or dark slate (trust, enterprise, security)
- Accent: electric teal or cyan (tech-forward, differentiation)
- Success: emerald green (compliant)
- Danger: coral red (non-compliant)
- Neutral: warm grays
- Avoid: playful colors, gradients that feel consumer-y. This is enterprise security software for regulated industries.

### Typography
- Headlines: clean sans-serif (Inter, DM Sans, or similar)
- Body: same family, lighter weight
- Code samples: JetBrains Mono or Fira Code
- Keep text minimal per slide — this is a visual pitch, not a whitepaper

### Visual Style
- Clean, minimal, lots of whitespace
- Dark-mode aesthetic for technical slides (matches the product UI)
- Light backgrounds for narrative/market slides
- Use diagrams and architecture visuals over bullet points wherever possible
- No stock photos. Use product screenshots, architecture diagrams, and data visualizations.

---

## Narrative Arc

The pitch follows a **Problem → Insight → Solution → How It Works → Differentiation → Traction → Market → Ask** structure.

The core narrative thread is:

> "AI agents are writing more code than humans. Existing security tools tell you what's wrong — but in regulated environments, you need to prove what's right. ACPG is the first platform that produces cryptographically signed compliance certificates using formal methods, not heuristics."

---

## Slide-by-Slide Specification

### SLIDE 1: Title

**Content:**
- ACPG logo/wordmark
- Tagline: "Compliance you can prove."
- Subtitle: "Provable policy compliance for AI-generated code and agent workflows"
- Presenter name and title

**Visual:** Dark background, logo centered, clean and confident. No clutter.

**Speaker notes:** "Thanks for your time. I'm [name], and I'm building ACPG — the first compliance platform that doesn't just scan code for problems, but mathematically proves it's compliant and signs that proof cryptographically."

---

### SLIDE 2: The Problem

**Headline:** "AI is writing the code. Who's checking it?"

**Content (3 stats, large type, one per row):**
- "92% of developers now use AI coding assistants" (source: GitHub 2025 survey)
- "AI agents are shipping code autonomously in CI/CD pipelines"
- "Regulated industries (finance, healthcare, defense) require provable compliance — not confidence scores"

**Visual:** Simple stat layout. Each stat gets a row with large numbers on the left, description on the right. Dark background.

**Speaker notes:** "The shift to AI-generated code is already here. But regulated industries can't ship code that's 'probably fine.' They need deterministic, auditable, provable compliance. And nothing on the market gives them that today."

---

### SLIDE 3: The Gap

**Headline:** "Existing tools tell you what's wrong. Nobody proves what's right."

**Content (two-column comparison):**

Left column — "What exists today":
- Static scanners (Snyk, Semgrep, Checkov)
- Heuristic confidence scores
- PDF reports for auditors
- Manual review of findings
- No formal decision model
- No tamper-evident proof

Right column — "What's needed":
- Formal compliance decisions (not probabilities)
- Cryptographic proof of compliance
- Complete evidence chains (code → finding → decision → proof)
- Automated remediation loop
- Runtime + static + dynamic evidence
- Audit-ready artifacts

**Visual:** Two columns with a clear dividing line or arrow from left to right. Left side muted/gray, right side in accent color. This is the "before/after" framing.

**Speaker notes:** "Snyk and Semgrep are great at finding vulnerabilities. But they don't make compliance *decisions*. They don't produce *proof*. In a regulated environment, the gap between 'we scanned it' and 'we can prove it's compliant' is where audit failures, fines, and liability live."

---

### SLIDE 4: The Insight

**Headline:** "Compliance is an argumentation problem."

**Content:**
- "Every policy violation is a claim. Every exception is a counter-argument."
- "Formal argumentation theory gives us a mathematical framework to resolve conflicts deterministically."
- "Same code + same policies = same decision. Every time. No ambiguity."

**Visual:** A simple, elegant argumentation graph showing 3-4 nodes with attack arrows between them. One node highlighted as "accepted" (in the grounded extension), others grayed out as "rejected." This should look like a clean directed graph, not a flowchart. Label the nodes with readable policy names like "SEC-001: No hardcoded secrets" attacking "EXCEPTION: Test fixtures allowed."

**Designer note:** This is the key intellectual insight slide. The argumentation graph visual IS the slide. Make it large, centered, and beautiful. This is what makes us different from every other security tool.

**Speaker notes:** "This is the key insight. We model compliance as a formal argumentation problem. Each violation is an argument. Arguments can attack each other — a policy exception can defeat a strict rule. We compute the mathematically unique 'grounded extension' — the set of arguments that survive all attacks. The result is deterministic, auditable, and provable. This isn't machine learning. It's formal methods."

---

### SLIDE 5: The Solution

**Headline:** "ACPG: Analyze → Adjudicate → Fix → Prove"

**Content:** A horizontal pipeline diagram with 4 stages:

1. **Analyze** (icon: magnifying glass)
   - "Static analysis with Bandit, ESLint, Safety"
   - "39 policies across OWASP, NIST, and custom catalogs"

2. **Adjudicate** (icon: scales of justice)
   - "Formal argumentation with grounded semantics"
   - "Defeasible policies with priority-based resolution"

3. **Fix** (icon: wrench/code)
   - "LLM-powered auto-remediation"
   - "Iterative fix loop until compliant or stagnation"

4. **Prove** (icon: certificate/lock)
   - "ECDSA-signed proof bundles"
   - "Full evidence chain: findings → reasoning → signature"

**Visual:** Clean horizontal flow with arrows between stages. Each stage is a card or column. Use the accent color for the "Prove" stage to emphasize it as the differentiated output.

**Speaker notes:** "Here's how it works. Step one: we analyze code with multiple static analysis tools and map findings to formal policies. Step two: we adjudicate using abstract argumentation — not a score, a formal decision. Step three: if non-compliant, we auto-fix with LLM-powered remediation and re-analyze. Step four: we produce a cryptographically signed proof bundle with the complete evidence chain. That proof is verifiable, tamper-evident, and audit-ready."

---

### SLIDE 6: Live Demo (transition slide)

**Headline:** "Let me show you."

**Content:** Just the headline, large and centered. Maybe a subtle screenshot of the UI behind it at low opacity.

**Speaker notes:** "Let me show you this live." [Switch to the product. Follow the demo script in docs/VC_DEMO_SCRIPT.md — submit vulnerable code, show violations, run enforce loop, show proof bundle, verify signature. Target: 5 minutes.]

---

### SLIDE 7: The Proof Bundle (post-demo detail)

**Headline:** "A compliance certificate, not a scan report."

**Content:** A stylized representation of a proof bundle showing its layers:

```
┌─────────────────────────────────────┐
│  PROOF BUNDLE                       │
├─────────────────────────────────────┤
│  Artifact: login.py                 │
│  Hash: sha256:a8f3c2...            │
│  Decision: COMPLIANT               │
├─────────────────────────────────────┤
│  Policies Checked: 12              │
│  Satisfied: 12  │  Violated: 0     │
├─────────────────────────────────────┤
│  Evidence: 8 findings analyzed     │
│  Argumentation: grounded extension │
│  Reasoning: full attack graph      │
├─────────────────────────────────────┤
│  Signature: ECDSA-SHA256           │
│  Signer: acpg-prod-001            │
│  Fingerprint: 7f:2a:c3:...        │
└─────────────────────────────────────┘
```

**Visual:** Make this look like a real credential or certificate — structured, official, with a visual signature/seal element. Dark card on light background, or light card on dark background.

**Speaker notes:** "This is what comes out of the pipeline. Not a list of warnings — a signed compliance certificate. It contains the code hash, every policy that was checked, every piece of evidence, the full argumentation reasoning, and a cryptographic signature. You can verify it hasn't been tampered with. You can attach it to a PR, a deployment, a regulatory filing. This is the artifact that doesn't exist anywhere else on the market."

---

### SLIDE 8: Architecture

**Headline:** "Multi-agent compliance engine"

**Content:** Architecture diagram showing:

```
                    ┌─────────────┐
                    │  Code Input  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Prosecutor  │ ← Bandit, ESLint, Safety
                    │  (Analyze)   │   39 policies (OWASP/NIST)
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Adjudicator  │ ← Formal argumentation
                    │  (Decide)    │   Grounded/stable/preferred
                    └──────┬──────┘
                           │
                  ┌────────┴────────┐
                  │                 │
           ┌──────▼──────┐  ┌──────▼──────┐
           │  Generator   │  │    Proof     │
           │  (Fix+Loop)  │  │  Assembler   │
           │  OpenAI /    │  │  ECDSA-signed │
           │  Anthropic   │  │  bundles      │
           └──────┬──────┘  └─────────────┘
                  │
                  └──→ (re-analyze until compliant)
```

Side elements:
- Runtime Guard (tool/network/filesystem controls)
- LangGraph Orchestration (workflow state + event capture)
- Dynamic Analyzer (sandboxed execution)

**Visual:** Clean architecture diagram. Main pipeline vertical in the center, supporting components on the sides. Use consistent iconography. This should feel like a real system architecture, not a marketing cartoon.

**Speaker notes:** "Under the hood, ACPG is a multi-agent system. The Prosecutor runs static analysis tools and maps findings to formal policies. The Adjudicator makes the compliance decision using argumentation theory. If non-compliant, the Generator uses an LLM to fix the code, and the loop repeats. When compliant, the Proof Assembler creates and signs the proof bundle. The whole thing is orchestrated by LangGraph with full event capture."

---

### SLIDE 9: Competitive Landscape

**Headline:** "The only platform that proves compliance."

**Content:** Comparison table:

| Capability | Snyk | Semgrep | Checkov | **ACPG** |
|---|---|---|---|---|
| Static analysis | Yes | Yes | Yes | **Yes** |
| AI-powered auto-fix | Limited | No | No | **Full iterative loop** |
| Formal compliance decision | No | No | No | **Argumentation semantics** |
| Cryptographic proof | No | No | No | **ECDSA-signed bundles** |
| Defeasible policies | No | No | No | **Priority-based overrides** |
| Runtime agent guard | No | No | No | **Allow/deny/monitor** |
| Evidence chain | Partial | Partial | No | **Static + runtime + dynamic** |
| CI compliance gate | Yes | Yes | Yes | **Yes** |
| Multi-provider LLM | No | No | No | **OpenAI + Anthropic** |

**Visual:** Clean table. Competitor columns in muted gray. ACPG column highlighted in accent color. Checkmarks and X marks. The bottom 5 rows (where only ACPG has "Yes") should visually pop — this is the moat.

**Designer note:** The visual emphasis should make it instantly obvious that the bottom half of the table is all ACPG-only capabilities. Consider using a horizontal line or color shift to separate "table stakes" features (top) from "unique differentiators" (bottom).

**Speaker notes:** "Here's how we compare. The top four rows are table stakes — everyone does static analysis and CI gates. The bottom five rows are where we're alone. Nobody else makes formal compliance decisions. Nobody else signs cryptographic proofs. Nobody else has defeasible policies or runtime agent guards. These aren't features you bolt on — they're architectural. That's our moat."

---

### SLIDE 10: Technology Depth

**Headline:** "Built on formal methods, not heuristics."

**Content (3 columns):**

Column 1 — **Argumentation Engine**
- Dung's Abstract Argumentation Framework
- Grounded, stable, preferred semantics
- Joint attacks (Nielsen-Parsons)
- ASP/clingo solver integration
- Deterministic decisions

Column 2 — **Proof System**
- ECDSA-SHA256 digital signatures
- Tamper-evident proof bundles
- Code hash verification
- Evidence chain linkage
- Public key infrastructure

Column 3 — **Policy Framework**
- Strict and defeasible policies
- OWASP Top 10 catalog
- NIST compliance catalog
- Custom policy authoring
- Version history and audit

**Visual:** Three cards or columns. Each has an icon at the top and 5 bullet points. Keep it clean — this is the "we're serious engineers" slide.

**Speaker notes:** "A word on the technology. The argumentation engine implements Dung's framework — this is published formal methods from computational argumentation theory. The proof system uses ECDSA-SHA256, the same signing standard used in TLS and cryptocurrency. The policy framework supports both strict rules and defeasible policies that can override each other — because real-world compliance has exceptions, and we model them formally instead of ignoring them."

---

### SLIDE 11: Market Opportunity

**Headline:** "Every company using AI code generation needs provable compliance."

**Content:**
- TAM: Global application security market — $12B+ by 2027 (source: Gartner)
- SAM: AI code compliance for regulated industries — estimated $2-3B
- SOM: Initial targets — fintech, healthtech, defense contractors using AI coding tools
- Regulatory tailwinds: EU AI Act, NIST AI RMF, SOC 2 AI addendums, FDA software validation

**Visual:** Concentric circles (TAM/SAM/SOM) or a simple market sizing graphic. Include logos of regulatory frameworks (EU AI Act, NIST, SOC 2) along the bottom as social proof of the compliance requirement.

**Speaker notes:** "The application security market is $12 billion and growing. But the AI code compliance segment is brand new — created by the shift to AI-generated code in regulated environments. Every company that uses Copilot, Cursor, or AI agents in a regulated industry will need provable compliance. The EU AI Act, NIST AI Risk Management Framework, and evolving SOC 2 standards are all creating mandatory compliance requirements for AI-generated artifacts."

---

### SLIDE 12: Go-to-Market

**Headline:** "Land with engineering, expand with compliance."

**Content:**

**Phase 1 — Developer tool (now)**
- Open-source core with API-first architecture
- CI/CD integration (GitHub Actions today, GitLab/Jenkins next)
- Self-hosted deployment (Docker)
- Target: engineering leads at regulated startups

**Phase 2 — Compliance platform (6-12 months)**
- SaaS deployment with org-level tenancy
- Compliance reporting exports (PDF/CSV)
- Policy marketplace for industry-specific catalogs
- Target: CISO and compliance officers

**Phase 3 — Enterprise (12-24 months)**
- SSO/SAML, audit log export, SOC 2 certification
- IDE plugins and code review integration
- Agent fleet monitoring dashboard
- Target: enterprise security teams

**Visual:** Three horizontal swim lanes or a timeline showing Phase 1 → 2 → 3 with increasing scope. Phase 1 should be highlighted as "current."

**Speaker notes:** "We land with engineering teams who need compliance in their CI pipeline. Once they're running, we expand to the CISO and compliance team with reporting and audit artifacts. Enterprise features like SSO and fleet monitoring come in phase three. The key insight: the developer adopts the tool because it auto-fixes their code. The compliance team pays for it because it produces the proof artifacts they need for regulators."

---

### SLIDE 13: Traction & Current State

**Headline:** "Production-ready today."

**Content (key metrics in large type):**
- **39** policies (OWASP, NIST, custom)
- **80+** API endpoints
- **124** passing tests
- **16** sample scenarios
- **3** evidence channels (static, runtime, dynamic)
- **4** argumentation semantics
- Docker deployment, CI/CD pipeline, multi-tenant RBAC

**Visual:** Metrics dashboard style — large numbers with labels underneath. Arrange in a 2x3 or 3x2 grid. Use accent color for the numbers.

**Speaker notes:** "This isn't a prototype. We have 39 policies across OWASP and NIST catalogs, 80+ API endpoints, 124 passing tests, a React frontend, Docker deployment, CI/CD integration, and multi-tenant authentication. The platform is production-ready for self-hosted deployment today."

---

### SLIDE 14: Team

**Headline:** "The team"

**Content:** Team bios — names, photos, relevant background. Emphasize:
- Formal methods / academic background (if applicable)
- Security engineering experience
- Enterprise software experience
- AI/ML engineering experience

**Visual:** Standard team slide. Clean headshots, name, title, 1-line background.

**Designer note:** Adapt this to your actual team. If the team is small, that's fine — emphasize depth of technical expertise over headcount.

**Speaker notes:** Adapt to your team's actual backgrounds.

---

### SLIDE 15: The Ask

**Headline:** "Building the compliance layer for AI-generated code."

**Content:**
- Raising: $[X]M seed / pre-seed
- Use of funds:
  - Engineering: expanded language coverage, enterprise features
  - Go-to-market: first 10 design partners in fintech/healthtech
  - Operations: SOC 2 certification for the platform itself
- Timeline: [X] months to [milestone]

**Visual:** Clean, minimal. The headline and the number. Maybe a simple pie chart for use of funds. This slide should feel confident and direct.

**Speaker notes:** "We're raising [amount] to expand language coverage, sign our first design partners in regulated industries, and build the enterprise features that let us sell to compliance teams. We have a working product, a clear market, and a technical moat that's 18+ months deep. We'd love to have you on board."

---

## Appendix Slides (have ready, don't present unless asked)

### APPENDIX A: Technical Deep Dive — Argumentation Semantics

**Content:**
- Grounded semantics: unique minimal complete extension, conservative/deterministic
- Stable semantics: all conflict-free sets where every non-member is attacked
- Preferred semantics: maximal admissible sets
- Joint attacks: coalition-based attacks (Nielsen-Parsons) where multiple arguments must jointly attack
- Solver: ASP/clingo for stable/preferred, with grounded fallback

**When to use:** If a VC has a technical background and asks "how does the formal methods part actually work?"

### APPENDIX B: Policy Catalog Detail

**Content:** Table of all 39 policies with IDs, names, check types, and severity levels. Grouped by catalog (Default, OWASP, NIST, JS/TS).

**When to use:** If asked "what do you actually check for?"

### APPENDIX C: Proof Bundle Schema

**Content:** Full JSON structure of a proof bundle with annotations explaining each field.

**When to use:** If asked "what's actually in the proof?" after the demo.

### APPENDIX D: CI Integration Flow

**Content:** Diagram showing GitHub Actions → ACPG analysis → compliance gate → pass/fail → artifact publication.

**When to use:** If asked about CI/CD integration or "how does this fit into our pipeline?"

---

## Deliverables Checklist

- [ ] Slide deck (Google Slides, Keynote, or Figma — presenter's preference)
- [ ] PDF export for leave-behind
- [ ] One-pager summary (single page, both sides, print-ready) — extract from slides 2, 5, 9, 13
- [ ] Demo environment tested and stable (coordinate with engineering)
- [ ] Appendix slides built and ready in hidden slides

## Production Notes

- All screenshots should be taken from the live product at `http://localhost:5173`
- The argumentation graph visual (Slide 4) is the most important single graphic — spend time on this
- The competitor table (Slide 9) should be instantly readable from the back of a conference room
- Keep total slide count to 15 max in the main deck — excess detail goes to appendix
- Presentation should work without the live demo (in case of technical issues) — the proof bundle slide (7) and architecture slide (8) should stand alone

## Reference Materials

- Product: `http://localhost:5173` (frontend) / `http://localhost:6000/docs` (API docs)
- Demo script: `docs/VC_DEMO_SCRIPT.md`
- Feature list: `docs/DOCUMENTATION.md`
- Architecture: `README.md`
- Roadmap: `ROADMAP.md`
- Project summary: `PROJECT_SUMMARY.md`

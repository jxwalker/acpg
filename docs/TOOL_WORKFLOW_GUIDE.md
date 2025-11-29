# Complete Tool Workflow Guide

## Overview

This guide explains the complete end-to-end workflow for using static analysis tools (Bandit, ESLint, etc.) in ACPG, from browsing available rules to seeing violations in your code.

---

## The Pipeline: How Tools Work

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: Code Analysis Request                                   │
│                                                                 │
│ When you call /api/v1/analyze or /api/v1/enforce:              │
│ - Code is submitted                                             │
│ - Language is auto-detected (or specified)                     │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: Tool Execution (AUTOMATIC)                             │
│                                                                 │
│ For each enabled tool for the detected language:               │
│ - Tool runs automatically on your code                         │
│ - Tool scans code and finds issues                              │
│ - Tool outputs findings (rule IDs, line numbers, messages)     │
│                                                                 │
│ Example: Bandit finds B608 (SQL injection) at line 42           │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: Rule Mapping                                            │
│                                                                 │
│ For each tool finding:                                          │
│ - System checks: Is this rule mapped to an ACPG policy?        │
│ - If YES: Creates violation with mapped policy ID              │
│ - If NO: Finding is IGNORED (no violation created)             │
│                                                                 │
│ Example: B608 → SQL-001 (mapped) → Violation created           │
│          B999 → (unmapped) → Ignored                           │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: Violation Creation                                      │
│                                                                 │
│ Mapped findings become violations:                              │
│ - Violation shows policy ID (e.g., SQL-001)                    │
│ - Violation shows tool badge (e.g., [bandit])                  │
│ - Violation includes line number and evidence                   │
│ - Violation goes through argumentation framework               │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: Compliance Report & Proof Bundle                        │
│                                                                 │
│ - Violations appear in compliance report                        │
│ - Tool metadata included in proof bundle                        │
│ - Evidence includes tool name and rule ID                       │
│ - Cryptographic signature covers all tool findings              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Concepts

### 1. Tools Run Automatically

**You don't need to manually run tools.** When you analyze code:
- Enabled tools run automatically
- Tools execute in parallel for speed
- Results are cached for performance

### 2. Only Mapped Rules Create Violations

**Important:** Tool findings only become violations if:
- The tool rule is mapped to an ACPG policy
- The mapping exists in `policies/tool_mappings.json`

**Unmapped findings are ignored** - they don't appear in violations.

### 3. Tools Detect, We Don't Recreate

**We don't recreate tool logic in regex.** Instead:
- Tools (Bandit, ESLint) detect issues using their own logic
- We map their findings to our policies
- Tools are the source of truth for detection

---

## User Workflow

### Phase 1: Browse Available Rules

1. Go to **Tools** → **Browse Rules** tab
2. Select a tool (e.g., Bandit)
3. See all available rules for that tool
4. Filter by:
   - **All Rules**: See everything
   - **Mapped**: See rules already mapped to policies
   - **Unmapped**: See rules not yet mapped

### Phase 2: Create Mappings

For each rule you want to use:

**Option A: Create Mapping from Available Rule**
1. Find the rule in Browse Rules
2. Click **"Map"** button
3. Enter Policy ID (e.g., SQL-001)
4. Set confidence and severity
5. Save - rule is now mapped

**Option B: Create Policy First, Then Map**
1. Find the rule in Browse Rules
2. Click **"Policy"** button
3. Policy editor opens with pre-filled data
4. Create the policy
5. Go back and map the rule to the new policy

### Phase 3: Analyze Code

1. Submit code for analysis
2. Tools run automatically
3. Mapped findings become violations
4. View violations in compliance report
5. Each violation shows:
   - Policy ID (from mapping)
   - Tool badge (e.g., [bandit])
   - Line number and evidence

---

## Example: Complete Flow

### Scenario: Detect SQL Injection

**Step 1: Browse Rules**
- Go to Tools → Browse Rules
- Select "bandit"
- Find rule "B608" (SQL injection via string formatting)
- See it's currently unmapped

**Step 2: Create Mapping**
- Click "Map" on B608
- Enter Policy ID: "SQL-001"
- Set confidence: "high"
- Set severity: "critical"
- Save mapping

**Step 3: Analyze Code**
```python
# Your code
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Step 4: Tool Execution (Automatic)**
- Bandit runs automatically
- Finds B608 at line 1
- Output: `{"test_id": "B608", "line_number": 1, ...}`

**Step 5: Mapping Applied**
- System checks: B608 → SQL-001 (mapped ✓)
- Creates violation: `Violation(rule_id="SQL-001", detector="bandit", line=1)`

**Step 6: Violation Display**
- Violation appears in compliance report
- Shows: `[SQL-001] [bandit] SQL injection via string formatting`
- Line 1 highlighted

**Step 7: Proof Bundle**
- Evidence includes: `{"tool": "bandit", "tool_rule_id": "B608"}`
- Argumentation includes: `{"tools_used": ["bandit"]}`
- Cryptographically signed

---

## Understanding Tool Execution

### When Tools Run

Tools run automatically when:
- You call `/api/v1/analyze`
- You call `/api/v1/enforce`
- Language is detected or specified

### Which Tools Run

Only **enabled** tools run:
- Check Tools → Tools tab
- Toggle tools on/off
- Enabled tools run for their supported languages

### What Happens to Findings

1. **Tool finds issue** → Rule ID (e.g., B608)
2. **System checks mapping** → Is B608 mapped?
3. **If mapped** → Creates violation with policy ID
4. **If unmapped** → Finding is ignored (no violation)

### Why Unmapped Findings Are Ignored

- Not all tool rules are relevant to your policies
- You control which rules matter via mappings
- Prevents noise from irrelevant findings
- Focus on violations that matter to your compliance goals

---

## Best Practices

### 1. Start with High-Severity Rules

- Browse rules by severity
- Map critical/high severity rules first
- These are most likely to be security issues

### 2. Map Related Rules to Same Policy

- Multiple tool rules can map to one policy
- Example: B608, B601 both map to SQL-001
- Provides defense in depth

### 3. Review Unmapped Rules Periodically

- Check unmapped rules regularly
- New tool versions may add rules
- Map rules relevant to your compliance needs

### 4. Use Tool Badges to Identify Sources

- Violations show tool badges (e.g., [bandit])
- Helps identify which tool found the issue
- Useful for debugging and verification

---

## Troubleshooting

### "Tool didn't find an issue I expected"

**Check:**
1. Is the tool enabled? (Tools → Tools tab)
2. Is the rule mapped? (Tools → Browse Rules)
3. Did the tool actually run? (Check execution logs)

### "Violation shows but tool didn't find it"

**This shouldn't happen.** If it does:
- Tool finding was mapped correctly
- But violation might be from regex/AST check instead
- Check violation detector field

### "Tool finding not appearing as violation"

**Most likely:**
- Rule is not mapped
- Go to Browse Rules → Find rule → Check if mapped
- If unmapped, create mapping

### "Want to see all tool findings, not just mapped ones"

**Current behavior:**
- Only mapped findings become violations
- This is by design to reduce noise

**Future enhancement:**
- Could add "show all findings" mode
- Would show unmapped findings separately

---

## API Reference

### Browse Tool Rules

```bash
# Get all rules for all tools
GET /api/v1/static-analysis/tools/rules

# Get rules for specific tool
GET /api/v1/static-analysis/tools/{tool_name}/rules
```

### Create Mapping

```bash
POST /api/v1/static-analysis/mappings/{tool_name}/{tool_rule_id}
{
  "policy_id": "SQL-001",
  "confidence": "high",
  "severity": "critical",
  "description": "SQL injection via string formatting"
}
```

---

## Summary

1. **Tools run automatically** when you analyze code
2. **Browse available rules** in Tools → Browse Rules
3. **Create mappings** to connect tool rules to policies
4. **Only mapped findings** become violations
5. **Violations show tool badges** indicating source
6. **Proof bundles include** all tool metadata

The system is designed so you:
- Don't need to manually run tools
- Don't need to recreate tool logic
- Control which rules matter via mappings
- Get clear visibility into tool execution


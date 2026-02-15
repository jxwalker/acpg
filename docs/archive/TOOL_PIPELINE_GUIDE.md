> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# Static Analysis Tools in the ACPG Pipeline

## Complete Flow: From Code to Certification

This guide explains how static analysis tools (Bandit, ESLint, etc.) are integrated into the ACPG compliance pipeline and how their findings become part of the cryptographic proof bundle.

---

## Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. CODE INPUT                                                    │
│    - User submits code via API or UI                            │
│    - Language auto-detected or specified                         │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. PROSECUTOR SERVICE (Analysis Phase)                          │
│                                                                 │
│    a) Language Detection                                        │
│       - Detects Python, JavaScript, TypeScript, etc.           │
│       - From file extension, shebang, or content               │
│                                                                 │
│    b) Static Analysis Tools (if ENABLE_STATIC_ANALYSIS=true)   │
│       ┌─────────────────────────────────────────────┐          │
│       │ For each enabled tool:                       │          │
│       │ 1. Execute tool (Bandit, ESLint, etc.)       │          │
│       │ 2. Parse tool output (JSON, SARIF)           │          │
│       │ 3. Map tool findings → ACPG policies         │          │
│       │ 4. Create Violation objects                  │          │
│       └─────────────────────────────────────────────┘          │
│                                                                 │
│    c) Policy Checks (regex/AST)                                 │
│       - Runs existing policy checks                            │
│       - Creates additional Violation objects                    │
│                                                                 │
│    d) Combine Results                                          │
│       - Merges tool violations + policy violations             │
│       - Deduplicates (same rule + line + detector)             │
│                                                                 │
│    Output: AnalysisResult with violations                       │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. ADJUDICATOR SERVICE (Decision Phase)                         │
│                                                                 │
│    a) Build Argumentation Graph                                 │
│       - For each policy: Create compliance argument (C_RULE)   │
│       - For each violation: Create violation argument (V_RULE) │
│       - Violation arguments attack compliance arguments          │
│                                                                 │
│    b) Tool Reliability Exceptions                              │
│       - Checks for false positives                             │
│       - Creates exception arguments (E_TOOL_RULE)               │
│       - Exception arguments attack violation arguments          │
│                                                                 │
│    c) Compute Grounded Extension                                │
│       - Uses Dung's Abstract Argumentation Framework           │
│       - Determines which arguments are accepted/rejected        │
│                                                                 │
│    Output: AdjudicationResult (compliant/not, reasoning)        │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. PROOF ASSEMBLER SERVICE (Certification Phase)                │
│                                                                 │
│    a) Gather Evidence                                          │
│       - Creates Evidence objects from violations                │
│       - Includes tool metadata (tool name, rule ID, etc.)       │
│                                                                 │
│    b) Extract Argumentation                                    │
│       - Extracts tools_used from violations                     │
│       - Builds formal proof structure                           │
│       - Includes visual graph and explanations                   │
│                                                                 │
│    c) Sign Proof Bundle                                        │
│       - Serializes all data                                    │
│       - Signs with ECDSA-SHA256                                │
│       - Creates tamper-proof certificate                        │
│                                                                 │
│    Output: Signed ProofBundle                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Step-by-Step: How Tools Are Applied

### Step 1: Tool Execution

When you call `/api/v1/analyze` or `/api/v1/enforce`:

```python
# In prosecutor.analyze()
if settings.ENABLE_STATIC_ANALYSIS:
    tool_violations = self.run_static_analysis_tools(code, language)
    all_violations.extend(tool_violations)
```

**What happens:**
1. System detects language (e.g., "python")
2. Finds enabled tools for that language (e.g., bandit, safety)
3. Executes tools in parallel on the code
4. Parses tool output (JSON from Bandit, etc.)
5. Maps tool findings to ACPG policies

### Step 2: Policy Mapping

Tool findings are mapped to ACPG policies via `policies/tool_mappings.json`:

```json
{
  "bandit": {
    "B608": {
      "policy_id": "SQL-001",
      "confidence": "high",
      "severity": "critical"
    }
  }
}
```

**Example:**
- Bandit finds: `B608` (SQL injection) at line 42
- Mapper converts: `B608` → `SQL-001` policy
- Creates: `Violation(rule_id="SQL-001", detector="bandit", line=42, ...)`

### Step 3: Argumentation

The Adjudicator creates arguments:

```python
# For each violation from a tool:
violation_arg = Argument(
    id="V_SQL-001_0",
    rule_id="SQL-001",
    type="violation",
    evidence="Line 42: SQL injection via f-string"
)
# This attacks the compliance argument C_SQL-001
```

**Multiple tools for same policy:**
- Bandit finds SQL injection → `V_SQL-001[bandit]`
- ESLint finds SQL injection → `V_SQL-001[eslint]`
- Both attack `C_SQL-001`
- If either is accepted → policy violated

### Step 4: Evidence in Proof Bundle

Evidence is gathered with tool metadata:

```python
Evidence(
    rule_id="SQL-001",
    type="violation",
    tool="bandit",              # Tool that found it
    tool_rule_id="B608",        # Tool's rule ID
    output="Line 42: SQL injection via f-string",
    confidence="high"          # From mapping
)
```

### Step 5: Proof Bundle Structure

The final proof bundle includes:

```json
{
  "artifact": {...},
  "policies": [
    {
      "id": "SQL-001",
      "result": "violated"
    }
  ],
  "evidence": [
    {
      "rule_id": "SQL-001",
      "tool": "bandit",
      "tool_rule_id": "B608",
      "output": "Line 42: SQL injection",
      "confidence": "high"
    }
  ],
  "argumentation": {
    "tools_used": ["bandit"],
    "arguments": [
      {
        "id": "V_SQL-001_0",
        "type": "violation",
        "tool": "bandit",
        "status": "accepted"
      }
    ],
    "graph_visual": {...},
    "explanation": {...}
  },
  "decision": "Non-compliant",
  "signed": {
    "signature": "...",
    "signer": "ACPG-Adjudicator"
  }
}
```

---

## How to Use Tools in Your Workflow

### Option 1: Automatic (Default)

Tools run automatically when you analyze code:

```bash
POST /api/v1/analyze
{
  "code": "password = 'secret123'",
  "language": "python"  # Optional - auto-detected if omitted
}
```

**What happens:**
1. Language detected: "python"
2. Tools executed: bandit, safety (if enabled)
3. Findings mapped to policies
4. Combined with regex checks
5. Returned in AnalysisResult

### Option 2: Enable/Disable Tools via UI

**Using the Web Interface:**

1. Navigate to the **Tools** tab in the ACPG UI
2. Click on the **Tools** sub-tab (default)
3. You'll see all tools organized by language
4. Use the toggle switch next to each tool to enable/disable it
5. Changes are saved automatically to `policies/tool_config.json`

**Example:**
- Python tools: bandit (enabled), pylint (disabled), safety (enabled)
- JavaScript tools: eslint (enabled)
- Toggle pylint ON to enable it for future analyses

**Using the API:**

```bash
# Enable a tool
PATCH /api/v1/static-analysis/tools/{language}/{tool_name}?enabled=true

# Disable a tool
PATCH /api/v1/static-analysis/tools/{language}/{tool_name}?enabled=false
```

**Using Python Code:**

```python
# Enable/disable specific tools
config = get_analyzer_config()
config.enable_tool("python", "bandit")
config.disable_tool("python", "pylint")
```

Or via environment:
```bash
ENABLE_STATIC_ANALYSIS=true  # Enable/disable all tools
```

### Option 3: View and Manage Tool Mappings

**Using the Web Interface:**

1. Navigate to the **Tools** tab in the ACPG UI
2. Click on the **Mappings** sub-tab
3. View all tool-to-policy mappings organized by tool
4. See which tool rules map to which ACPG policies
5. View confidence levels and severity for each mapping

**Example Mapping Display:**
- **bandit** → B608 → SQL-001 (high confidence, critical severity)
- **eslint** → no-eval → SEC-003 (high confidence, high severity)

**Using the API:**

```bash
# Get all mappings
GET /api/v1/static-analysis/mappings

# Update mappings (requires editing tool_mappings.json file)
PUT /api/v1/static-analysis/mappings
{
  "mappings": {
    "bandit": {
      "B999": {
        "policy_id": "CUSTOM-001",
        "confidence": "medium",
        "severity": "high",
        "description": "Custom rule mapping"
      }
    }
  }
}
```

**Editing Mappings File:**

Edit `policies/tool_mappings.json` directly:

```json
{
  "bandit": {
    "B999": {
      "policy_id": "CUSTOM-001",
      "confidence": "medium",
      "severity": "high",
      "description": "Custom rule mapping"
    }
  }
}
```

---

## How Findings Get Into Proof & Certification

### 1. Evidence Collection

Every violation becomes evidence:

```python
# In proof_assembler._gather_evidence()
for v in analysis.violations:
    evidence_list.append(Evidence(
        rule_id=v.rule_id,        # ACPG policy ID
        type="violation",
        tool=v.detector,          # "bandit", "eslint", etc.
        output=f"Line {v.line}: {v.evidence}"
    ))
```

### 2. Argumentation Trace

Tool findings are included in the argumentation:

```python
# In proof_assembler._extract_argumentation()
tools_used = set()
for violation in analysis.violations:
    if violation.detector not in ("regex", "ast"):
        tools_used.add(violation.detector)

formal_proof = {
    "tools_used": sorted(list(tools_used)),
    "arguments": [
        {
            "id": "V_SQL-001_0",
            "type": "violation",
            "tool": "bandit",  # Shows which tool found it
            "status": "accepted"
        }
    ]
}
```

### 3. Cryptographic Signing

The entire proof bundle (including tool findings) is signed:

```python
bundle_data = {
    "artifact": {...},
    "policies": [...],
    "evidence": [...],      # Includes tool evidence
    "argumentation": {...}, # Includes tools_used
    "decision": "...",
    "timestamp": "..."
}

signature = signer.sign_proof(bundle_data)
```

**Result:** Tamper-proof certificate that includes:
- All tool findings
- Tool metadata
- Formal argumentation
- Cryptographic signature

---

## Example: Complete Flow

### Input Code
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

### Step 1: Tool Execution
- Bandit runs, finds `B608` (SQL injection) at line 1
- Output: `{"test_id": "B608", "line_number": 1, ...}`

### Step 2: Mapping
- Mapper: `B608` → `SQL-001`
- Creates: `Violation(rule_id="SQL-001", detector="bandit", line=1)`

### Step 3: Argumentation
- Creates: `V_SQL-001[bandit]` (violation argument)
- Attacks: `C_SQL-001` (compliance argument)
- Result: `V_SQL-001[bandit]` accepted → `C_SQL-001` rejected

### Step 4: Evidence
```json
{
  "rule_id": "SQL-001",
  "tool": "bandit",
  "tool_rule_id": "B608",
  "output": "Line 1: SQL injection via f-string"
}
```

### Step 5: Proof Bundle
```json
{
  "decision": "Non-compliant",
  "policies": [{"id": "SQL-001", "result": "violated"}],
  "evidence": [{"rule_id": "SQL-001", "tool": "bandit", ...}],
  "argumentation": {
    "tools_used": ["bandit"],
    "arguments": [{"id": "V_SQL-001_0", "tool": "bandit", ...}]
  },
  "signed": {"signature": "..."}
}
```

---

## Key Points

1. **Automatic Integration**: Tools run automatically when `ENABLE_STATIC_ANALYSIS=true`
2. **Policy Mapping**: Tool findings are mapped to ACPG policies via `tool_mappings.json`
3. **Unified Violations**: Tool violations are combined with regex/AST violations
4. **Formal Reasoning**: All findings go through Dung's AAF for adjudication
5. **Evidence Chain**: Tool findings become Evidence objects in proof bundle
6. **Tamper-Proof**: Entire bundle (including tool findings) is cryptographically signed
7. **Full Traceability**: Proof bundle shows which tools found which violations

---

## Configuration

### Enable/Disable Tools
```python
# In static_analyzers.py
"bandit": ToolConfig(
    enabled=True,  # Set to False to disable
    ...
)
```

### Add Tool Mappings
Edit `policies/tool_mappings.json` to map new tool rules to policies.

### Tool Execution Settings
```python
# In config.py
ENABLE_STATIC_ANALYSIS = True
STATIC_ANALYSIS_TIMEOUT = 30  # seconds
STATIC_ANALYSIS_CACHE_TTL = 3600  # seconds
```

---

## Verification

To verify tools are working:

1. **Check Tools Tab**: 
   - Navigate to **Tools** → **Tools** sub-tab
   - Verify tools are enabled/disabled as expected
   - Check cache statistics are displayed

2. **Check Mappings Tab**:
   - Navigate to **Tools** → **Mappings** sub-tab
   - Verify tool rules are mapped to policies
   - Check confidence and severity levels

3. **Check Violations**: 
   - Look for tool badges (bandit, eslint) on violations
   - Tool name should appear next to violation description

4. **Check Proof Bundle**: 
   - Look for `tools_used` in argumentation section
   - Verify tool metadata in evidence objects

5. **Check Evidence**: 
   - Evidence objects should have `tool` field populated
   - Tool rule IDs should be present in evidence

---

## Troubleshooting

**Tools not running?**
- Check `ENABLE_STATIC_ANALYSIS=true` in config
- Check tool is enabled in `static_analyzers.py`
- Check tool is installed (e.g., `which bandit`)

**Findings not mapped?**
- Check `tool_mappings.json` has mapping for tool rule
- Check tool rule ID matches exactly

**Not in proof bundle?**
- Check violations have `detector` field set to tool name
- Check evidence gathering includes tool metadata
- Check argumentation extraction includes `tools_used`


# ACPG User Guide

## Getting Started

### Starting the System

```bash
# Start all services
./scripts/start.sh

# Check status
./scripts/status.sh

# Access the UI
# Frontend: http://localhost:6001
# Backend API: http://localhost:6000
```

### First Steps

1. **Open the Web UI**: Navigate to `http://localhost:6001`
2. **Configure Tools**: Go to Tools → Tools tab
   - Enable Bandit for Python security scanning
   - Enable Safety for dependency vulnerability checking
   - Enable ESLint for JavaScript/TypeScript (if needed)
3. **Load Sample Code**: Use the sample dropdown to load `12_tool_demo.py`
4. **Run Analysis**: Click "Analyze" to see violations and tool findings

---

## Understanding the Workflow

### 1. Code Analysis

When you click "Analyze", ACPG:

1. **Detects Language** - Automatically identifies Python, JavaScript, etc.
2. **Runs Static Analysis Tools** - Executes enabled tools (Bandit, ESLint, etc.)
3. **Runs Policy Checks** - Checks code against ACPG policies
4. **Maps Tool Findings** - Converts tool findings to policy violations
5. **Adjudicates** - Uses formal argumentation to determine compliance

### 2. Understanding Results

#### Tool Execution Status

Shows which tools ran and what they found:
- **✓ Success**: Tool ran successfully
  - Shows: findings count, mapped count, unmapped count
  - Shows: tool version (e.g., "bandit v1.7.5")
  - Shows: execution time
- **✗ Failed**: Tool encountered an error
  - Shows: error message with helpful suggestions

#### Unmapped Findings

Findings from tools that aren't mapped to ACPG policies:
- **What it means**: Tool found something, but no policy mapping exists
- **What to do**: Click "Map Rule" to create a mapping
- **Why it matters**: Unmapped findings won't appear as violations

#### Violations

Policy violations found in your code:
- **Mapped findings**: Tool findings that are mapped to policies
- **Regex/AST findings**: Direct policy checks
- **Each violation shows**:
  - Policy ID (e.g., SQL-001)
  - Tool badge (e.g., [bandit])
  - Line number
  - Description
  - Severity

### 3. Creating Mappings

**Why create mappings?**
- Map tool rules to ACPG policies
- Makes tool findings appear as violations
- Enables automatic compliance checking

**How to create mappings:**

**Method 1: From Unmapped Findings**
1. Analyze code
2. Find "Unmapped Findings" section
3. Click "Map Rule" on a finding
4. System navigates to Tools → Mappings
5. Fill in Policy ID (e.g., "SQL-001")
6. Set confidence and severity
7. Click "Save"

**Method 2: From Browse Rules**
1. Go to Tools → Browse Rules
2. Select a tool (e.g., "bandit")
3. Find an unmapped rule
4. Click "Map" button
5. Fill in mapping details
6. Click "Save"

**Method 3: Manual Entry**
1. Go to Tools → Mappings
2. Click "Add Mapping"
3. Enter:
   - Tool Name (e.g., "bandit")
   - Tool Rule ID (e.g., "B608")
   - Policy ID (e.g., "SQL-001")
   - Confidence (low/medium/high)
   - Severity (low/medium/high/critical)
   - Description (optional)
4. Click "Save"

### 4. Auto-Fix & Certify

Click "Auto-Fix & Certify" to:
1. **Fix Violations**: AI attempts to fix all violations
2. **Iterate**: Up to 3 iterations to achieve compliance
3. **Generate Proof**: Creates tamper-proof proof bundle
4. **Show Diff**: Displays what changed

**Proof Bundle Contains:**
- Original and fixed code
- Policy outcomes
- Evidence from tools
- Formal argumentation trace
- Cryptographic signature
- **Code included** (tamper-proof)

---

## Tool Configuration

### Enabling/Disabling Tools

1. Go to **Tools → Tools** tab
2. Find the tool you want to configure
3. Toggle the switch to enable/disable
4. Settings are saved automatically

### Available Tools

**Python:**
- **Bandit**: Security linter (recommended)
- **Safety**: Dependency vulnerability checker (recommended)
- **Pylint**: Code quality (optional)

**JavaScript/TypeScript:**
- **ESLint**: Linting tool (requires config file)

### Tool Requirements

- Tools must be installed in the backend environment
- Check installation: `pip install bandit safety`
- Check health: Visit `/api/v1/health` endpoint

---

## Understanding Proof Bundles

### What is a Proof Bundle?

A cryptographically-signed certificate proving code compliance:
- **Tamper-proof**: Code is included and signed
- **Verifiable**: Can verify signature independently
- **Complete**: Contains all evidence and reasoning

### Proof Bundle Structure

```json
{
  "artifact": {
    "hash": "sha256:...",
    "language": "python",
    "generator": "ACPG-Qwen2.5-Coder"
  },
  "code": "...",  // Actual code (tamper-proof)
  "policies": [...],
  "evidence": [...],
  "argumentation": {
    "tools_used": ["bandit"],
    "tool_versions": {"bandit": "1.7.5"}
  },
  "decision": "Compliant",
  "signed": {
    "signature": "...",
    "algorithm": "ECDSA-SHA256"
  }
}
```

### Verifying Proof Bundles

1. Go to **Verify** tab
2. Paste proof bundle JSON
3. Click "Verify"
4. See results:
   - ✓ Signature valid
   - ✓ Code hash matches
   - ✓ PROOF BUNDLE INTEGRITY VERIFIED

**Or use API:**
```bash
curl -X POST http://localhost:6000/api/v1/proof/verify \
  -H "Content-Type: application/json" \
  -d @proof_bundle.json
```

---

## Common Workflows

### Workflow 1: First-Time Setup

1. Start services: `./scripts/start.sh`
2. Configure tools: Enable Bandit and Safety
3. Browse rules: See what Bandit can detect
4. Create mappings: Map common rules (B608 → SQL-001, etc.)
5. Test: Load sample code and analyze

### Workflow 2: Analyzing New Code

1. Paste code in editor
2. Click "Analyze"
3. Review violations
4. Check unmapped findings
5. Create mappings for important findings
6. Re-analyze to see new violations
7. Click "Auto-Fix & Certify" if needed

### Workflow 3: Compliance Certification

1. Analyze code
2. Fix violations (manually or auto-fix)
3. Verify compliance
4. Generate proof bundle
5. Verify proof bundle integrity
6. Store proof bundle for audit

---

## Troubleshooting

### Tools Not Running

**Problem**: Tool execution shows "Failed"

**Solutions**:
1. Check if tool is installed: `which bandit`
2. Check if tool is enabled: Tools → Tools tab
3. Check backend logs: `tail -f /tmp/acpg_backend.log`
4. Check health endpoint: `curl http://localhost:6000/api/v1/health`

### No Violations Appearing

**Problem**: Code has issues but no violations shown

**Solutions**:
1. Check tool execution status - did tools run?
2. Check unmapped findings - are findings unmapped?
3. Create mappings for unmapped findings
4. Verify policies are enabled

### Unmapped Findings Not Showing

**Problem**: Can't see unmapped findings

**Solutions**:
1. Expand "Unmapped Findings" section
2. Check tool execution panel - expand tool details
3. Verify tools actually found issues (findings_count > 0)
4. Check if findings are actually unmapped (not mapped)

### Proof Bundle Verification Fails

**Problem**: Proof bundle shows as tampered

**Solutions**:
1. Don't modify the JSON manually
2. Use the verification endpoint
3. Check that code hash matches
4. Verify signature is intact

---

## Best Practices

### 1. Tool Configuration

- **Enable essential tools**: Bandit for Python, ESLint for JS
- **Disable unnecessary tools**: Don't enable tools you won't use
- **Check tool versions**: Use health endpoint to verify

### 2. Mapping Management

- **Map important rules first**: Security-critical rules
- **Use appropriate severity**: Match tool severity to policy severity
- **Document mappings**: Add descriptions for clarity
- **Review unmapped findings**: Don't ignore them

### 3. Code Analysis

- **Analyze before fixing**: Understand violations first
- **Review unmapped findings**: May indicate missing policies
- **Use auto-fix carefully**: Review changes before accepting
- **Verify proof bundles**: Always verify after generation

### 4. Compliance Workflow

- **Regular analysis**: Analyze code frequently
- **Track violations**: Use proof bundles as audit trail
- **Maintain mappings**: Keep mappings up to date
- **Document decisions**: Use proof bundles for compliance records

---

## API Usage

### Health Check

```bash
curl http://localhost:6000/api/v1/health
```

Returns detailed component status.

### Analyze Code

```bash
curl -X POST http://localhost:6000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"secret123\"",
    "language": "python"
  }'
```

### Get Tool Mappings

```bash
curl http://localhost:6000/api/v1/static-analysis/mappings
```

### Create Mapping

```bash
curl -X POST http://localhost:6000/api/v1/static-analysis/mappings/bandit/B608 \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "SQL-001",
    "confidence": "high",
    "severity": "critical",
    "description": "SQL injection via string formatting"
  }'
```

---

## Advanced Features

### Service Management

```bash
# Start services
./scripts/start.sh

# Stop services
./scripts/stop.sh

# Restart services
./scripts/restart.sh

# Check status
./scripts/status.sh
```

### Configuration

Edit `config.yaml` to customize:
- Port numbers
- CORS origins
- Log locations
- Timeouts

### Tool Cache

Tool results are cached for performance:
- Cache location: Managed automatically
- Cache invalidation: On code change
- Cache stats: Available in Tools → Tools tab

---

## Getting Help

- **Documentation**: See `docs/` directory
- **API Docs**: Visit `http://localhost:6000/docs`
- **Health Check**: `http://localhost:6000/api/v1/health`
- **Logs**: Check `/tmp/acpg_backend.log` and `/tmp/acpg_frontend.log`

---

## Next Steps

1. **Explore Tools**: Browse available rules in Tools → Browse Rules
2. **Create Mappings**: Map important tool rules to policies
3. **Analyze Code**: Test with your own code
4. **Generate Proofs**: Create compliance certificates
5. **Verify Integrity**: Test tamper detection

Happy compliance checking! 🎉


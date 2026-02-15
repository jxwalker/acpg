> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# End-to-End Workflow Test Guide

## Complete Test Scenario

This guide walks through testing the complete tool integration workflow using `samples/12_tool_demo.py`.

---

## Prerequisites

1. Backend server running on port 6000
2. Frontend server running on port 6001
3. Bandit installed and enabled
4. Sample file `12_tool_demo.py` available

---

## Test Steps

### Step 1: Browse Available Rules

1. Open frontend: `http://localhost:6001`
2. Navigate to **Tools** tab
3. Click **Browse Rules** sub-tab
4. Select **bandit** from tool dropdown
5. **Verify**:
   - See list of all Bandit rules
   - B608, B105, B307, B601, B602, B104 show as "Mapped"
   - B102, B101 show as "Unmapped"
   - Can see rule descriptions and severity

### Step 2: Load Sample Code

1. Go to **Editor** tab
2. Click sample dropdown
3. Select **12_tool_demo.py**
4. **Verify**: Code loads with various security issues

### Step 3: Analyze Code

1. Click **Analyze** button
2. Wait for analysis to complete
3. **Verify**: Analysis completes without errors

### Step 4: Check Tool Execution Status

1. Look for **Tool Execution** panel in results
2. **Verify**:
   - Shows "bandit" with ✓ (success)
   - Shows "8 findings (6 mapped, 2 unmapped)"
   - Shows execution time
3. Click to expand bandit details
4. **Verify**:
   - Stats show: 8 total, 6 mapped, 2 unmapped
   - "Show 2 unmapped findings" button appears
5. Click "Show unmapped findings"
6. **Verify**:
   - See B102 (exec usage) and B101 (assert usage)
   - Both marked as "Unmapped"
   - Can see line numbers and messages

### Step 5: Check Violations

1. Look for **Policy Violations** panel
2. **Verify**:
   - See 6 violations total
   - Each violation has [bandit] badge
   - Violations include:
     - SQL-001 (from B608, B601)
     - SEC-001 (from B105, B104)
     - SEC-003 (from B307, B602)
3. Expand a violation
4. **Verify**:
   - Shows evidence from tool
   - Shows line number
   - Shows tool badge

### Step 6: Create Mapping for Unmapped Rule

1. Go back to **Tools** → **Browse Rules**
2. Find **B102** (exec usage)
3. Click **Map** button
4. **Verify**: Form opens with:
   - Tool: bandit
   - Rule ID: B102
   - Description pre-filled
5. Enter Policy ID: `SEC-003` (or create new)
6. Set confidence: `high`
7. Set severity: `high`
8. Click **Save**
9. **Verify**: Mapping created successfully

### Step 7: Re-analyze Code

1. Go back to **Editor**
2. Click **Analyze** again
3. **Verify**:
   - Tool execution shows: 7 mapped, 1 unmapped
   - Violations panel shows 7 violations
   - New violation for B102 appears

### Step 8: Verify Proof Bundle

1. Click **Proof** tab (if available)
2. **Verify**:
   - `tools_used` includes "bandit"
   - Evidence includes tool metadata
   - Argumentation shows tool findings

---

## Expected Results Summary

### Initial Analysis
- **Tool Execution**: bandit ✓ (8 findings: 6 mapped, 2 unmapped)
- **Violations**: 6 violations with [bandit] badges
- **Unmapped Findings**: B102, B101 visible in tool execution panel

### After Mapping B102
- **Tool Execution**: bandit ✓ (8 findings: 7 mapped, 1 unmapped)
- **Violations**: 7 violations with [bandit] badges
- **Unmapped Findings**: Only B101 remains

---

## Troubleshooting

### Tool Execution Shows "Failed"
- Check if bandit is installed: `which bandit`
- Check if bandit is enabled in Tools → Tools tab
- Check backend logs for errors

### No Violations Appear
- Verify mappings exist in `policies/tool_mappings.json`
- Check tool execution panel to see if tools ran
- Verify findings were mapped (not all unmapped)

### Unmapped Findings Not Showing
- Expand tool execution panel
- Click "Show unmapped findings" button
- Verify tool actually found issues (check findings_count > 0)

### Mappings Not Saving
- Check backend logs for errors
- Verify `policies/tool_mappings.json` is writable
- Check browser console for API errors

---

## Success Criteria

✅ Can browse available tool rules
✅ Can see which rules are mapped/unmapped
✅ Tools run automatically during analysis
✅ Tool execution status shows results
✅ Mapped findings appear as violations
✅ Unmapped findings visible in tool execution panel
✅ Can create mappings from unmapped findings
✅ New mappings take effect on re-analysis
✅ Violations show tool badges
✅ Proof bundle includes tool metadata

---

## Next Steps After Testing

1. **Create more mappings**: Map remaining unmapped rules
2. **Test other tools**: Try ESLint with JavaScript code
3. **Test tool failures**: Disable a tool and verify error handling
4. **Test performance**: Analyze large code files
5. **Test caching**: Re-analyze same code to see cache hits


# Next Steps for Tool Integration

## Priority 1: Show Tool Execution Status (High Impact)

**Problem**: Users can't see which tools ran, what they found, or why findings were ignored.

**Solution**: Enhance `AnalysisResult` to include tool execution metadata:

```python
class AnalysisResult:
    artifact_id: str
    violations: List[Violation]
    tool_execution: Dict[str, ToolExecutionInfo]  # NEW
    
class ToolExecutionInfo:
    tool_name: str
    success: bool
    findings_count: int
    mapped_findings: int
    unmapped_findings: int
    execution_time: float
    error: Optional[str]
```

**UI Changes**:
- Add "Tool Execution" panel in analysis results
- Show: ✓ bandit (3 findings, 2 mapped, 1 unmapped)
- Show: ✗ eslint (failed: config missing)
- Click to see unmapped findings

**Benefits**:
- Users see tools are running
- Users understand why some findings don't appear
- Easier debugging when tools fail

---

## Priority 2: Show Unmapped Findings (High Value)

**Problem**: Unmapped findings are silently ignored - users don't know tools found something.

**Solution**: Include unmapped findings in analysis results (separate from violations):

```python
class AnalysisResult:
    violations: List[Violation]  # Mapped findings
    unmapped_findings: List[UnmappedFinding]  # NEW
    
class UnmappedFinding:
    tool_name: str
    tool_rule_id: str
    line: int
    message: str
    severity: str
```

**UI Changes**:
- Add "Unmapped Findings" section (collapsed by default)
- Show: "bandit found B999 (unmapped) at line 42"
- "Map this rule" button next to each unmapped finding
- Quick action to create mapping

**Benefits**:
- Users discover available rules
- No silent ignoring of findings
- Easy path to create mappings

---

## Priority 3: Real-time Tool Execution Status (Nice to Have)

**Problem**: During analysis, users don't see progress.

**Solution**: Stream tool execution status:

```python
# WebSocket or Server-Sent Events
{
  "status": "running_tools",
  "tool": "bandit",
  "progress": 50
}
```

**UI Changes**:
- Progress indicator: "Running bandit... (2/3 tools)"
- Live updates as tools execute
- Show errors immediately

**Benefits**:
- Better UX during long analyses
- Immediate feedback on tool failures

---

## Priority 4: Enhanced Tool Rules Registry (Medium Priority)

**Current**: Static list of known rules.

**Enhancements**:
1. **Dynamic rule discovery**: Try to query tools for rules
   ```python
   # Try: bandit --help, eslint --print-config
   # Fallback to static registry
   ```

2. **Rule descriptions from tools**: Get actual descriptions
   ```python
   # Parse tool help/docs for better descriptions
   ```

3. **Rule categories**: Group rules by category
   ```python
   # Security, Performance, Style, etc.
   ```

---

## Priority 5: Test End-to-End Workflow (Critical)

**Create test scenario**:

1. **Sample code with known issues**:
   ```python
   # samples/12_tool_demo.py
   query = f"SELECT * FROM users WHERE id = {user_id}"  # B608
   password = "secret123"  # B105
   eval(user_input)  # B307
   ```

2. **Test steps**:
   - Browse rules → Find B608
   - Create mapping: B608 → SQL-001
   - Analyze code
   - Verify violation appears with [bandit] badge
   - Check unmapped findings (B105, B307) appear
   - Create mappings for those
   - Re-analyze → All violations appear

3. **Document results**: Screenshots, workflow video

---

## Priority 6: Tool Configuration Improvements (Low Priority)

**Enhancements**:
1. **Tool-specific settings**: Timeout, severity filters per tool
2. **Tool groups**: Enable/disable groups of tools
3. **Tool dependencies**: Show if tools are installed
4. **Tool version info**: Display versions in UI

---

## Recommended Implementation Order

1. ✅ **Done**: Tool rules browser, mappings UI, workflow visualization
2. 🔄 **Next**: Show tool execution status in analysis results
3. 🔄 **Then**: Show unmapped findings with quick mapping
4. 🔄 **After**: Test end-to-end workflow
5. ⏳ **Later**: Real-time status, dynamic rule discovery

---

## Quick Wins

**Can implement quickly**:
- Add tool execution summary to `AnalysisResult`
- Show "Tools used: bandit, eslint" in compliance report
- Add unmapped findings count to UI
- Create sample code demonstrating tool findings

**High impact, low effort**:
- Tool execution status panel
- Unmapped findings list
- "Map this rule" quick action

---

## Questions to Answer

1. **Should unmapped findings be warnings or just informational?**
   - Option A: Show as warnings (might be noise)
   - Option B: Show in separate "Info" section (recommended)

2. **Should we cache tool execution results?**
   - Already implemented ✓
   - But should we show cache hits in UI?

3. **Should we allow running tools manually?**
   - Current: Automatic only
   - Future: "Test Tool" button to run on sample code

4. **Should we show tool output raw?**
   - For debugging: Yes, in expanded view
   - For users: No, just summary

---

## Success Criteria

The tool integration is "complete" when:

- [x] Users can browse available rules
- [x] Users can create mappings
- [x] Tools run automatically
- [ ] Users can see which tools ran
- [ ] Users can see unmapped findings
- [ ] Users can create mappings from unmapped findings
- [ ] End-to-end workflow tested and documented
- [ ] Sample code demonstrates all features


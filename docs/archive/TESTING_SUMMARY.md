> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# Static Analysis Integration - Testing Summary

## Test Results

**Overall:** ✅ 65 tests passed, 1 failed (unrelated), 1 skipped

**Static Analysis Integration Tests:** ✅ 14/15 passed, 1 skipped (Bandit dependency issue)

## Test Coverage

### Language Detection (4 tests) ✅
- Python detection from file extension
- Python detection from shebang
- JavaScript detection from extension
- Language detection from content

### Bandit Parser (1 test) ✅
- Parses Bandit JSON output correctly
- Extracts rule IDs, severity, line numbers
- Handles multiple findings

### Tool Mapper (1 test) ✅
- Maps Bandit findings to ACPG policies
- Returns correct policy ID and metadata
- Handles confidence and severity mapping

### Tool Executor (1 test) ⏭️ Skipped
- Requires Bandit to be fully installed
- Gracefully handles missing tools

### Prosecutor Integration (2 tests) ✅
- Static analysis integration works
- Auto language detection functions
- Falls back to regex when tools unavailable

### End-to-End Integration (2 tests) ✅
- Sample file analysis (hardcoded secrets)
- Sample file analysis (SQL injection)
- Multiple detectors work together
- Tool badges appear in violations

### Tool Cache (2 tests) ✅
- Cache set/get operations
- Cache expiry mechanism

### Static Analyzer Config (2 tests) ✅
- Tool configuration retrieval
- Tool configuration structure

## Integration Test Results

```
tests/test_static_analysis_integration.py::TestLanguageDetection::test_detect_python_from_extension PASSED
tests/test_static_analysis_integration.py::TestLanguageDetection::test_detect_python_from_shebang PASSED
tests/test_static_analysis_integration.py::TestLanguageDetection::test_detect_javascript_from_extension PASSED
tests/test_static_analysis_integration.py::TestLanguageDetection::test_detect_from_content PASSED
tests/test_static_analysis_integration.py::TestBanditParser::test_parse_bandit_output PASSED
tests/test_static_analysis_integration.py::TestToolMapper::test_map_bandit_finding PASSED
tests/test_static_analysis_integration.py::TestToolExecutor::test_execute_bandit SKIPPED
tests/test_static_analysis_integration.py::TestProsecutorIntegration::test_prosecutor_with_static_analysis PASSED
tests/test_static_analysis_integration.py::TestProsecutorIntegration::test_prosecutor_auto_language_detection PASSED
tests/test_static_analysis_integration.py::TestEndToEndIntegration::test_sample_hardcoded_secrets PASSED
tests/test_static_analysis_integration.py::TestEndToEndIntegration::test_sample_sql_injection PASSED
tests/test_static_analysis_integration.py::TestToolCache::test_cache_set_get PASSED
tests/test_static_analysis_integration.py::TestToolCache::test_cache_expiry PASSED
tests/test_static_analysis_integration.py::TestStaticAnalyzerConfig::test_get_tools_for_language PASSED
tests/test_static_analysis_integration.py::TestStaticAnalyzerConfig::test_tool_configuration PASSED
```

## Manual Testing

### API Endpoints
- ✅ `/api/v1/analyze` - Works with static analysis
- ⚠️ `/api/v1/static-analysis/tools` - Route exists but may need server restart

### Sample Files
- ✅ `samples/01_hardcoded_secrets.py` - Analyzed successfully
- ✅ `samples/02_sql_injection.py` - Analyzed successfully
- ✅ Violations detected with correct rule IDs
- ✅ Detector field populated correctly

### Error Handling
- ✅ Gracefully handles missing tools (safety, bandit dependency issues)
- ✅ Falls back to regex checks when tools unavailable
- ✅ Logs errors without crashing

## Known Issues

1. **Bandit Dependency**: Bandit has a missing `pbr` module dependency
   - **Impact**: Bandit tool doesn't execute
   - **Workaround**: System falls back to regex checks
   - **Fix**: Install missing dependency: `pip install pbr`

2. **Safety Tool**: Not installed in environment
   - **Impact**: Safety tool skipped
   - **Workaround**: Tool executor handles gracefully
   - **Fix**: Install safety: `pip install safety`

3. **Datetime Warnings**: Some other modules still use deprecated `datetime.utcnow()`
   - **Impact**: Deprecation warnings in tests
   - **Status**: Fixed in tool_executor, other modules need updating

## Test Execution

Run all tests:
```bash
cd backend && source venv/bin/activate && cd .. && python -m pytest tests/ -v
```

Run static analysis tests only:
```bash
cd backend && source venv/bin/activate && cd .. && python -m pytest tests/test_static_analysis_integration.py -v
```

## Verification Checklist

- [x] Language detection works for Python, JavaScript
- [x] Parsers correctly extract findings from tool output
- [x] Tool-to-policy mapping functions correctly
- [x] Tool executor handles missing tools gracefully
- [x] Prosecutor integrates static analysis tools
- [x] End-to-end flow works with sample files
- [x] Caching system functions correctly
- [x] Configuration system loads tools correctly
- [x] Error handling doesn't crash system
- [x] Fallback to regex when tools unavailable

## Next Steps

1. Fix Bandit dependency: `pip install pbr` in venv
2. Install Safety: `pip install safety` in venv
3. Test with fully installed tools
4. Update remaining datetime.utcnow() calls
5. Add ESLint integration test (requires Node.js/ESLint)


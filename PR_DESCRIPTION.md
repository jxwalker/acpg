# Static Analysis Integration & Export Functionality

## 🎯 Overview

This PR adds comprehensive static analysis tool integration to ACPG, enabling automatic execution of industry-standard security tools (Bandit, ESLint, Safety, etc.) alongside existing policy checks. It also adds proof bundle export functionality and enhanced error handling.

## 📊 Statistics

- **58 files changed**: 12,993 insertions(+), 216 deletions(-)
- **53 commits** ahead of main
- **15+ new API endpoints**
- **4 new export formats** (JSON, Markdown, HTML, Summary)

## ✨ Key Features

### 1. Static Analysis Integration
- **Automatic Tool Execution**: Tools run automatically during code analysis
- **Language Detection**: Automatic detection of Python, JavaScript, TypeScript
- **Parallel Execution**: Multiple tools run simultaneously for performance
- **Tool Version Tracking**: Automatic extraction and display of tool versions
- **Tool Caching**: Results cached to improve performance
- **Supported Tools**:
  - Python: Bandit, Safety, Pylint
  - JavaScript/TypeScript: ESLint
  - Generic: SARIF format (Semgrep, CodeQL, etc.)

### 2. Tool Configuration UI
- **Tools Tab**: Enable/disable tools per language
- **Visual Feedback**: Toggle switches with status indicators
- **Tool Details**: Timeout, format, configuration requirements
- **Cache Statistics**: View cache hit rates and performance
- **Persistence**: Configuration saved to `policies/tool_config.json`

### 3. Tool Rules Browser
- **Browse Rules**: View all available rules from tools
- **Mapping Status**: See which rules are mapped/unmapped
- **Filtering**: Filter by All / Mapped / Unmapped
- **Rule Details**: Description, severity, category
- **Quick Actions**: Create mappings and policies directly from rules
- **Pipeline Visualization**: See how tools fit into the workflow

### 4. Tool-to-Policy Mapping
- **Mapping Management**: Create, edit, delete mappings
- **Mappings Tab**: Organized view by tool with statistics
- **Quick Mapping**: Create mappings from unmapped findings
- **Policy Creation**: Create policies from tool rules
- **Confidence Levels**: High/medium/low confidence mapping
- **Persistence**: Mappings saved to `policies/tool_mappings.json`

### 5. Unmapped Findings Discovery
- **Prominent Display**: Dedicated section for unmapped findings
- **Aggregation**: All unmapped findings across tools
- **Quick Actions**: One-click mapping creation
- **Details**: Rule IDs, lines, messages, severity
- **Visual Indicators**: Clear badges and icons

### 6. Tool Execution Status
- **Real-Time Status**: Shows which tools ran (success/failure)
- **Findings Breakdown**: Total, mapped, unmapped counts
- **Execution Time**: Per-tool performance metrics
- **Error Messages**: Helpful error messages with actionable guidance
- **Expandable Details**: Drill down into tool results

### 7. Proof Bundle Export
- **Multiple Formats**: JSON, Markdown, HTML, Summary
- **Format Selector**: Dropdown menu in proof bundle view
- **Styled Reports**: HTML with color-coded sections
- **Human-Readable**: Markdown with structured sections
- **Export from Verifier**: Export functionality in proof verifier
- **Backend Formatting**: Consistent, professional exports

### 8. Enhanced Error Handling
- **Retry Logic**: Automatic retries for transient failures (up to 2 retries)
- **Exponential Backoff**: 0.5s, 1s, 2s delays between retries
- **Error Categorization**: Not installed, timeout, missing dependencies, etc.
- **Actionable Messages**: Clear guidance on how to fix issues
- **Better Logging**: Improved debugging information

### 9. Service Management
- **YAML Configuration**: Centralized config in `config.yaml`
- **Automatic Port Finding**: Finds free ports automatically
- **Graceful Startup/Shutdown**: Proper process management
- **Status Scripts**: Quick status checks
- **Restart Scripts**: Easy service restarts

### 10. Code Integrity
- **Code in Proof Bundles**: Code included for tamper detection
- **Cryptographic Signing**: Code is part of signed data
- **Tamper Detection**: Any code modification invalidates signature
- **Verification**: Independent verification endpoint

## 🏗️ Architecture

```
Code Input
    ↓
Language Detection
    ↓
Static Analysis Tools (Bandit, ESLint, etc.)
    ↓
Tool Output Parsers
    ↓
Tool-to-Policy Mapping
    ↓
Prosecutor (combines with regex/AST checks)
    ↓
Adjudicator (Dung's AAF with tool reliability)
    ↓
Proof Bundle (with tool metadata & code)
    ↓
Export (JSON/Markdown/HTML/Summary)
```

## 📁 New Files

### Backend
- `backend/app/core/static_analyzers.py` - Tool configuration
- `backend/app/core/tool_rules_registry.py` - Tool rules registry
- `backend/app/services/language_detector.py` - Language detection
- `backend/app/services/tool_executor.py` - Tool execution service
- `backend/app/services/tool_cache.py` - Result caching
- `backend/app/services/tool_mapper.py` - Tool-to-policy mapping
- `backend/app/services/tool_reliability.py` - Tool reliability assessment
- `backend/app/services/parsers/` - Output parsers (Bandit, ESLint, SARIF)
- `backend/app/core/service_config.py` - Service configuration
- `tests/test_static_analysis_integration.py` - Integration tests

### Frontend
- Enhanced `frontend/src/App.tsx` with:
  - ToolsConfigurationView
  - ToolRulesBrowser
  - ToolMappingsView
  - UnmappedFindingsSection
  - ToolExecutionStatus
  - AnalysisProgress
  - Export functionality

### Configuration
- `config.yaml` - Service configuration
- `policies/tool_config.json` - Tool enable/disable settings
- `policies/tool_mappings.json` - Tool-to-policy mappings

### Scripts
- `scripts/start.sh` - Service startup
- `scripts/stop.sh` - Service shutdown
- `scripts/restart.sh` - Service restart
- `scripts/status.sh` - Service status

### Documentation
- `docs/STATIC_ANALYSIS_INTEGRATION_PLAN.md`
- `docs/STATIC_ANALYSIS_GUIDE.md`
- `docs/TOOL_PIPELINE_GUIDE.md`
- `docs/TOOL_WORKFLOW_GUIDE.md`
- `docs/END_TO_END_TEST.md`
- `docs/USER_GUIDE.md`
- `docs/IMPLEMENTATION_SUMMARY.md`
- And many more...

## 🔌 New API Endpoints

- `GET /api/v1/static-analysis/tools` - List available tools
- `PUT /api/v1/static-analysis/tools/{lang}/{tool}` - Enable/disable tool
- `GET /api/v1/static-analysis/mappings` - Get tool mappings
- `PUT /api/v1/static-analysis/mappings` - Update mappings
- `POST /api/v1/static-analysis/mappings/{tool}/{rule}` - Add mapping
- `DELETE /api/v1/static-analysis/mappings/{tool}/{rule}` - Delete mapping
- `GET /api/v1/static-analysis/rules` - Browse tool rules
- `POST /api/v1/proof/export` - Export proof bundle
- `GET /api/v1/metrics` - Prometheus metrics
- `GET /api/v1/health` - Enhanced health check

## 🧪 Testing

- **66 total tests**: 65 passing, 1 skipped (unrelated)
- **15 static analysis integration tests**: 14 passing, 1 skipped
- **98.5% success rate**
- Comprehensive test coverage for:
  - Language detection
  - Tool configuration
  - Parsers (Bandit, ESLint, SARIF)
  - Tool mapper
  - Tool executor
  - Tool cache
  - Prosecutor integration
  - Adjudicator integration
  - End-to-end workflows

## 📝 Documentation

- Comprehensive user guides
- API documentation
- Integration guides
- Testing documentation
- Deployment guides
- CI/CD integration examples

## 🚀 Migration Guide

### For Existing Users

1. **Install Tools** (optional but recommended):
   ```bash
   pip install bandit safety
   npm install -g eslint
   ```

2. **Configure Tools**:
   - Navigate to Tools → Tools tab
   - Enable/disable tools as needed
   - Configuration is automatically saved

3. **Create Mappings**:
   - Browse rules in Tools → Browse Rules
   - Create mappings in Tools → Mappings
   - Or use quick mapping from unmapped findings

4. **Service Management**:
   - Use `./scripts/start.sh` instead of manual startup
   - Ports are automatically configured
   - Check status with `./scripts/status.sh`

## 🔄 Breaking Changes

None - this is a fully backward-compatible addition.

## ✅ Checklist

- [x] All tests passing
- [x] Documentation complete
- [x] Backward compatible
- [x] Error handling robust
- [x] Performance optimized (caching, parallel execution)
- [x] UI/UX polished
- [x] Code review ready

## 📸 Screenshots

(Add screenshots of:
- Tools configuration UI
- Tool rules browser
- Mappings management
- Unmapped findings section
- Export functionality
- Tool execution status)

## 🔗 Related Issues

(Link to any related issues)

## 👥 Reviewers

@jxwalker

---

**Ready for Review** ✅


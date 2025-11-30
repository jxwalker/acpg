# Static Analysis Integration Development Plan

## Overview
Integrate industry-standard static analysis tools (Bandit, ESLint, Semgrep, etc.) into the ACPG pipeline, using Dung's Abstract Argumentation Framework to adjudicate findings and cryptographic signing to produce tamper-proof compliance certificates.

## Goals
1. **Comprehensive Coverage**: Multiple tools catch different security issues
2. **Formal Reasoning**: Use argumentation framework to resolve tool conflicts
3. **Tamper-Proof Evidence**: Cryptographically sign all tool findings
4. **Extensibility**: Easy to add new tools and languages
5. **Auditability**: Full trace of which tools found what violations

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Code Input                                │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│            Language Detection Service                         │
│  - File extension analysis                                    │
│  - Shebang detection                                          │
│  - Package.json/requirements.txt parsing                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         Static Analysis Orchestrator                          │
│  - Select tools based on language                             │
│  - Execute tools in parallel                                  │
│  - Handle timeouts and errors                                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│            Tool Output Parsers                                │
│  - Bandit (JSON)                                             │
│  - ESLint (JSON)                                              │
│  - SARIF (generic)                                            │
│  - Custom parsers                                             │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         Tool-to-Policy Mapper                                 │
│  - Map tool rules to ACPG policy IDs                         │
│  - Handle multiple tools for same policy                      │
│  - Confidence/severity mapping                                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│            Enhanced Prosecutor                                │
│  - Combine static analysis findings                           │
│  - Combine with existing regex/AST checks                    │
│  - Generate Evidence objects                                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         Adjudicator (Dung's AAF)                             │
│  - Build argumentation graph                                 │
│  - Handle multi-tool arguments                               │
│  - Tool reliability exceptions                               │
│  - Compute grounded extension                                │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│            Proof Assembler                                   │
│  - Bundle all evidence (tools + checks)                      │
│  - Include tool metadata                                     │
│  - Sign with ECDSA                                           │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         Compliance Certificate (Proof Bundle)                │
└─────────────────────────────────────────────────────────────┘
```

---

## Development Phases

### Phase 1: Foundation & Configuration (Tasks 1-2)
**Goal**: Set up infrastructure for tool integration

**Tasks**:
- Create static analyzer configuration system
- Implement language detection service

**Deliverables**:
- `backend/app/core/static_analyzers.py` - Tool configuration
- `backend/app/services/language_detector.py` - Language detection
- `policies/tool_mappings.json` - Tool-to-policy mappings

**Files to Create**:
- `backend/app/core/static_analyzers.py`
- `backend/app/services/language_detector.py`
- `policies/tool_mappings.json`

**Files to Modify**:
- `backend/app/core/config.py` - Add static analyzer settings

---

### Phase 2: Tool Execution Infrastructure (Task 3)
**Goal**: Safe, reliable tool execution

**Tasks**:
- Create tool executor service with subprocess handling
- Implement sandboxing, timeouts, error recovery

**Deliverables**:
- `backend/app/services/tool_executor.py` - Tool execution service
- Error handling and logging

**Files to Create**:
- `backend/app/services/tool_executor.py`

**Dependencies**:
- Python `subprocess` module
- Consider `docker` for sandboxing (optional)

---

### Phase 3: Tool Parsers (Tasks 4-6)
**Goal**: Parse tool outputs into normalized format

**Tasks**:
- Implement Bandit parser (Python)
- Implement ESLint parser (JavaScript/TypeScript)
- Create generic SARIF parser

**Deliverables**:
- `backend/app/services/parsers/bandit_parser.py`
- `backend/app/services/parsers/eslint_parser.py`
- `backend/app/services/parsers/sarif_parser.py`
- `backend/app/services/parsers/base_parser.py` - Base class

**Files to Create**:
- `backend/app/services/parsers/__init__.py`
- `backend/app/services/parsers/base_parser.py`
- `backend/app/services/parsers/bandit_parser.py`
- `backend/app/services/parsers/eslint_parser.py`
- `backend/app/services/parsers/sarif_parser.py`

**Test Files**:
- `tests/test_parsers/test_bandit_parser.py`
- `tests/test_parsers/test_eslint_parser.py`
- `tests/test_parsers/test_sarif_parser.py`

---

### Phase 4: Policy Mapping (Task 7)
**Goal**: Map tool findings to ACPG policies

**Tasks**:
- Build tool-to-policy mapping system
- Support multiple tools per policy
- Handle confidence/severity levels

**Deliverables**:
- `backend/app/services/tool_mapper.py` - Mapping service
- Enhanced `policies/tool_mappings.json` with full mappings

**Files to Create**:
- `backend/app/services/tool_mapper.py`

**Files to Modify**:
- `policies/tool_mappings.json` - Add comprehensive mappings

**Example Mapping Structure**:
```json
{
  "bandit": {
    "B105": {
      "policy_id": "SEC-001",
      "confidence": "high",
      "severity": "high"
    },
    "B608": {
      "policy_id": "SQL-001",
      "confidence": "high",
      "severity": "critical"
    }
  },
  "eslint": {
    "no-eval": {
      "policy_id": "SEC-003",
      "confidence": "medium",
      "severity": "high"
    }
  }
}
```

---

### Phase 5: Data Model Enhancements (Task 8)
**Goal**: Extend models to support tool metadata

**Tasks**:
- Enhance Evidence model with tool fields
- Update Pydantic schemas
- Migrate database (if needed)

**Deliverables**:
- Updated `Evidence` model with tool metadata
- Updated API schemas

**Files to Modify**:
- `backend/app/models/schemas.py` - Add tool fields to Evidence
- `frontend/src/types.ts` - Update TypeScript types

**New Evidence Fields**:
- `tool_name: str` - Name of the tool (e.g., "bandit")
- `tool_version: Optional[str]` - Tool version
- `tool_rule_id: Optional[str]` - Tool-specific rule ID (e.g., "B608")
- `confidence: Optional[str]` - Tool confidence level
- `location: Optional[Dict]` - File, line, column

---

### Phase 6: Prosecutor Integration (Task 9)
**Goal**: Integrate static analysis into existing prosecutor

**Tasks**:
- Modify Prosecutor to run static analyzers
- Combine tool findings with regex/AST checks
- Generate unified Evidence objects

**Deliverables**:
- Enhanced Prosecutor service
- Unified evidence generation

**Files to Modify**:
- `backend/app/services/prosecutor.py` - Add static analysis execution
- `backend/app/api/routes.py` - Update endpoints if needed

**Integration Points**:
- Call tool executor from prosecutor
- Merge tool findings with existing checks
- Maintain backward compatibility

---

### Phase 7: Argumentation Framework Updates (Tasks 10-11)
**Goal**: Handle multi-tool arguments in Dung's AAF

**Tasks**:
- Update Adjudicator for multi-tool violation arguments
- Add tool reliability exception arguments
- Update argumentation graph generation

**Deliverables**:
- Enhanced Adjudicator service
- Tool reliability exception logic

**Files to Modify**:
- `backend/app/services/adjudicator.py` - Multi-tool argument handling
- `backend/app/services/proof_assembler.py` - Update graph visualization

**Argumentation Logic**:
- Multiple violation arguments from different tools attack same compliance argument
- Exception arguments can defeat tool findings based on:
  - Tool version/known issues
  - Low confidence scores
  - Tool-specific false positive patterns

---

### Phase 8: Proof Bundle Enhancements (Task 12)
**Goal**: Include tool metadata in signed proof bundles

**Tasks**:
- Update Proof Assembler to include tool information
- Add tools_used and tool_versions to argumentation
- Maintain signature compatibility

**Deliverables**:
- Enhanced proof bundles with tool metadata
- Updated proof bundle schema

**Files to Modify**:
- `backend/app/services/proof_assembler.py` - Add tool metadata
- `backend/app/models/schemas.py` - Update ProofBundle schema

**New Proof Bundle Fields**:
```python
{
  "argumentation": {
    "tools_used": ["bandit", "eslint"],
    "tool_versions": {
      "bandit": "1.7.5",
      "eslint": "8.50.0"
    },
    ...
  }
}
```

---

### Phase 9: Frontend Integration (Tasks 13-14)
**Goal**: UI for tool configuration and evidence display

**Tasks**:
- Create tool configuration UI
- Display tool evidence in compliance reports
- Show which tools found violations

**Deliverables**:
- Tool management UI component
- Enhanced compliance report with tool badges
- Tool evidence details in proof view

**Files to Create**:
- `frontend/src/components/ToolConfig.tsx` - Tool configuration UI

**Files to Modify**:
- `frontend/src/App.tsx` - Add tool evidence display
- `frontend/src/types.ts` - Update types for tool metadata

**UI Features**:
- Enable/disable tools per language
- View tool status and versions
- See which tool found each violation
- Tool confidence indicators

---

### Phase 10: Performance & Caching (Task 15)
**Goal**: Optimize tool execution performance

**Tasks**:
- Implement result caching for unchanged files
- Parallel tool execution
- Timeout and resource management

**Deliverables**:
- Caching system for tool results
- Parallel execution infrastructure

**Files to Create**:
- `backend/app/services/tool_cache.py` - Result caching

**Files to Modify**:
- `backend/app/services/tool_executor.py` - Add caching and parallel execution

**Caching Strategy**:
- Cache key: file hash + tool name + tool version
- TTL: Configurable (default 1 hour)
- Invalidate on file change

---

### Phase 11: Logging & Auditing (Task 16)
**Goal**: Track tool execution for auditability

**Tasks**:
- Add tool execution logging
- Track execution time, success/failure
- Store in audit log

**Deliverables**:
- Enhanced audit logging
- Tool execution metrics

**Files to Modify**:
- `backend/app/services/tool_executor.py` - Add logging
- `backend/app/core/audit.py` - Add tool execution events

**Audit Events**:
- Tool execution started
- Tool execution completed
- Tool execution failed
- Tool findings count

---

### Phase 12: Testing (Tasks 17-18)
**Goal**: Comprehensive integration tests

**Tasks**:
- Test Bandit integration with Python samples
- Test ESLint integration with JavaScript samples
- Test multi-tool scenarios
- Test argumentation with tool conflicts

**Deliverables**:
- Integration test suite
- Test fixtures with tool outputs

**Files to Create**:
- `tests/integration/test_bandit_integration.py`
- `tests/integration/test_eslint_integration.py`
- `tests/integration/test_multi_tool.py`
- `tests/fixtures/bandit_output.json`
- `tests/fixtures/eslint_output.json`

**Test Scenarios**:
- Single tool finding violation
- Multiple tools finding same violation
- Tool conflict resolution
- Tool exception arguments
- Proof bundle with tool metadata

---

### Phase 13: Documentation (Task 19)
**Goal**: Document static analysis integration

**Tasks**:
- Write integration guide
- Document tool configuration
- Create tool mapping guide
- Update API documentation

**Deliverables**:
- Static analysis integration guide
- Tool configuration documentation
- Tool mapping reference

**Files to Create**:
- `docs/STATIC_ANALYSIS_GUIDE.md`
- `docs/TOOL_CONFIGURATION.md`
- `docs/TOOL_MAPPINGS.md`

**Files to Modify**:
- `README.md` - Add static analysis section
- `docs/API.md` - Document new endpoints

---

### Phase 14: Performance Optimization (Task 20)
**Goal**: Optimize for production use

**Tasks**:
- Parallel tool execution
- Timeout management
- Resource limits
- Error recovery

**Deliverables**:
- Optimized tool execution
- Production-ready performance

**Files to Modify**:
- `backend/app/services/tool_executor.py` - Performance optimizations

**Optimizations**:
- Async/parallel tool execution
- Configurable timeouts per tool
- Memory limits
- Graceful degradation on tool failure

---

## Implementation Details

### Tool Configuration Structure

```python
# backend/app/core/static_analyzers.py

STATIC_ANALYZERS = {
    "python": {
        "bandit": {
            "command": ["bandit", "-f", "json", "-ll", "-r", "{target}"],
            "parser": "bandit_parser",
            "enabled": True,
            "timeout": 30,
            "requires_file": True,
            "output_format": "json"
        },
        "pylint": {
            "command": ["pylint", "--output-format=json", "{target}"],
            "parser": "pylint_parser",
            "enabled": False,
            "timeout": 60
        },
        "safety": {
            "command": ["safety", "check", "--json", "--file", "{target}"],
            "parser": "safety_parser",
            "enabled": True,
            "timeout": 20
        }
    },
    "javascript": {
        "eslint": {
            "command": ["eslint", "--format", "json", "{target}"],
            "parser": "eslint_parser",
            "enabled": True,
            "timeout": 30,
            "requires_config": ".eslintrc.json"
        }
    },
    "typescript": {
        "eslint": {
            "command": ["eslint", "--format", "json", "{target}"],
            "parser": "eslint_parser",
            "enabled": True,
            "timeout": 30
        }
    }
}
```

### Evidence Model Enhancement

```python
# backend/app/models/schemas.py

class Evidence(BaseModel):
    rule_id: str
    type: str  # "violation" | "compliance"
    tool: Optional[str] = None  # "bandit", "eslint", "regex", "ast", etc.
    tool_version: Optional[str] = None
    tool_rule_id: Optional[str] = None  # Tool-specific rule ID
    detector: str  # Keep for backward compatibility
    output: str
    confidence: Optional[str] = None  # "high", "medium", "low"
    location: Optional[Dict[str, Any]] = None  # file, line, column
```

### Tool Mapper Interface

```python
# backend/app/services/tool_mapper.py

class ToolMapper:
    def map_finding_to_policy(
        self, 
        tool_name: str, 
        tool_rule_id: str,
        finding: Dict[str, Any]
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Map a tool finding to an ACPG policy.
        
        Returns:
            Tuple of (policy_id, metadata) or None if no mapping
        """
        pass
```

---

## Risk Mitigation

### Security Risks
- **Tool Execution**: Run tools in sandboxed containers
- **Output Validation**: Validate and sanitize tool output
- **Command Injection**: Use subprocess with proper escaping

### Performance Risks
- **Slow Tools**: Implement timeouts and parallel execution
- **Large Outputs**: Stream parsing, limit output size
- **Resource Usage**: Monitor memory and CPU usage

### Reliability Risks
- **Tool Failures**: Graceful degradation, continue with other tools
- **False Positives**: Use confidence scores and exception arguments
- **Version Compatibility**: Pin tool versions, test compatibility

---

## Success Criteria

1. ✅ Bandit integration works for Python code
2. ✅ ESLint integration works for JavaScript/TypeScript
3. ✅ Multiple tools can check the same policy
4. ✅ Argumentation framework handles tool conflicts
5. ✅ Proof bundles include tool metadata
6. ✅ Frontend displays tool evidence
7. ✅ Performance is acceptable (< 10s for typical file)
8. ✅ All tests pass
9. ✅ Documentation is complete

---

## Timeline Estimate

- **Phase 1-2** (Foundation): 2-3 days
- **Phase 3** (Parsers): 3-4 days
- **Phase 4** (Mapping): 2 days
- **Phase 5** (Data Models): 1 day
- **Phase 6** (Prosecutor): 2 days
- **Phase 7** (Argumentation): 2-3 days
- **Phase 8** (Proof Bundles): 1 day
- **Phase 9** (Frontend): 2-3 days
- **Phase 10** (Caching): 1-2 days
- **Phase 11** (Logging): 1 day
- **Phase 12** (Testing): 3-4 days
- **Phase 13** (Documentation): 1-2 days
- **Phase 14** (Optimization): 1-2 days

**Total Estimate**: 23-30 days

---

## Dependencies

### External Tools (to be installed)
- **Bandit**: `pip install bandit`
- **ESLint**: `npm install -g eslint`
- **Semgrep**: `pip install semgrep` (optional)

### Python Packages
- No new packages required (use existing subprocess, json, etc.)

### System Requirements
- Node.js (for ESLint)
- Python 3.8+ (for Bandit)
- Sufficient disk space for tool outputs

---

## Future Enhancements

1. **More Tools**: Add Pylint, SonarQube, CodeQL, etc.
2. **Custom Rules**: Allow users to define custom tool rules
3. **Tool Comparison**: Compare findings across tools
4. **Historical Analysis**: Track tool findings over time
5. **CI/CD Integration**: Pre-commit hooks, GitHub Actions
6. **Tool Marketplace**: Community-contributed tool integrations


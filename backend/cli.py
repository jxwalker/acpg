#!/usr/bin/env python3
"""ACPG Command Line Interface.

Usage:
    python cli.py check --input code.py
    python cli.py enforce --input code.py --output fixed.py
    python cli.py list-policies
"""
import argparse
import json
import sys
import os
from pathlib import Path

# Add the backend app to path
sys.path.insert(0, str(Path(__file__).parent))

# Set default API key if not present (for non-AI operations)
if not os.environ.get("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = "not-required-for-analysis-only"


def cmd_check(args):
    """Check code for compliance violations."""
    from app.services import get_policy_compiler, get_prosecutor, get_adjudicator
    
    # Read input file
    with open(args.input, 'r') as f:
        code = f.read()
    
    # Detect language from extension
    ext = Path(args.input).suffix.lower()
    language = {'.py': 'python', '.js': 'javascript', '.ts': 'typescript'}.get(ext, 'python')
    
    print(f"🔍 Analyzing {args.input}...")
    print()
    
    # Run analysis
    prosecutor = get_prosecutor()
    analysis = prosecutor.analyze(code, language)
    
    # Adjudicate
    adjudicator = get_adjudicator()
    result = adjudicator.adjudicate(analysis)
    
    # Output results
    if result.compliant:
        print("✅ COMPLIANT - No violations detected")
        print(f"   Policies satisfied: {len(result.satisfied_rules)}")
    else:
        print("❌ NON-COMPLIANT")
        print(f"   Violations found: {len(analysis.violations)}")
        print()
        
        for v in analysis.violations:
            severity_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪'}.get(v.severity, '⚪')
            print(f"   {severity_icon} [{v.rule_id}] {v.description}")
            if v.line:
                print(f"      Line {v.line}: {v.evidence or ''}")
    
    # Output JSON if requested
    if args.json:
        output = {
            'compliant': result.compliant,
            'violations': [v.model_dump() for v in analysis.violations],
            'satisfied_rules': result.satisfied_rules,
            'unsatisfied_rules': result.unsatisfied_rules
        }
        print()
        print(json.dumps(output, indent=2))
    
    return 0 if result.compliant else 1


def cmd_enforce(args):
    """Enforce compliance by auto-fixing code."""
    from app.services import get_prosecutor, get_adjudicator, get_generator, get_proof_assembler
    from app.core.llm_config import get_llm_config
    
    # Check LLM configuration
    try:
        llm_config = get_llm_config()
        provider = llm_config.get_active_provider()
        print(f"🤖 Using LLM: {provider.name}")
    except Exception as e:
        print(f"❌ Error: Could not configure LLM: {e}")
        return 1
    
    # Read input file
    with open(args.input, 'r') as f:
        code = f.read()
    
    ext = Path(args.input).suffix.lower()
    language = {'.py': 'python', '.js': 'javascript', '.ts': 'typescript'}.get(ext, 'python')
    
    print(f"🔧 Enforcing compliance on {args.input}...")
    print()
    
    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()
    generator = get_generator()
    proof_assembler = get_proof_assembler()
    
    original_code = code
    max_iterations = args.iterations
    
    for iteration in range(max_iterations):
        print(f"   Iteration {iteration + 1}/{max_iterations}...")
        
        # Analyze
        analysis = prosecutor.analyze(code, language)
        result = adjudicator.adjudicate(analysis)
        
        if result.compliant:
            print()
            print("✅ COMPLIANT after", iteration + 1, "iteration(s)")
            
            # Write output
            output_path = args.output or args.input
            with open(output_path, 'w') as f:
                f.write(code)
            print(f"   Fixed code written to: {output_path}")
            
            # Generate proof if requested
            if args.proof:
                proof = proof_assembler.assemble_proof(
                    code=code,
                    analysis=analysis,
                    adjudication=result,
                    artifact_name=Path(output_path).name,
                    language=language
                )
                with open(args.proof, 'w') as f:
                    json.dump(proof.model_dump(), f, indent=2, default=str)
                print(f"   Proof bundle written to: {args.proof}")
            
            return 0
        
        # Try to fix
        print(f"      Found {len(analysis.violations)} violations, attempting fix...")
        try:
            code = generator.fix_violations(code, analysis.violations, language)
        except Exception as e:
            print(f"❌ Fix failed: {e}")
            return 1
    
    print()
    print(f"❌ Could not achieve compliance after {max_iterations} iterations")
    
    # Write partially fixed code if output specified
    if args.output:
        with open(args.output, 'w') as f:
            f.write(code)
        print(f"   Partially fixed code written to: {args.output}")
    
    return 1


def cmd_list_policies(args):
    """List all available policies."""
    from app.services import get_policy_compiler
    
    compiler = get_policy_compiler()
    policies = compiler.get_all_policies()
    
    print("📋 Available Policies")
    print("=" * 60)
    
    for p in sorted(policies, key=lambda x: (x.severity != 'critical', x.severity != 'high', x.id)):
        severity_icon = {
            'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪'
        }.get(p.severity, '⚪')
        type_label = '⚡ STRICT' if p.type == 'strict' else '〰️ DEFEASIBLE'
        
        print(f"\n{severity_icon} {p.id} [{type_label}]")
        print(f"   {p.description}")
        if p.fix_suggestion:
            print(f"   💡 Fix: {p.fix_suggestion}")
    
    print()
    print(f"Total: {len(policies)} policies")
    
    if args.json:
        output = [p.model_dump() for p in policies]
        print()
        print(json.dumps(output, indent=2))
    
    return 0


def cmd_generate_proof(args):
    """Generate a proof bundle for compliant code."""
    from app.services import get_prosecutor, get_adjudicator, get_proof_assembler
    
    with open(args.input, 'r') as f:
        code = f.read()
    
    ext = Path(args.input).suffix.lower()
    language = {'.py': 'python', '.js': 'javascript', '.ts': 'typescript'}.get(ext, 'python')
    
    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()
    proof_assembler = get_proof_assembler()
    
    analysis = prosecutor.analyze(code, language)
    result = adjudicator.adjudicate(analysis)
    
    if not result.compliant:
        print("❌ Code is not compliant, cannot generate proof")
        print(f"   Violations: {len(analysis.violations)}")
        return 1
    
    proof = proof_assembler.assemble_proof(
        code=code,
        analysis=analysis,
        adjudication=result,
        artifact_name=Path(args.input).name,
        language=language
    )
    
    output_path = args.output or f"{args.input}.proof.json"
    with open(output_path, 'w') as f:
        json.dump(proof.model_dump(), f, indent=2, default=str)
    
    print(f"✅ Proof bundle generated: {output_path}")
    print(f"   Hash: {proof.artifact.hash[:16]}...")
    print(f"   Decision: {proof.decision}")
    print(f"   Signature: {proof.signed['signature'][:32]}...")
    
    return 0


def cmd_init_hook(args):
    """Initialize pre-commit hook for the current repository."""
    import subprocess
    
    # Find git root
    try:
        git_root = subprocess.check_output(
            ['git', 'rev-parse', '--show-toplevel'],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except subprocess.CalledProcessError:
        print("❌ Error: Not in a git repository")
        return 1
    
    hooks_dir = Path(git_root) / '.git' / 'hooks'
    hook_file = hooks_dir / 'pre-commit'
    
    # Get ACPG API URL
    api_url = args.api_url or os.environ.get('ACPG_API_URL', 'http://localhost:8000')
    
    # Generate hook content
    hook_content = f'''#!/bin/bash
# ACPG Pre-commit Hook
# Automatically checks staged Python/JS/TS files for compliance violations
# Generated by: acpg init-hook

ACPG_API_URL="${{ACPG_API_URL:-{api_url}}}"

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

echo -e "${{YELLOW}}🔍 ACPG Pre-commit Check${{NC}}"

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(py|js|ts)$')

if [ -z "$STAGED_FILES" ]; then
    echo -e "${{GREEN}}✓ No Python/JS/TS files to check${{NC}}"
    exit 0
fi

FAILED=0
CHECKED=0

for FILE in $STAGED_FILES; do
    if [ -f "$FILE" ]; then
        echo -n "  Checking $FILE... "
        CHECKED=$((CHECKED + 1))
        
        # Get file content
        CONTENT=$(cat "$FILE")
        
        # Detect language
        case "${{FILE##*.}}" in
            py) LANG="python" ;;
            js) LANG="javascript" ;;
            ts) LANG="typescript" ;;
            *) LANG="python" ;;
        esac
        
        # Call ACPG API
        RESULT=$(curl -s -X POST "$ACPG_API_URL/api/v1/analyze" \\
            -H "Content-Type: application/json" \\
            -d "$(jq -n --arg code "$CONTENT" --arg lang "$LANG" \\
                '{{code: $code, language: $lang}}')" 2>/dev/null)
        
        if [ $? -ne 0 ] || [ -z "$RESULT" ]; then
            echo -e "${{YELLOW}}⚠ Could not reach ACPG API${{NC}}"
            continue
        fi
        
        # Check compliance
        VIOLATIONS=$(echo "$RESULT" | jq -r '.violations | length')
        
        if [ "$VIOLATIONS" = "0" ] || [ "$VIOLATIONS" = "null" ]; then
            echo -e "${{GREEN}}✓${{NC}}"
        else
            echo -e "${{RED}}✗ $VIOLATIONS violation(s)${{NC}}"
            echo "$RESULT" | jq -r '.violations[] | "    \\(.severity): [\\(.rule_id)] \\(.description)"' 2>/dev/null
            FAILED=$((FAILED + 1))
        fi
    fi
done

echo ""
if [ $FAILED -gt 0 ]; then
    echo -e "${{RED}}❌ Compliance check failed: $FAILED file(s) with violations${{NC}}"
    echo -e "${{YELLOW}}Run 'acpg enforce --input <file>' to auto-fix, or commit with --no-verify to skip${{NC}}"
    exit 1
else
    echo -e "${{GREEN}}✅ All $CHECKED file(s) passed compliance check${{NC}}"
    exit 0
fi
'''
    
    # Write hook
    with open(hook_file, 'w') as f:
        f.write(hook_content)
    
    # Make executable
    os.chmod(hook_file, 0o755)
    
    print(f"✅ Pre-commit hook installed: {hook_file}")
    print()
    print("Configuration:")
    print(f"  API URL: {api_url}")
    print()
    print("The hook will automatically check Python, JavaScript, and TypeScript")
    print("files for compliance violations before each commit.")
    print()
    print("To skip the hook temporarily, use: git commit --no-verify")
    print("To remove the hook, delete: " + str(hook_file))
    
    return 0


def cmd_init_config(args):
    """Initialize a new .acpgrc configuration file."""
    from app.core.project_config import generate_default_config
    
    output_file = Path(args.output) if args.output else Path('.acpgrc')
    
    if output_file.exists() and not args.force:
        print(f"❌ Config file already exists: {output_file}")
        print("   Use --force to overwrite")
        return 1
    
    format = 'json' if output_file.suffix == '.json' else 'yaml'
    generate_default_config(output_file, format)
    
    print(f"✅ Configuration file created: {output_file}")
    print()
    print("Edit this file to customize ACPG behavior for your project.")
    print("Documentation: https://github.com/jxwalker/acpg#configuration")
    
    return 0


def cmd_show_config(args):
    """Show current configuration."""
    from app.core.project_config import load_config, find_config_file
    
    config_path = find_config_file()
    
    if config_path:
        print(f"📄 Config file: {config_path}")
    else:
        print("📄 Config file: (using defaults)")
    
    print()
    
    config = load_config()
    
    print("Current configuration:")
    print(f"  API URL: {config.api_url}")
    print(f"  Fail on severity: {config.fail_on_severity}")
    print(f"  Auto-fix enabled: {config.auto_fix_enabled}")
    print(f"  Max iterations: {config.max_iterations}")
    print(f"  Output format: {config.output_format}")
    print()
    print(f"  Enabled policies: {config.enabled_policies or '(all)'}")
    print(f"  Disabled policies: {config.disabled_policies or '(none)'}")
    print(f"  Policy groups: {config.policy_groups or '(default)'}")
    print()
    print(f"  Include patterns: {config.include_patterns}")
    print(f"  Exclude patterns: {config.exclude_patterns}")
    
    return 0


def cmd_gen_hook(args):
    """Generate pre-commit hook script (output to stdout or file)."""
    api_url = args.api_url or os.environ.get('ACPG_API_URL', 'http://localhost:8000')
    
    hook_content = f'''#!/bin/bash
# ACPG Pre-commit Hook
# See: https://github.com/jxwalker/acpg

ACPG_API_URL="${{ACPG_API_URL:-{api_url}}}"

STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(py|js|ts)$')
[ -z "$STAGED" ] && exit 0

for f in $STAGED; do
  [ -f "$f" ] || continue
  lang=$(case "${{f##*.}}" in py) echo python;; js) echo javascript;; ts) echo typescript;; esac)
  result=$(curl -s -X POST "$ACPG_API_URL/api/v1/analyze" -H "Content-Type: application/json" \\
    -d "$(jq -n --arg c "$(cat $f)" --arg l "$lang" '{{code:$c,language:$l}}')")
  violations=$(echo "$result" | jq '.violations|length')
  [ "$violations" != "0" ] && [ "$violations" != "null" ] && {{
    echo "❌ $f: $violations violation(s)"
    echo "$result" | jq -r '.violations[]|"  [\\(.rule_id)] \\(.description)"'
    exit 1
  }}
done
echo "✅ ACPG: All files compliant"
'''
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(hook_content)
        os.chmod(args.output, 0o755)
        print(f"✅ Hook script written to: {args.output}")
    else:
        print(hook_content)
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="ACPG - Agentic Compliance and Policy Governor CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py check --input mycode.py
  python cli.py check --input mycode.py --json
  python cli.py enforce --input mycode.py --output fixed.py --proof proof.json
  python cli.py list-policies
  python cli.py proof --input clean_code.py --output proof.json
  python cli.py init-hook                    # Install pre-commit hook
  python cli.py gen-hook --output hook.sh    # Generate hook script
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Check command
    check_parser = subparsers.add_parser('check', help='Check code for compliance')
    check_parser.add_argument('--input', '-i', required=True, help='Input file to check')
    check_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    
    # Enforce command
    enforce_parser = subparsers.add_parser('enforce', help='Enforce compliance with auto-fix')
    enforce_parser.add_argument('--input', '-i', required=True, help='Input file')
    enforce_parser.add_argument('--output', '-o', help='Output file (default: overwrite input)')
    enforce_parser.add_argument('--proof', '-p', help='Write proof bundle to file')
    enforce_parser.add_argument('--iterations', '-n', type=int, default=3, help='Max fix iterations')
    
    # List policies command
    list_parser = subparsers.add_parser('list-policies', help='List available policies')
    list_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    
    # Proof command
    proof_parser = subparsers.add_parser('proof', help='Generate proof bundle')
    proof_parser.add_argument('--input', '-i', required=True, help='Input file')
    proof_parser.add_argument('--output', '-o', help='Output proof file')
    
    # Init hook command
    init_hook_parser = subparsers.add_parser('init-hook', help='Install pre-commit hook in current repo')
    init_hook_parser.add_argument('--api-url', help='ACPG API URL (default: http://localhost:8000)')
    
    # Gen hook command
    gen_hook_parser = subparsers.add_parser('gen-hook', help='Generate pre-commit hook script')
    gen_hook_parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    gen_hook_parser.add_argument('--api-url', help='ACPG API URL to use in hook')
    
    # Init config command
    init_config_parser = subparsers.add_parser('init-config', help='Create .acpgrc configuration file')
    init_config_parser.add_argument('--output', '-o', default='.acpgrc', help='Output file path')
    init_config_parser.add_argument('--force', '-f', action='store_true', help='Overwrite existing file')
    
    # Show config command
    show_config_parser = subparsers.add_parser('show-config', help='Show current configuration')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    commands = {
        'check': cmd_check,
        'enforce': cmd_enforce,
        'list-policies': cmd_list_policies,
        'proof': cmd_generate_proof,
        'init-hook': cmd_init_hook,
        'gen-hook': cmd_gen_hook,
        'init-config': cmd_init_config,
        'show-config': cmd_show_config,
    }
    
    return commands[args.command](args)


if __name__ == '__main__':
    sys.exit(main())


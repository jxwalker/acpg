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
    
    # Check for OpenAI API key
    if os.environ.get("OPENAI_API_KEY") == "not-required-for-analysis-only":
        print("❌ Error: OPENAI_API_KEY environment variable required for auto-fix")
        print("   Set it with: export OPENAI_API_KEY='your-key-here'")
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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    commands = {
        'check': cmd_check,
        'enforce': cmd_enforce,
        'list-policies': cmd_list_policies,
        'proof': cmd_generate_proof,
    }
    
    return commands[args.command](args)


if __name__ == '__main__':
    sys.exit(main())


#!/usr/bin/env python3
"""ACPG Command Line Interface.

Usage:
    acpg check --input code.py
    acpg enforce --input code.py --output fixed.py
    acpg list-policies
    acpg verify --proof proof.json
    acpg version
"""
import argparse
import json
import sys
import os
from pathlib import Path

__version__ = "1.0.0"

# Add the backend app to path
sys.path.insert(0, str(Path(__file__).parent))

# Set default API key if not present (for non-AI operations)
if not os.environ.get("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = "not-required-for-analysis-only"

# Quiet mode flag — suppress rich output when True
_quiet = False


def _get_console():
    """Get a rich Console instance."""
    from rich.console import Console
    return Console(quiet=_quiet)


def _detect_language(filepath):
    """Detect language from file extension."""
    ext = Path(filepath).suffix.lower()
    return {'.py': 'python', '.js': 'javascript', '.ts': 'typescript'}.get(ext, 'python')


def cmd_version(args):
    """Show ACPG version and system status."""
    console = _get_console()
    from rich.panel import Panel
    from rich.table import Table

    from app.services import get_policy_compiler
    from app.core.crypto import get_signer

    compiler = get_policy_compiler()
    policies = compiler.get_all_policies()
    signer = get_signer()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column()
    table.add_row("Version", __version__)
    table.add_row("Policies", str(len(policies)))
    table.add_row("Signer", signer.get_public_key_fingerprint())
    table.add_row("Algorithm", "ECDSA-SHA256 (SECP256R1)")

    # LLM status
    try:
        from app.core.llm_config import get_llm_config
        llm_config = get_llm_config()
        provider = llm_config.get_active_provider()
        table.add_row("LLM Provider", f"{provider.name} ({provider.model})")
    except Exception:
        table.add_row("LLM Provider", "[dim]not configured[/dim]")

    console.print(Panel(table, title="[bold]ACPG[/bold] — Agentic Compliance and Policy Governor", border_style="cyan"))
    return 0


def cmd_check(args):
    """Check code for compliance violations."""
    console = _get_console()
    from rich.table import Table
    from rich.panel import Panel
    from app.services import get_prosecutor, get_adjudicator

    with open(args.input, 'r') as f:
        code = f.read()

    language = _detect_language(args.input)

    with console.status(f"[cyan]Analyzing {args.input}..."):
        prosecutor = get_prosecutor()
        analysis = prosecutor.analyze(code, language)
        adjudicator = get_adjudicator()
        result = adjudicator.adjudicate(analysis)

    if args.json:
        output = {
            'compliant': result.compliant,
            'violations': [v.model_dump() for v in analysis.violations],
            'satisfied_rules': result.satisfied_rules,
            'unsatisfied_rules': result.unsatisfied_rules
        }
        console.print_json(json.dumps(output, default=str))
        return 0 if result.compliant else 1

    if result.compliant:
        console.print(Panel(
            f"[bold green]COMPLIANT[/bold green]\n\nPolicies satisfied: {len(result.satisfied_rules)}",
            title=f"[bold]{args.input}[/bold]",
            border_style="green"
        ))
    else:
        severity_styles = {'critical': 'bold red', 'high': 'red', 'medium': 'yellow', 'low': 'dim'}

        table = Table(title=f"Violations in {args.input}", show_lines=False)
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=12)
        table.add_column("Description")
        table.add_column("Line", width=6, justify="right")

        for v in analysis.violations:
            style = severity_styles.get(v.severity, '')
            table.add_row(
                f"[{style}]{v.severity.upper()}[/{style}]",
                v.rule_id,
                v.description,
                str(v.line) if v.line else "-"
            )

        console.print(table)
        console.print()
        console.print(f"[bold red]NON-COMPLIANT[/bold red] — {len(analysis.violations)} violation(s)")
        if not _quiet:
            console.print("[dim]Run [bold]acpg enforce --input {0}[/bold] to auto-fix[/dim]".format(args.input))

    return 0 if result.compliant else 1


def cmd_enforce(args):
    """Enforce compliance by auto-fixing code."""
    console = _get_console()
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from app.services import get_prosecutor, get_adjudicator, get_generator, get_proof_assembler
    from app.core.llm_config import get_llm_config

    try:
        llm_config = get_llm_config()
        provider = llm_config.get_active_provider()
        console.print(f"[cyan]LLM:[/cyan] {provider.name} ({provider.model})")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Could not configure LLM: {e}")
        return 1

    with open(args.input, 'r') as f:
        code = f.read()

    language = _detect_language(args.input)

    prosecutor = get_prosecutor()
    adjudicator = get_adjudicator()
    generator = get_generator()
    proof_assembler = get_proof_assembler()

    max_iterations = args.iterations

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Enforcing compliance...", total=None)

        for iteration in range(max_iterations):
            progress.update(task, description=f"Iteration {iteration + 1}/{max_iterations}: analyzing...")

            analysis = prosecutor.analyze(code, language)
            result = adjudicator.adjudicate(analysis)

            if result.compliant:
                progress.stop()
                console.print()
                console.print(Panel(
                    f"[bold green]COMPLIANT[/bold green] after {iteration + 1} iteration(s)",
                    border_style="green"
                ))

                output_path = args.output or args.input
                with open(output_path, 'w') as f:
                    f.write(code)
                console.print(f"[dim]Fixed code written to:[/dim] {output_path}")

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
                    console.print(f"[dim]Proof bundle written to:[/dim] {args.proof}")

                return 0

            progress.update(task, description=f"Iteration {iteration + 1}/{max_iterations}: fixing {len(analysis.violations)} violations...")
            try:
                code = generator.fix_violations(code, analysis.violations, language)
            except Exception as e:
                progress.stop()
                console.print(f"[bold red]Fix failed:[/bold red] {e}")
                return 1

    console.print()
    console.print(f"[bold red]Could not achieve compliance after {max_iterations} iterations[/bold red]")

    if args.output:
        with open(args.output, 'w') as f:
            f.write(code)
        console.print(f"[dim]Partially fixed code written to:[/dim] {args.output}")

    return 1


def cmd_list_policies(args):
    """List all available policies."""
    console = _get_console()
    from rich.table import Table
    from app.services import get_policy_compiler

    compiler = get_policy_compiler()
    policies = compiler.get_all_policies()

    if args.json:
        output = [p.model_dump() for p in policies]
        console.print_json(json.dumps(output, default=str))
        return 0

    table = Table(title=f"ACPG Policies ({len(policies)})")
    table.add_column("ID", width=14, style="cyan")
    table.add_column("Type", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Description")

    severity_styles = {'critical': 'bold red', 'high': 'red', 'medium': 'yellow', 'low': 'dim'}

    for p in sorted(policies, key=lambda x: (x.severity != 'critical', x.severity != 'high', x.id)):
        sev_style = severity_styles.get(p.severity, '')
        type_style = "bold" if p.type == 'strict' else "dim"
        table.add_row(
            p.id,
            f"[{type_style}]{p.type.upper()}[/{type_style}]",
            f"[{sev_style}]{p.severity.upper()}[/{sev_style}]",
            p.description
        )

    console.print(table)
    return 0


def cmd_generate_proof(args):
    """Generate a proof bundle for compliant code."""
    console = _get_console()
    from rich.panel import Panel
    from app.services import get_prosecutor, get_adjudicator, get_proof_assembler

    with open(args.input, 'r') as f:
        code = f.read()

    language = _detect_language(args.input)

    with console.status("[cyan]Analyzing and generating proof..."):
        prosecutor = get_prosecutor()
        adjudicator = get_adjudicator()
        proof_assembler = get_proof_assembler()

        analysis = prosecutor.analyze(code, language)
        result = adjudicator.adjudicate(analysis)

    if not result.compliant:
        console.print(f"[bold red]Code is not compliant — cannot generate proof[/bold red]")
        console.print(f"[dim]Violations: {len(analysis.violations)}[/dim]")
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

    console.print(Panel(
        f"[bold green]Proof bundle generated[/bold green]\n\n"
        f"[cyan]File:[/cyan]        {output_path}\n"
        f"[cyan]Hash:[/cyan]        {proof.artifact.hash[:24]}...\n"
        f"[cyan]Decision:[/cyan]    {proof.decision}\n"
        f"[cyan]Signature:[/cyan]   {proof.signed['signature'][:32]}...\n"
        f"[cyan]Algorithm:[/cyan]   {proof.signed.get('algorithm', 'ECDSA-SHA256')}",
        title="[bold]Proof Bundle[/bold]",
        border_style="green"
    ))

    return 0


def cmd_verify(args):
    """Verify a proof bundle's cryptographic signature."""
    console = _get_console()
    from rich.panel import Panel
    from rich.table import Table
    from app.services import get_proof_assembler
    from app.models.schemas import ProofBundle as ProofBundleModel

    with open(args.proof, 'r') as f:
        bundle_raw = json.load(f)

    signed = bundle_raw.get('signed', {})
    if not signed.get('signature'):
        console.print("[bold red]Invalid proof bundle — no signature found[/bold red]")
        return 1

    # Use the proof assembler's own verify method for correctness
    try:
        bundle = ProofBundleModel(**bundle_raw)
        proof_assembler = get_proof_assembler()
        valid = proof_assembler.verify_proof(bundle)
    except Exception:
        valid = False

    # Also verify code hash independently
    code = bundle_raw.get('code', '')
    artifact = bundle_raw.get('artifact', {})
    expected_hash = artifact.get('hash', '')
    import hashlib
    actual_hash = hashlib.sha256(code.encode()).hexdigest() if code else ''
    hash_valid = actual_hash == expected_hash if expected_hash else None

    # Build result display
    bundle = bundle_raw
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column()

    table.add_row("File", args.proof)
    table.add_row("Decision", bundle.get('decision', 'unknown'))
    table.add_row("Artifact", artifact.get('name', 'unknown'))
    table.add_row("Language", artifact.get('language', 'unknown'))
    table.add_row("Hash", expected_hash[:24] + "..." if expected_hash else "missing")
    table.add_row("Algorithm", signed.get('algorithm', 'unknown'))
    table.add_row("Signer", signed.get('signer', 'unknown'))

    table.add_row("", "")
    sig_status = "[bold green]VALID[/bold green]" if valid else "[bold red]INVALID[/bold red]"
    table.add_row("Signature", sig_status)

    if hash_valid is not None:
        hash_status = "[bold green]VALID[/bold green]" if hash_valid else "[bold red]TAMPERED[/bold red]"
        table.add_row("Code Hash", hash_status)

    if valid and (hash_valid is None or hash_valid):
        border = "green"
        title = "[bold green]Proof Verified[/bold green]"
    else:
        border = "red"
        title = "[bold red]Verification Failed[/bold red]"

    console.print(Panel(table, title=title, border_style=border))

    if args.json:
        output = {
            'valid': valid,
            'hash_valid': hash_valid,
            'decision': bundle.get('decision'),
            'artifact': artifact.get('name'),
            'signer': signed.get('signer'),
            'algorithm': signed.get('algorithm'),
        }
        console.print_json(json.dumps(output, default=str))

    return 0 if (valid and hash_valid is not False) else 1


def cmd_init_hook(args):
    """Initialize pre-commit hook for the current repository."""
    import subprocess
    console = _get_console()

    try:
        git_root = subprocess.check_output(
            ['git', 'rev-parse', '--show-toplevel'],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except subprocess.CalledProcessError:
        console.print("[bold red]Error:[/bold red] Not in a git repository")
        return 1

    hooks_dir = Path(git_root) / '.git' / 'hooks'
    hook_file = hooks_dir / 'pre-commit'

    api_url = args.api_url or os.environ.get('ACPG_API_URL', 'http://localhost:8000')

    hook_content = f'''#!/bin/bash
# ACPG Pre-commit Hook
# Automatically checks staged Python/JS/TS files for compliance violations
# Generated by: acpg init-hook

ACPG_API_URL="${{ACPG_API_URL:-{api_url}}}"

RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m'

echo -e "${{YELLOW}}ACPG Pre-commit Check${{NC}}"

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(py|js|ts)$')

if [ -z "$STAGED_FILES" ]; then
    echo -e "${{GREEN}}No Python/JS/TS files to check${{NC}}"
    exit 0
fi

FAILED=0
CHECKED=0

for FILE in $STAGED_FILES; do
    if [ -f "$FILE" ]; then
        echo -n "  Checking $FILE... "
        CHECKED=$((CHECKED + 1))
        CONTENT=$(cat "$FILE")
        case "${{FILE##*.}}" in
            py) LANG="python" ;;
            js) LANG="javascript" ;;
            ts) LANG="typescript" ;;
            *) LANG="python" ;;
        esac
        RESULT=$(curl -s -X POST "$ACPG_API_URL/api/v1/analyze" \\
            -H "Content-Type: application/json" \\
            -d "$(jq -n --arg code "$CONTENT" --arg lang "$LANG" \\
                '{{code: $code, language: $lang}}')" 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$RESULT" ]; then
            echo -e "${{YELLOW}}Could not reach ACPG API${{NC}}"
            continue
        fi
        VIOLATIONS=$(echo "$RESULT" | jq -r '.violations | length')
        if [ "$VIOLATIONS" = "0" ] || [ "$VIOLATIONS" = "null" ]; then
            echo -e "${{GREEN}}pass${{NC}}"
        else
            echo -e "${{RED}}$VIOLATIONS violation(s)${{NC}}"
            echo "$RESULT" | jq -r '.violations[] | "    \\(.severity): [\\(.rule_id)] \\(.description)"' 2>/dev/null
            FAILED=$((FAILED + 1))
        fi
    fi
done

echo ""
if [ $FAILED -gt 0 ]; then
    echo -e "${{RED}}Compliance check failed: $FAILED file(s) with violations${{NC}}"
    echo -e "${{YELLOW}}Run 'acpg enforce --input <file>' to auto-fix, or commit with --no-verify to skip${{NC}}"
    exit 1
else
    echo -e "${{GREEN}}All $CHECKED file(s) passed compliance check${{NC}}"
    exit 0
fi
'''

    with open(hook_file, 'w') as f:
        f.write(hook_content)
    os.chmod(hook_file, 0o755)

    console.print(f"[green]Pre-commit hook installed:[/green] {hook_file}")
    console.print(f"[dim]API URL: {api_url}[/dim]")
    console.print()
    console.print("The hook checks Python, JavaScript, and TypeScript files before each commit.")
    console.print("[dim]To skip: git commit --no-verify[/dim]")

    return 0


def cmd_init_config(args):
    """Initialize a new .acpgrc configuration file."""
    console = _get_console()
    from app.core.project_config import generate_default_config

    output_file = Path(args.output) if args.output else Path('.acpgrc')

    if output_file.exists() and not args.force:
        console.print(f"[bold red]Config file already exists:[/bold red] {output_file}")
        console.print("[dim]Use --force to overwrite[/dim]")
        return 1

    format = 'json' if output_file.suffix == '.json' else 'yaml'
    generate_default_config(output_file, format)

    console.print(f"[green]Configuration file created:[/green] {output_file}")
    console.print("[dim]Edit this file to customize ACPG behavior for your project.[/dim]")

    return 0


def cmd_show_config(args):
    """Show current configuration."""
    console = _get_console()
    from rich.table import Table
    from rich.panel import Panel
    from app.core.project_config import load_config, find_config_file

    config_path = find_config_file()
    config = load_config()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan")
    table.add_column()

    table.add_row("Config file", str(config_path) if config_path else "(defaults)")
    table.add_row("", "")
    table.add_row("API URL", config.api_url)
    table.add_row("Fail on severity", config.fail_on_severity)
    table.add_row("Auto-fix", str(config.auto_fix_enabled))
    table.add_row("Max iterations", str(config.max_iterations))
    table.add_row("Output format", config.output_format)
    table.add_row("", "")
    table.add_row("Enabled policies", ", ".join(config.enabled_policies) if config.enabled_policies else "(all)")
    table.add_row("Disabled policies", ", ".join(config.disabled_policies) if config.disabled_policies else "(none)")
    table.add_row("Policy groups", ", ".join(config.policy_groups) if config.policy_groups else "(default)")
    table.add_row("", "")
    table.add_row("Include", ", ".join(config.include_patterns))
    table.add_row("Exclude", ", ".join(config.exclude_patterns))

    console.print(Panel(table, title="[bold]ACPG Configuration[/bold]", border_style="cyan"))
    return 0


def cmd_gen_hook(args):
    """Generate pre-commit hook script (output to stdout or file)."""
    console = _get_console()
    api_url = args.api_url or os.environ.get('ACPG_API_URL', 'http://localhost:8000')

    hook_content = f'''#!/bin/bash
# ACPG Pre-commit Hook
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
    echo "FAIL $f: $violations violation(s)"
    echo "$result" | jq -r '.violations[]|"  [\\(.rule_id)] \\(.description)"'
    exit 1
  }}
done
echo "ACPG: All files compliant"
'''

    if args.output:
        with open(args.output, 'w') as f:
            f.write(hook_content)
        os.chmod(args.output, 0o755)
        console.print(f"[green]Hook script written to:[/green] {args.output}")
    else:
        print(hook_content)

    return 0


def main():
    global _quiet

    parser = argparse.ArgumentParser(
        description="ACPG — Agentic Compliance and Policy Governor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  acpg check --input mycode.py
  acpg check --input mycode.py --json
  acpg enforce --input mycode.py --output fixed.py --proof proof.json
  acpg verify --proof proof.json
  acpg list-policies
  acpg proof --input clean_code.py
  acpg init-hook
  acpg version
        """
    )

    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Version
    subparsers.add_parser('version', help='Show ACPG version and system status')

    # Check
    check_parser = subparsers.add_parser('check', help='Check code for compliance violations')
    check_parser.add_argument('--input', '-i', required=True, help='Input file to check')
    check_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')

    # Enforce
    enforce_parser = subparsers.add_parser('enforce', help='Enforce compliance with auto-fix')
    enforce_parser.add_argument('--input', '-i', required=True, help='Input file')
    enforce_parser.add_argument('--output', '-o', help='Output file (default: overwrite input)')
    enforce_parser.add_argument('--proof', '-p', help='Write proof bundle to file')
    enforce_parser.add_argument('--iterations', '-n', type=int, default=3, help='Max fix iterations (default: 3)')

    # Verify
    verify_parser = subparsers.add_parser('verify', help='Verify a proof bundle signature')
    verify_parser.add_argument('--proof', '-p', required=True, help='Proof bundle JSON file')
    verify_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')

    # List policies
    list_parser = subparsers.add_parser('list-policies', help='List available policies')
    list_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')

    # Proof
    proof_parser = subparsers.add_parser('proof', help='Generate proof bundle for compliant code')
    proof_parser.add_argument('--input', '-i', required=True, help='Input file')
    proof_parser.add_argument('--output', '-o', help='Output proof file')

    # Init hook
    init_hook_parser = subparsers.add_parser('init-hook', help='Install pre-commit hook in current repo')
    init_hook_parser.add_argument('--api-url', help='ACPG API URL (default: http://localhost:8000)')

    # Gen hook
    gen_hook_parser = subparsers.add_parser('gen-hook', help='Generate pre-commit hook script')
    gen_hook_parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    gen_hook_parser.add_argument('--api-url', help='ACPG API URL to use in hook')

    # Init config
    init_config_parser = subparsers.add_parser('init-config', help='Create .acpgrc configuration file')
    init_config_parser.add_argument('--output', '-o', default='.acpgrc', help='Output file path')
    init_config_parser.add_argument('--force', '-f', action='store_true', help='Overwrite existing file')

    # Show config
    subparsers.add_parser('show-config', help='Show current configuration')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    _quiet = args.quiet

    if args.verbose:
        os.environ['ACPG_VERBOSE'] = '1'

    commands = {
        'version': cmd_version,
        'check': cmd_check,
        'enforce': cmd_enforce,
        'verify': cmd_verify,
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

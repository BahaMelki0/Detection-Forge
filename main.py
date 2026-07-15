"""Detection Forge command-line interface."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from core.alerter import AlertStore
from core.pipeline import FILE_TYPES, InputSpec, analyze, input_from_profile, make_input
from core.rule_engine import RuleEngine, RuleError
from core.rule_manager import install_rule

ROOT = Path(__file__).resolve().parent
DEFAULT_RULES = ROOT / "rules"
DEFAULT_OUTPUT = ROOT / "data" / "alerts.json"

SEVERITY_COLORS = {
    "critical": "\033[1;91m",
    "high": "\033[1;38;5;208m",
    "medium": "\033[1;93m",
    "low": "\033[1;96m",
}
RESET_COLOR = "\033[0m"


class ForgeArgumentParser(argparse.ArgumentParser):
    """Keep subcommand help standard while presenting a useful product-level landing screen."""

    def __init__(self, *args, branded: bool = False, **kwargs):
        self.branded = branded
        super().__init__(*args, **kwargs)

    def format_help(self) -> str:
        if not self.branded:
            return super().format_help()
        colored = use_color("auto")

        def paint(value: str, code: str) -> str:
            return f"\033[{code}m{value}{RESET_COLOR}" if colored else value

        title = paint("DETECTION FORGE", "1;96")
        heading = lambda value: paint(value, "1;36")
        command = lambda value: paint(value, "1")
        return f"""{title}
Hybrid identity and endpoint threat detection

{heading('USAGE')}
  {command('python main.py analyze')} [options]       Analyze explicitly supplied telemetry
  {command('python main.py rules')} <command>         Manage detection rules

{heading('QUICK ANALYSIS')}
  python main.py analyze --file "signins.json" --type entra_signin

{heading('FILE TYPES')}
  entra_signin       Entra ID sign-in logs
  entra_audit        Entra ID directory audit logs
  entra_auto         Auto-detect the Entra log subtype
  windows_security   Windows Security event logs
  sysmon             Sysmon Operational logs

{heading('RULE COMMANDS')}
  rules list         Show the active detection registry
  rules validate     Validate a YAML rule or directory
  rules add FILE     Validate and install a new rule

Run {command('python main.py <command> -h')} for command-specific options.
"""
def build_parser() -> argparse.ArgumentParser:
    parser = ForgeArgumentParser(
        branded=True,
        description="Normalize telemetry, run detections, and manage detection-as-code rules."
    )
    subcommands = parser.add_subparsers(dest="command")

    analyze = subcommands.add_parser("analyze", help="Analyze one or more supplied log files.")
    analyze.add_argument(
        "--file", type=Path, action="append", required=True, metavar="PATH",
        help="JSON or JSONL file; repeat for multi-source analysis.",
    )
    analyze.add_argument(
        "--type", dest="file_types", action="append", required=True,
        choices=sorted(FILE_TYPES), metavar="TYPE",
        help="File type paired by order with --file.",
    )
    _add_detection_options(analyze)

    rules = subcommands.add_parser("rules", help="List, validate, or install YAML detection rules.")
    rule_commands = rules.add_subparsers(dest="rules_command", required=True)
    list_rules = rule_commands.add_parser("list", help="List active rules.")
    list_rules.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    list_rules.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    list_rules.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    validate = rule_commands.add_parser("validate", help="Validate a rule file or directory.")
    validate.add_argument("path", type=Path, nargs="?", default=DEFAULT_RULES)
    add = rule_commands.add_parser("add", help="Validate and install one YAML rule.")
    add.add_argument("file", type=Path)
    add.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    add.add_argument("--category", choices=("auto", "entra", "windows", "cross_source"), default="auto")
    return parser


def _add_detection_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")


def inputs_from_args(args: argparse.Namespace) -> list[InputSpec]:
    if len(args.file) != len(args.file_types):
        raise ValueError(
            f"Received {len(args.file)} --file value(s) but {len(args.file_types)} --type value(s); "
            "each file requires one type"
        )
    specifications = []
    for path, profile in zip(args.file, args.file_types):
        specifications.append(input_from_profile(profile, path))
    return specifications


def run_detection(inputs: list[InputSpec], rules_path: Path, output: Path, color_mode: str) -> tuple[int, int]:
    events, alerts, input_counts = analyze(inputs, rules_path)
    for specification, loaded_count in zip(inputs, input_counts):
        print(
            f"Loaded {loaded_count:>4} events  "
            f"source={specification.source:<7} type={specification.log_type:<8} file={specification.path}"
        )
    AlertStore(output).save(alerts)
    rule_count = len(RuleEngine.from_directory(rules_path).rules)
    print(f"\nProcessed {len(events)} events with {rule_count} rules")
    print(f"Generated {len(alerts)} alerts -> {output}")
    colored = use_color(color_mode)
    for alert in alerts:
        print(f"[{severity_label(alert.severity, colored)}] {alert.rule_id}  {alert.rule_title}")
    return len(events), len(alerts)


def list_active_rules(path: Path, color_mode: str, as_json: bool = False) -> int:
    rules = RuleEngine.from_directory(path).rules
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rules.sort(key=lambda rule: (severity_order.get(rule.severity, 99), rule.id))
    if as_json:
        values = [
            {"id": rule.id, "title": rule.title, "severity": rule.severity, "type": rule.type,
             "sources": list(rule.sources), "attack": rule.attack.get("id")}
            for rule in rules
        ]
        print(json.dumps(values, indent=2))
        return len(rules)
    colored = use_color(color_mode)
    print(f"{'SEVERITY':10} {'RULE ID':16} {'TYPE':13} {'SOURCES':18} ATT&CK / TITLE")
    print("-" * 96)
    for rule in rules:
        sources = ",".join(rule.sources)
        print(
            f"{severity_label(rule.severity, colored):10} {rule.id:16} {rule.type:13} "
            f"{sources:18} {rule.attack.get('id', '-')}  {rule.title}"
        )
    print(f"\n{len(rules)} active rules")
    return len(rules)


def use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or "NO_COLOR" in os.environ:
        return False
    return sys.stdout.isatty()


def severity_label(severity: str, colored: bool) -> str:
    label = severity.upper().ljust(8)
    if not colored:
        return label
    color = SEVERITY_COLORS.get(severity.lower(), "")
    return f"{color}{label}{RESET_COLOR}" if color else label


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command is None:
            parser.print_help()
        elif args.command == "analyze":
            run_detection(inputs_from_args(args), args.rules, args.output, args.color)
        elif args.rules_command == "list":
            list_active_rules(args.rules, args.color, args.json)
        elif args.rules_command == "validate":
            engine = RuleEngine.from_directory(args.path)
            print(f"Valid: {len(engine.rules)} rule(s) loaded from {args.path}")
        elif args.rules_command == "add":
            destination = install_rule(args.file, args.rules, args.category)
            print(f"Rule installed: {destination}")
    except (OSError, ValueError, RuleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cmax import __version__
from cmax import audit_cli

SECURITY_CRITICAL_EXIT = 2
AUDIT_CANCEL_EXIT = 130
AUDIT_TARGET_NAMES = audit_cli.AUDIT_TARGET_NAMES
class _TopLevelArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        usage = self.usage
        self.usage = argparse.SUPPRESS
        try:
            return super().format_help()
        finally:
            self.usage = usage


# Host role guard (see cmax.host_role). Every command that runs against a
# target adds its options with _add_target_confirmation_options, which adds
# --allow-cluster-node and names the work for the guard messages, and selects
# its target with target_selection.prepare_target, which runs the guard.
# Commands that start no work on a target are listed here. A test walks the
# whole parser tree, so a new or ported command that neither adds the options
# nor appears here fails the suite.
HOST_ROLE_EXEMPT_COMMANDS = frozenset({
    # Reads a saved audit; runs nothing on the cluster.
    "cmax audit review",
})


def host_role_unguarded_commands(parser: argparse.ArgumentParser) -> list[str]:
    """Return commands that skip the host role guard by mistake.

    A command is covered when it has --allow-cluster-node (added by
    _add_target_confirmation_options) or is in HOST_ROLE_EXEMPT_COMMANDS.
    An exemption that names no command is reported too, so the list stays
    current when a command is renamed or removed.
    """
    found: list[str] = []
    seen: set[str] = set()

    def walk(current: argparse.ArgumentParser, *, root: bool) -> None:
        for action in current._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child in dict.fromkeys(action.choices.values()):
                    walk(child, root=False)
        if root:
            return
        seen.add(current.prog)
        guarded = "--allow-cluster-node" in current._option_string_actions
        if not guarded and current.prog not in HOST_ROLE_EXEMPT_COMMANDS:
            found.append(current.prog)

    walk(parser, root=True)
    found.extend(
        f"{name} (exempt, but no such command)"
        for name in sorted(HOST_ROLE_EXEMPT_COMMANDS - seen)
    )
    return found


def _add_target_confirmation_options(
    parser: argparse.ArgumentParser, *, noun: str = "audit"
) -> None:
    """Add --yes and --allow-cluster-node and name the work for the guard."""
    parser.set_defaults(host_role_noun=noun)
    audit_cli.add_confirmation_options(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = _TopLevelArgumentParser(
        prog="cmax",
        usage="%(prog)s [-h] [-v] command ...",
        add_help=False,
        description="Audit the configuration and security of a GPU cluster.",
        epilog=f"commands:\n  audit  {audit_cli.AUDIT_HELP}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-h", "--help", action="help", help=argparse.SUPPRESS)
    parser.add_argument(
        "--repo",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-v",
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=argparse.ArgumentParser,
    )
    sub.help = argparse.SUPPRESS

    audit_cli.add_audit_parser(sub)
    return parser


def _resolve_audit_target(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    command: str,
    confirm: bool,
    keep_kubeconfig: bool = True,
):
    from cmax import security, target_selection

    noun = getattr(args, "host_role_noun", "audit")
    had_kubeconfig = "KUBECONFIG" in os.environ
    original_kubeconfig = os.environ.get("KUBECONFIG", "")

    def restore_kubeconfig() -> None:
        if had_kubeconfig:
            os.environ["KUBECONFIG"] = original_kubeconfig
        else:
            os.environ.pop("KUBECONFIG", None)

    try:
        target = security.detect_target(args.target)
        if not confirm:
            if not keep_kubeconfig or target.harness != "k8s":
                restore_kubeconfig()
            return target
        selected = target_selection.prepare_target(
            target,
            command=command,
            noun=noun,
            assume_yes=args.assume_yes,
            allow_cluster_node=getattr(args, "allow_cluster_node", False),
        )
        if selected.harness != "k8s":
            restore_kubeconfig()
        return selected
    except target_selection.TargetSelectionCancelled:
        restore_kubeconfig()
        print(f"cmax: {noun} canceled", file=sys.stderr)
        return None
    except (security.SecurityAuditError, target_selection.TargetSelectionError) as exc:
        restore_kubeconfig()
        parser.error(str(exc))


def _audit_verbosity(verbose: int) -> int:
    """Use level one as the minimum and default audit detail."""
    return min(max(verbose, 1), 3)


def _run_security(
    args: argparse.Namespace,
    passthrough: list[str],
    parser: argparse.ArgumentParser,
) -> int:
    from cmax import security

    try:
        if passthrough:
            parser.error(f"unrecognized arguments: {' '.join(passthrough)}")
        if args.output_format and not args.dry_run:
            parser.error("-o yaml requires --dry-run")
        if args.output_file and not (args.dry_run and args.output_format == "yaml"):
            parser.error("--output-file requires --dry-run -o yaml")
        if args.show or (args.dry_run and not args.output_format):
            args.show = True
            return _run_audit(
                args,
                parser,
                command="cmax audit security",
            )
        if args.dry_run:
            if args.verbose:
                parser.error("-v cannot be used with -o yaml")
            target = _resolve_audit_target(
                args,
                parser,
                command="cmax audit security",
                confirm=False,
            )
            if target is None:
                return AUDIT_CANCEL_EXIT
            rendered = security.format_security_plan_yaml(target, repo=args.repo)
            if args.output_file:
                path = Path(args.output_file)
                if path.exists():
                    parser.error(f"refusing to overwrite existing file: {path}")
                path.write_text(rendered)
            else:
                print(rendered, end="" if rendered.endswith("\n") else "\n")
            return 0
        # The fetch is on by default. `sync_minimum_table` never raises, so a
        # host with no outbound network access prints one warning and grades
        # against the installed table, exactly as before.
        if args.fetch_minimums:
            security.sync_minimum_table(repo=args.repo)
        return _run_audit(
            args,
            parser,
            command="cmax audit security",
            exit_on_fail=not args.exit_zero,
        )
    except security.SecurityAuditError as exc:
        parser.error(str(exc))


def _run_audit(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    command: str = "cmax audit",
    exit_on_fail: bool = False,
) -> int:
    category = args.audit_category
    if args.show:
        from cmax import audit_report, security

        try:
            target = _resolve_audit_target(
                args,
                parser,
                command=f"{command} --show",
                confirm=False,
                keep_kubeconfig=False,
            )
            if target is None:
                return AUDIT_CANCEL_EXIT
            runtime_root = security.find_runtime_root(args.repo)
            checks = audit_report.list_check_specs(
                runtime_root,
                category=category,
                harness=target.harness,
            )
            print(audit_report.format_check_specs(checks))
            return 0
        except (security.SecurityAuditError, ValueError) as exc:
            parser.error(str(exc))

    from cmax import audit_runner

    try:
        target = _resolve_audit_target(
            args,
            parser,
            command=command,
            confirm=True,
        )
        if target is None:
            return AUDIT_CANCEL_EXIT
        runner_options = dict(
            repo=args.repo,
            verbosity=_audit_verbosity(args.verbose),
            category=category,
            resolved_target=target,
        )
        if exit_on_fail:
            runner_options["exit_on_fail"] = True
        if args.output_dir:
            runner_options["output_dir"] = args.output_dir
        return audit_runner.run(**runner_options)
    except audit_runner.AuditError as exc:
        parser.error(str(exc))


def _run_audit_review(
    args: argparse.Namespace,
    passthrough: list[str],
    parser: argparse.ArgumentParser,
) -> int:
    from cmax import audit_review, security

    if passthrough:
        parser.error(f"unrecognized arguments: {' '.join(passthrough)}")
    try:
        rules_root = security.find_runtime_root(args.repo)
        artifacts = (
            audit_review.resolve_source(Path(args.review_source))
            if args.review_source
            else audit_review.find_latest(
                [Path.cwd(), *Path.cwd().parents, rules_root]
            )
        )
        return audit_review.run(
            artifacts,
            rules_root,
            verbosity=_audit_verbosity(args.verbose),
            commands=args.review_commands,
            interactive=False if args.review_no_interactive else None,
        )
    except (audit_review.AuditReviewError, security.SecurityAuditError) as exc:
        parser.error(str(exc))


# Commands that start a run and own the terminal until they finish. The banner
# marks where such an invocation begins, which a campaign of several commands
# otherwise leaves unmarked in the scrollback and in a screenshot. This release
# exposes only the audit command from the larger master CLI command surface.
_BANNER_COMMANDS = frozenset({"audit"})

# Flags that turn a run command into an inspection or a machine-readable plan.
# The banner goes to stdout, so it would corrupt those outputs.
_BANNER_SUPPRESSING_FLAGS = (
    "dry_run",
    "show",
    "output_format",
    "output_file",
)


def _show_banner(args: argparse.Namespace) -> None:
    """Draw the master CLI startup banner for a live terminal audit."""
    if getattr(args, "command", None) not in _BANNER_COMMANDS:
        return
    if any(getattr(args, flag, None) for flag in _BANNER_SUPPRESSING_FLAGS):
        return
    from cmax import banner

    banner.print_banner()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, passthrough = parser.parse_known_args(argv)
    audit_cli.finish_audit_args(args, parser)
    _show_banner(args)
    try:
        if args.command == "audit" and args.profile == "review":
            return _run_audit_review(args, passthrough, parser)
        if args.command == "audit" and args.profile == "security":
            return _run_security(args, passthrough, parser)
        if passthrough:
            parser.error(f"unrecognized arguments: {' '.join(passthrough)}")
        return _run_audit(args, parser)
    except KeyboardInterrupt:
        print("\n==> cmax: interrupted; active audit stopped", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

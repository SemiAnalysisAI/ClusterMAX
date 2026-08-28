from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cmax import __version__
from cmax.audit_profiles import AUDIT_CATEGORIES, AUDIT_CATEGORY_NAMES

SECURITY_CRITICAL_EXIT = 2
AUDIT_CANCEL_EXIT = 130
AUDIT_COMMAND_HELP = "Run the full cluster configuration and health audit."
AUDIT_TARGETS = (
    ("local", "Audit this local machine."),
    ("vm", "Audit this standalone virtual machine."),
    ("container", "Audit this standalone container."),
    ("standalone", "Audit this standalone bare-metal host."),
    ("slurm", "Audit the detected Slurm cluster."),
    ("k8s", "Audit the current Kubernetes cluster."),
)
AUDIT_TARGET_NAMES = tuple(name for name, _ in AUDIT_TARGETS)


class _TopLevelArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        usage = self.usage
        self.usage = argparse.SUPPRESS
        try:
            return super().format_help()
        finally:
            self.usage = usage


def _add_target_options(
    parser: argparse.ArgumentParser,
    *,
    dest: str = "target",
    suppress_default: bool = False,
) -> None:
    target = parser.add_mutually_exclusive_group()
    default = argparse.SUPPRESS if suppress_default else None
    for value, help_text in AUDIT_TARGETS:
        target.add_argument(
            f"--{value}",
            action="store_const",
            const=value,
            default=default,
            dest=dest,
            help=help_text,
        )


def _add_target_confirmation_options(
    parser: argparse.ArgumentParser,
    *,
    suppress_default: bool = False,
) -> None:
    default = argparse.SUPPRESS if suppress_default else False
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        default=default,
        dest="assume_yes",
        help="Accept the reported audit target without an interactive confirmation.",
    )
    parser.add_argument(
        "--kubeconfig",
        default=argparse.SUPPRESS if suppress_default else None,
        metavar="PATH",
        help="Use this kubeconfig when the audit target is Kubernetes.",
    )


def _add_full_audit_profile_options(
    parser: argparse.ArgumentParser, *, allow_target: bool
) -> None:
    parser.add_argument(
        "-s",
        "--show",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print the included audit checks without running them.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=argparse.SUPPRESS,
        help="Increase report detail. The default is -v; repeat up to -vvv.",
    )
    _add_target_confirmation_options(parser, suppress_default=True)
    if allow_target:
        _add_target_options(parser, dest="profile_target", suppress_default=True)


def build_parser() -> argparse.ArgumentParser:
    parser = _TopLevelArgumentParser(
        prog="cmax",
        usage="%(prog)s [-h] [-v] command ...",
        add_help=False,
        description="Audit the configuration and security of a GPU cluster.",
        epilog=f"commands:\n  audit  {AUDIT_COMMAND_HELP}",
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

    audit = sub.add_parser(
        "audit",
        prog="cmax audit",
        help=AUDIT_COMMAND_HELP,
        description=AUDIT_COMMAND_HELP,
    )
    audit_commands = audit.add_subparsers(
        dest="profile", title="audit profiles and targets"
    )
    security = audit_commands.add_parser(
        "security",
        help="Run the focused, read-only security report.",
        description="Run the focused, read-only security report.",
    )
    security.set_defaults(audit_category="security")
    for category in AUDIT_CATEGORIES:
        category_parser = audit_commands.add_parser(
            category.name,
            help=category.description,
            description=(
                f"{category.description} The standard audit wrapper runs the "
                "selected profile and saves the standard artifacts."
            ),
        )
        category_parser.set_defaults(audit_category=category.name)
        _add_full_audit_profile_options(category_parser, allow_target=True)

    for target_name, target_help in AUDIT_TARGETS:
        target_parser = audit_commands.add_parser(
            target_name,
            help=target_help,
            description=target_help,
        )
        target_parser.set_defaults(profile_target=target_name)
        _add_full_audit_profile_options(target_parser, allow_target=False)

    review = audit_commands.add_parser(
        "review",
        help="Review a saved audit without running checks.",
        description="Review a saved ClusterMAX audit without running checks.",
    )

    review.add_argument(
        "review_source",
        nargs="?",
        metavar="PATH",
        help=(
            "Audit directory, audit.values.json, or audit.out. "
            "Defaults to the newest saved audit."
        ),
    )
    review.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=argparse.SUPPRESS,
        help="Increase report detail. The default is -v; repeat up to -vvv.",
    )
    review.add_argument(
        "--command",
        action="append",
        default=[],
        dest="review_commands",
        metavar="COMMAND",
        help="Run one audit review command and exit. Repeat as needed.",
    )
    review.add_argument(
        "--no-interactive",
        action="store_true",
        dest="review_no_interactive",
        help="Print the saved audit report without starting the review prompt.",
    )

    audit.add_argument(
        "-s",
        "--show",
        action="store_true",
        help="Print the included audit without running it.",
    )
    _add_target_options(audit)
    _add_target_confirmation_options(audit)
    audit.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase report detail. The default is -v; repeat up to -vvv.",
    )

    security.add_argument(
        "-s",
        "--show",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print the included security checks without running them.",
    )
    security.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve the security plan without running it.",
    )
    security.add_argument(
        "-o",
        "--output",
        choices=("yaml",),
        dest="output_format",
        help="Print the dry-run plan as YAML.",
    )
    security.add_argument(
        "--output-file",
        metavar="PATH",
        help="Write dry-run output to a new file instead of standard output.",
    )
    _add_target_options(security, dest="profile_target", suppress_default=True)
    _add_target_confirmation_options(security, suppress_default=True)
    security.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=argparse.SUPPRESS,
        help="Increase report detail. The default is -v; repeat up to -vvv.",
    )
    security.add_argument(
        "--exit-zero",
        action="store_true",
        help="Return exit code 0 when the report has critical findings.",
    )
    security.add_argument(
        "--refresh-minimums",
        action="store_true",
        help="Update minimum versions before the audit runs.",
    )
    security.add_argument(
        "--no-fetch-minimums",
        action="store_false",
        dest="fetch_minimums",
        help=(
            "Do not read the published minimum version table from "
            "https://www.clustermax.ai/minimum-versions.json before the audit "
            "runs. By default the security audit fetches that table on "
            "startup, stores it in a user cache directory, and grades against "
            "it; a fetch failure prints a warning and the audit continues "
            "against the installed table. This flag skips the fetch, which "
            "keeps a committed audit result reproducible from the installed "
            "table on a host with no outbound network access."
        ),
    )

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

    had_kubeconfig = "KUBECONFIG" in os.environ
    original_kubeconfig = os.environ.get("KUBECONFIG", "")

    def restore_kubeconfig() -> None:
        if had_kubeconfig:
            os.environ["KUBECONFIG"] = original_kubeconfig
        else:
            os.environ.pop("KUBECONFIG", None)

    try:
        target_selection.apply_kubeconfig(args.kubeconfig)
        target = security.detect_target(args.target)
        if not confirm:
            if not keep_kubeconfig or target.harness != "k8s":
                restore_kubeconfig()
            return target
        selected = target_selection.prepare_audit_target(
            target,
            command=command,
            assume_yes=args.assume_yes,
            kubeconfig=args.kubeconfig,
        )
        if selected.harness != "k8s":
            restore_kubeconfig()
        return selected
    except target_selection.TargetSelectionCancelled:
        restore_kubeconfig()
        print("cmax: audit canceled", file=sys.stderr)
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
        # Refresh first. `sync_minimum_table` points CLUSTERMAX_MINIMUM_VERSIONS at
        # the fetch cache, and a later refresh would then write the locally
        # rebuilt table over the cached published bytes while the stored
        # validators still describe the published body.
        if args.refresh_minimums:
            security.refresh_minimum_table(repo=args.repo)
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
    category = getattr(args, "audit_category", None)
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
    _show_banner(args)
    try:
        if args.command == "audit" and args.profile == "review":
            return _run_audit_review(args, passthrough, parser)
        if args.command == "audit" and (
            args.profile == "security"
            or args.profile in AUDIT_CATEGORY_NAMES
            or args.profile in AUDIT_TARGET_NAMES
        ):
            profile_target = getattr(args, "profile_target", None)
            if args.target and profile_target:
                parser.error("audit target flags are mutually exclusive")
            if profile_target:
                args.target = profile_target
            if args.profile == "security":
                return _run_security(args, passthrough, parser)
        if passthrough:
            parser.error(f"unrecognized arguments: {' '.join(passthrough)}")
        return _run_audit(args, parser)
    except KeyboardInterrupt:
        print("\n==> cmax: interrupted; active audit stopped", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

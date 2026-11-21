"""Parser for the `cmax audit` command.

Keep this file the same in SemiAnalysisAI/ClusterMAX and
SemiAnalysisAI/ClusterMAX-internal. The internal repository adds its
checkout-only security options through `security_options`. See
scripts/1-audit/audit/SECURITY-CLI.md#internal-and-public-versions in the
internal repository.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable

from cmax.audit_profiles import AUDIT_CATEGORIES, AUDIT_CATEGORY_NAMES

AUDIT_HELP = "Run the cluster configuration and health audit."
SECURITY_HELP = "Run the focused, read-only security report."
REVIEW_HELP = "Review a saved audit without running checks."
AUDIT_TARGETS = (
    ("local", "Audit this local machine."),
    ("vm", "Audit this standalone virtual machine."),
    ("container", "Audit this standalone container."),
    ("standalone", "Audit this standalone bare-metal host."),
    ("slurm", "Audit the detected Slurm cluster."),
    ("k8s", "Audit the current Kubernetes cluster."),
)
AUDIT_TARGET_NAMES = tuple(name for name, _ in AUDIT_TARGETS)
PROFILE_NAMES = ("security", *AUDIT_CATEGORY_NAMES)
VERBOSE_HELP = "Increase report detail. The default is -v; repeat up to -vvv."

# Every option of every audit subcommand, with the value that it has when the
# user does not give it. The `audit` parser sets these, so each command reads
# the same namespace. A subcommand option has a suppressed default, so an
# option given before the subcommand stays set.
AUDIT_DEFAULTS = {
    "profile": None,
    "audit_category": None,
    "target": None,
    "profile_target": None,
    "show": False,
    "dry_run": False,
    "output_format": None,
    "output_file": None,
    "output_dir": None,
    "exit_zero": False,
    "fetch_minimums": True,
    "verbose": 0,
    "assume_yes": False,
    "allow_cluster_node": False,
    "review_source": None,
    "review_commands": [],
    "review_no_interactive": False,
    "host_role_noun": "audit",
}


def _default(suppress: bool, value: object) -> object:
    return argparse.SUPPRESS if suppress else value


def add_target_options(
    parser: argparse.ArgumentParser, *, suppress: bool = False, dest: str = "target"
) -> None:
    target = parser.add_mutually_exclusive_group()
    for value, help_text in AUDIT_TARGETS:
        target.add_argument(
            f"--{value}",
            action="store_const",
            const=value,
            dest=dest,
            default=_default(suppress, None),
            help=help_text,
        )


def add_confirmation_options(parser: argparse.ArgumentParser, *, suppress: bool = False) -> None:
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        dest="assume_yes",
        default=_default(suppress, False),
        help=(
            "Accept the reported target and every confirmation, including the "
            "host role and interface checks, without a prompt."
        ),
    )
    parser.add_argument(
        "--allow-cluster-node",
        action="store_true",
        dest="allow_cluster_node",
        default=_default(suppress, False),
        help="Run even when this host is a cluster node that the target does not fit.",
    )


def _add_verbose(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=_default(suppress, 0),
        help=VERBOSE_HELP,
    )


def _add_run_options(parser: argparse.ArgumentParser, *, show_help: str) -> None:
    parser.add_argument(
        "--show",
        action="store_true",
        default=argparse.SUPPRESS,
        help=show_help,
    )
    add_target_options(parser, suppress=True, dest="profile_target")
    add_confirmation_options(parser, suppress=True)
    _add_verbose(parser, suppress=True)


def add_audit_parser(
    sub: argparse._SubParsersAction,
    *,
    security_options: Callable[[argparse.ArgumentParser], None] | None = None,
) -> argparse.ArgumentParser:
    """Add `cmax audit` and its subcommands to `sub` and return the parser."""
    audit = sub.add_parser("audit", prog="cmax audit", help=AUDIT_HELP, description=AUDIT_HELP)
    audit.set_defaults(**AUDIT_DEFAULTS)
    audit.add_argument(
        "--show",
        action="store_true",
        help="Print the included audit checks without running them.",
    )
    add_target_options(audit)
    add_confirmation_options(audit)
    _add_verbose(audit, suppress=False)

    commands = audit.add_subparsers(dest="profile", title="commands", metavar="COMMAND")

    security = commands.add_parser("security", help=SECURITY_HELP, description=SECURITY_HELP)
    security.set_defaults(audit_category="security")
    _add_run_options(security, show_help="Print the included security checks without running them.")
    security.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Resolve the security plan without running it.",
    )
    security.add_argument(
        "-o",
        "--output",
        choices=("yaml",),
        dest="output_format",
        default=argparse.SUPPRESS,
        help="Print the dry-run plan as YAML.",
    )
    security.add_argument(
        "--output-file",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="Write dry-run output to a new file instead of standard output.",
    )
    security.add_argument(
        "--output-dir",
        metavar="DIR",
        default=argparse.SUPPRESS,
        help="Write audit logs and reports to this new directory.",
    )
    security.add_argument(
        "--exit-zero",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Return exit code 0 when the report has critical findings.",
    )
    security.add_argument(
        "--no-fetch-minimums",
        action="store_false",
        dest="fetch_minimums",
        default=argparse.SUPPRESS,
        help=(
            "Do not read the published minimum version table from "
            "https://semianalysisai.github.io/ClusterMAX/minimum-versions.json "
            "before the audit runs. By default the security audit fetches that "
            "table, stores it in a user cache directory, and grades against it. "
            "A fetch failure prints a warning, and the audit continues against "
            "the last fetched table or the installed table. This flag keeps a "
            "saved result reproducible on a host with no outbound network access."
        ),
    )
    if security_options is not None:
        security_options(security)

    for category in AUDIT_CATEGORIES:
        profile = commands.add_parser(
            category.name,
            help=category.description,
            description=category.description,
        )
        profile.set_defaults(audit_category=category.name)
        _add_run_options(profile, show_help="Print the included checks without running them.")

    review = commands.add_parser("review", help=REVIEW_HELP, description=REVIEW_HELP)
    review.add_argument(
        "review_source",
        nargs="?",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="Audit directory, audit.values.json, or audit.out. Defaults to the newest saved audit.",
    )
    _add_verbose(review, suppress=True)
    review.add_argument(
        "--command",
        action="append",
        dest="review_commands",
        metavar="COMMAND",
        default=argparse.SUPPRESS,
        help="Run summary, all, passes, show, find, raw, or paths and exit. Repeat as needed.",
    )
    review.add_argument(
        "--no-interactive",
        action="store_true",
        dest="review_no_interactive",
        default=argparse.SUPPRESS,
        help="Print the saved audit report without starting the review prompt.",
    )
    return audit


def finish_audit_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Merge a subcommand target into `args.target` and reject two targets."""
    if getattr(args, "command", None) != "audit":
        return
    if args.profile_target:
        if args.target and args.target != args.profile_target:
            parser.error("audit target flags are mutually exclusive")
        args.target = args.profile_target

import subprocess
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "cmax"
    / "scripts"
    / "1-audit"
    / "cluster-audit-k8s.sh"
)


def test_check_deadline_fallback_does_not_hold_command_substitution_open():
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("check_deadline() {")
    end = source.index("\n}", start) + len("\n}")
    function = source[start:end]

    script = f"""
command() {{
    if [[ "$1" == "-v" && "${{2:-}}" == "timeout" ]]; then
        return 1
    fi
    builtin command "$@"
}}
{function}
result="$(check_deadline 5 bash -c 'printf complete')"
[[ "$result" == "complete" ]]
"""

    subprocess.run(["bash", "-c", script], check=True, timeout=2)

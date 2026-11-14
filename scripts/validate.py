"""Run the repository's CI validation blocks locally, without duplicated logic.

Run with mcp/.venv/bin/python scripts/validate.py from any directory. The
workflow is trusted repository code; review it before running this command on
an untrusted checkout. Dependency installation and GitHub actions are excluded.
"""
import os
import subprocess
import sys
from pathlib import Path

import yaml


def main():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / '.github/workflows/validate.yml').read_text())
    environment = os.environ.copy()
    environment.update(workflow.get('env', {}))
    environment['PATH'] = str(Path(sys.executable).parent) + os.pathsep + environment['PATH']
    for step in workflow['jobs']['validate']['steps']:
        if 'run' not in step or step.get('name', '').startswith('Install dependencies'):
            continue
        print('CHECK:', step['name'], flush=True)
        result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', step['run']], cwd=root, env=environment, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

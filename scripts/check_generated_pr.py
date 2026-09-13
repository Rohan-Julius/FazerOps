"""CI entry point for W42's PR checks. See `src/fazerops/actions/growth/pr.py`.

    python scripts/check_generated_pr.py commits --base origin/main --head HEAD
    python scripts/check_generated_pr.py evidence --bundle .fazerops/proposals/gap-… --ledger .fazerops/ledger.jsonl
"""

import sys

from fazerops.actions.growth.pr import main

if __name__ == "__main__":
    sys.exit(main())

# Implementation Plan

# Build an offline CI auditor for PineBuild snapshots

## User Review Required

> [!IMPORTANT]
> The auditor will output findings in two files per snapshot: a machine‑readable JSON file (`findings.json`) and a human‑readable Markdown summary (`summary.md`).  Confirm that this output layout meets your expectations.
>
> The remediation queue will be a simple prioritized list (CSV) with the top two actions.  If you need a different format, let me know.

## Open Questions

> [!WARNING]
> **Prioritization criteria** – The policy does not assign explicit severity scores.  Should we prioritize by rule order (S1 highest, S5 lowest) or by a custom weight you prefer?
>
> > [ ] Use rule order as severity (S1 > S2 > … > S5).
> > [ ] Provide custom weights (specify).
>
> > [ ] Any other criteria (e.g., number of occurrences, impact on CI).

> [!CAUTION]
> **Output location** – Where should the auditor write its result files?  Options:
> - Inside each snapshot directory (`snapshot-one/output/` etc.)
> - A user‑specified output directory via `--out-dir`
> Please confirm.

## Proposed Changes

---
### Core auditor script

#### [NEW] [`auditor.py`](file:///C:/Users/hachn/.gemini/antigravity/brain/3edb4cbb-bb58-46c4-894b-8f8003954140/auditor.py)
- Implements a CLI using `argparse`.
- Accepts a snapshot root path.
- Loads `policy.md` rules (hard‑coded mapping for S1‑S5).
- Recursively scans the four content directories (`app/`, `tests/`, `docs/`, `build/`).
- Parses `inventory.json` and `ci.json` for token metadata and workflow definitions.
- Applies each rule, collects evidence, redacts token values while keeping `token_id`.
- Emits `findings.json` (list of dicts) and `summary.md` (human readable).

---
### Helper modules

#### [NEW] [`rules.py`](file:///C:/Users/hachn/.gemini/antigravity/brain/3edb4cbb-bb58-46c4-894b-8f8003954140/rules.py)
- Python functions for S1‑S5, each returning a list of finding dicts.
- Centralised rule definitions for easy testing/extension.

#### [NEW] [`utils.py`](file:///C:/Users/hachn/.gemini/antigravity/brain/3edb4cbb-bb58-46c4-894b-8f8003954140/utils.py)
- File I/O helpers, JSON loading, path normalisation, redaction utility.

---
### Remediation prioritizer

#### [NEW] [`prioritize.py`](file:///C:/Users/hachn/.gemini/antigravity/brain/3edb4cbb-bb58-46c4-894b-8f8003954140/prioritize.py)
- Takes the `findings.json` and produces `remediation_queue.csv` with rank, rule_id, description, suggested action.
- Uses the severity ordering requested in the open question.

---
### Documentation & example commands

#### [NEW] [`README_AUDIT.md`](file:///C:/Users/hachn/.gemini/antigravity/brain/3edb4cbb-bb58-46c4-894b-8f8003954140/README_AUDIT.md)
- Instructions for running the auditor on both snapshots.
- Sample invocation:
  ```
  python auditor.py candidate/inputs/snapshot-one --out-dir candidate/outputs/snapshot-one
  python prioritize.py candidate/outputs/snapshot-one/findings.json --out-dir candidate/outputs/snapshot-one
  ```

---
### Tests (optional but helpful)

#### [NEW] [`test_auditor.py`](file:///C:/Users/hachn/.gemini/antigravity/brain/3edb4cbb-bb58-46c4-894b-8f8003954140/test_auditor.py)
- Unit tests for each rule using a minimal handcrafted snapshot.

## Verification Plan

- Run the auditor on `snapshot-one` and `snapshot-two`.
- Inspect that `findings.json` contains entries for each rule that should fire (e.g., active token exposure, unsafe logging, etc.).
- Verify that token values are redacted but `token_id` remains.
- Check that `summary.md` lists at least two benign decisions and the risky findings.
- Ensure `remediation_queue.csv` ranks the top two actions.
- Execute the provided `README_AUDIT.md` commands on a fresh clone to confirm reproducibility.

---

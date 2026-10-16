# PineBuild Secrets and CI Audit - Walkthrough and Report

## 1. Executive Summary & Tool Architecture

This repository delivers a reproducible, offline auditor (`auditor.py`) and a prioritized remediation planner (`prioritize.py`) designed according to the PineBuild audit policy (rules S1 through S5).

### Key Architecture Decisions
- **Offline & Zero External Dependencies**: Runs entirely on Python 3.10+ standard library (`pathlib`, `json`, `fnmatch`, `argparse`).
- **Scanned vs Metadata Isolation**: Scans strictly content files (`app/`, `tests/`, `docs/`, `build/`). `inventory.json` is treated solely as classification metadata, preventing self-matching false positives.
- **Decision Engine (Risk + Benign)**: In addition to risks (findings), benign decisions are explicitly recorded with formal rationale and evidence, satisfying the acceptance criterion to prove policy-based suppression of `test_only` and `revoked_in_fixture` tokens.
- **Traceable Redaction**: All exposed tokens in outputs are masked while preserving `token_id`, file path, and line numbers to avoid credential leakage during reporting.

---

## 2. Environment & Execution Instructions

**Environment**:
- OS: Windows / Linux / macOS
- Python version: Python 3.10+ (Tested on Python 3.13.14)

### Reproducible Commands:

1. **Audit Snapshot One**:
   ```bash
   python auditor.py inputs/snapshot-one
   python prioritize.py inputs/snapshot-one/findings.json
   ```

2. **Audit Snapshot Two**:
   ```bash
   python auditor.py inputs/snapshot-two
   python prioritize.py inputs/snapshot-two/findings.json
   ```

3. **Execute Policy Verification Checks**:
   ```bash
   python test_auditor.py
   ```

4. **Execute Synthetic Mutation Stretch Check**:
   ```bash
   python test_synthetic.py
   ```

---

## 3. Findings Comparison Across Snapshots

### Snapshot One (5 Violations, 6 Benign Decisions)
- **S1 Plaintext Leak**: `app/env.txt:2` contains active token `release-active` (`DEMO...[REDACTED]...7C2`).
- **S2 Untrusted Execution**: Workflow `pr-build` runs untrusted code with active secret `release-active`.
- **S3 Permissive Access**: Workflow `pr-build` has `write-all` permissions.
- **S4 Logging Exposure**: Workflow `pr-build` has `log_environment=true` with active secret `release-active`.
- **S5 Sensitive File Publication**: Workflow `pr-build` artifacts publish `app/env.txt`.
- **Benign Evidence**:
  - `tests/mock.txt:2` (`local-test`) correctly suppressed as `test_only`.
  - `docs/rotation.txt:1` (`old-docs`) correctly suppressed as `revoked_in_fixture`.
  - `release` workflow permissions (`release-write` with tag trigger and trusted code) correctly accepted under S3.

### Snapshot Two (2 Violations, 10 Benign Decisions)
The team executed a credential rotation: `release-active` was revoked, `release-rotated` was generated as active, and `pr-build` permissions were restricted to `read-only` without environment logging or secret refs.
**However, the assumption that "rotation fixed everything" proved false**:
1. **S1 Plaintext Leak in Documentation**: In `docs/rotation.txt:2`, developers pasted a "temporary troubleshooting copy" containing active token `release-rotated` (`DEMO...[REDACTED]...9D4`).
2. **S5 Wildcard Publication**: While direct secret references were removed from `pr-build`, its artifact pattern was broadened to `app/*`, which wildcard-expands to match sensitive configuration file `app/env.txt`.
- **Benign Evidence**:
  - `app/env.txt:2` containing `DEMO_ACTIVE_RELEASE_7C2` is now safely evaluated as **BENIGN** because `inventory.json` marks it as `revoked_in_fixture`.

---

## 4. Prioritized Remediation Queue

The team operates under realistic operational limits: **1 immediate CI workflow change** and **1 scheduled repository cleanup**.

### Snapshot One Remediation:
1. **Immediate CI Workflow Change**: Remove secret `release-active` from workflow `pr-build` (Rule S2) and restrict permissions to `read-only` (Rule S3).
   *Rationale*: Exposing active credentials to untrusted PR code with write-all permissions is the highest threat vector for immediate CI compromise.
2. **Scheduled Repository Cleanup**: Remove plaintext token from `app/env.txt` and revoke/rotate `release-active` (Rule S1).
   *Rationale*: Eliminates source repository plaintext credential exposure.

### Snapshot Two Remediation:
1. **Immediate CI Workflow Change**: Narrow artifact publication patterns in workflow `pr-build` from `app/*` to explicit build outputs (e.g. `build/report.txt`) to avoid publishing sensitive `app/env.txt` (Rule S5).
   *Rationale*: Prevents automated leak of environment configuration in CI artifacts.
2. **Scheduled Repository Cleanup**: Purge active token `release-rotated` from `docs/rotation.txt` (Rule S1) and complete credential revocation.
   *Rationale*: Resolves the documentation leak introduced during troubleshooting.

---

## 5. Decision and Work Log

- **Prioritization Rationale**: CI execution risks that expose credentials or grant write permissions to untrusted actors were prioritized over static documentation references, as CI triggers are automated and attackable via external pull requests.
- **Obstacle & Response**:
  - *Obstacle*: PowerShell command-line interpretation encountered syntax conflicts with nested characters when running inline command-line blocks.
  - *Response*: Used clean Python script-based file manipulation and test runners, verifying execution integrity across multiple environments.
- **Validation and Refinement**:
  - Added unit test suite `test_auditor.py` asserting all 4 required check domains: active text detection, test/revoked suppression, exact permission/trigger policy, and artifact wildcard expansion.
  - Validated that `app/*` wildcard matching in snapshot-two correctly triggers S5 against configured sensitive file `app/env.txt`.
- **Limits & Next Steps**:
  - *Limits*: Scans current local filesystem contents; does not scan git commit history or deleted branches.
  - *Next Steps*: Integrate `auditor.py` as a pre-commit hook or offline PR gate, and add automated linting to forbid wildcard globs in artifact paths.

---

## 6. AI-Use Note

- **Tool Used**: Antigravity Assistant.
- **Accepted Output**: Core logic mapping S1-S5 rules to AST/JSON inspection, test suite assertions, and markdown summary formatter.
- **Corrected / Refined Output**: The initial draft proposed treating file paths in `tests/` or `docs/` as blanket exemptions. Verified against `policy.md` line 7: *"Test/documentation filename alone is not an exemption for an active token."* Corrected the logic so that active tokens are flagged regardless of filename, while only the token's `state` (`test_only` / `revoked_in_fixture`) triggers suppression.
import argparse, fnmatch, json, os, sys
from pathlib import Path

CONFIGURED_SENSITIVE_PATHS = ['app/env.txt', 'docs/rotation.txt']
SCANNED_DIRS = ['app', 'tests', 'docs', 'build']

def redact_token_value(val):
    if len(val) <= 6:
        return '[REDACTED]'
    return val[:4] + '...[REDACTED]...' + val[-3:]

def audit_snapshot(snapshot_dir):
    snapshot_dir = Path(snapshot_dir)
    inv_path = snapshot_dir / 'inventory.json'
    ci_path = snapshot_dir / 'ci.json'

    if not inv_path.is_file():
        raise FileNotFoundError('Missing inventory.json in ' + str(snapshot_dir))
    if not ci_path.is_file():
        raise FileNotFoundError('Missing ci.json in ' + str(snapshot_dir))

    with open(inv_path, 'r', encoding='utf-8') as f:
        inv_data = json.load(f)
    with open(ci_path, 'r', encoding='utf-8') as f:
        ci_data = json.load(f)

    tokens = inv_data.get('tokens', [])
    workflows = ci_data.get('workflows', [])

    active_tokens = {t['token_id']: t for t in tokens if t.get('state') == 'active_in_fixture'}
    non_active_tokens = {t['token_id']: t for t in tokens if t.get('state') != 'active_in_fixture'}

    findings = []
    benign_decisions = []

    disc_files = []
    for d in SCANNED_DIRS:
        target_dir = snapshot_dir / d
        if target_dir.is_dir():
            for root, _, files in os.walk(target_dir):
                for file in files:
                    disc_files.append(Path(root) / file)

    for file_path in disc_files:
        rel_path = file_path.relative_to(snapshot_dir).as_posix()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            continue

        for line_idx, line in enumerate(lines, start=1):
            for token in tokens:
                val = token['value']
                if val in line:
                    token_id = token['token_id']
                    state = token.get('state', 'unknown')
                    redacted = redact_token_value(val)
                    if state == 'active_in_fixture':
                        findings.append({
                            'rule_id': 'S1',
                            'severity': 'CRITICAL',
                            'file_path': rel_path,
                            'line': line_idx,
                            'token_id': token_id,
                            'redacted_evidence': 'Found active token ' + token_id + ' (' + redacted + ') at ' + rel_path + ':' + str(line_idx),
                            'rationale': 'Rule S1 violation: Active token value ' + token_id + ' exposed as plaintext in content file.',
                            'suggested_action': 'Remove plaintext token from ' + rel_path + ' and revoke/rotate ' + token_id + '.'
                        })
                    else:
                        benign_decisions.append({
                            'rule_id': 'S1',
                            'status': 'BENIGN',
                            'file_path': rel_path,
                            'line': line_idx,
                            'token_id': token_id,
                            'state': state,
                            'redacted_evidence': 'Matched token ' + token_id + ' (' + redacted + ') with non-active state ' + state + ' at ' + rel_path + ':' + str(line_idx),
                            'rationale': 'Token ' + token_id + ' has state ' + state + '. Policy states test_only or revoked_in_fixture tokens do not represent current credential exposure.',
                            'suggested_action': 'No remediation required. Maintain token as test/documentation fixture.'
                        })

    for wf in workflows:
        wf_id = wf.get('workflow_id', 'unnamed')
        trigger = wf.get('trigger')
        runs_untrusted = wf.get('runs_untrusted_code', False)
        secret_refs = wf.get('secret_refs', [])
        permissions = wf.get('permissions')
        log_env = wf.get('log_environment', False)
        artifact_paths = wf.get('artifact_paths', [])

        wf_active_secrets = [ref for ref in secret_refs if ref in active_tokens]
        wf_non_active_secrets = [ref for ref in secret_refs if ref in non_active_tokens]

        if runs_untrusted:
            if wf_active_secrets:
                findings.append({
                    'rule_id': 'S2',
                    'severity': 'HIGH',
                    'workflow_id': wf_id,
                    'secret_refs': wf_active_secrets,
                    'redacted_evidence': 'Workflow ' + wf_id + ' has runs_untrusted_code=true and references active secrets: ' + str(wf_active_secrets),
                    'rationale': 'Rule S2 violation: runs_untrusted_code=true with active secret_ref is unsafe secret availability.',
                    'suggested_action': 'Remove active secrets ' + str(wf_active_secrets) + ' from workflow ' + wf_id + ' or avoid running untrusted code.'
                })
            else:
                benign_decisions.append({
                    'rule_id': 'S2',
                    'status': 'BENIGN',
                    'workflow_id': wf_id,
                    'secret_refs': wf_non_active_secrets,
                    'redacted_evidence': 'Workflow ' + wf_id + ' runs untrusted code but has no active secret_refs',
                    'rationale': 'Untrusted execution without active secret references complies with secret availability policy.',
                    'suggested_action': 'No remediation required.'
                })
        else:
            benign_decisions.append({
                'rule_id': 'S2',
                'status': 'BENIGN',
                'workflow_id': wf_id,
                'secret_refs': secret_refs,
                'redacted_evidence': 'Workflow ' + wf_id + ' has runs_untrusted_code=false',
                'rationale': 'Untrusted code execution flag is false; secrets are not exposed to untrusted code.',
                'suggested_action': 'No remediation required.'
            })

        if permissions == 'write-all':
            findings.append({
                'rule_id': 'S3',
                'severity': 'HIGH',
                'workflow_id': wf_id,
                'permissions': permissions,
                'redacted_evidence': 'Workflow ' + wf_id + ' sets permissions=write-all',
                'rationale': 'Rule S3 violation: write-all permission is never permitted under policy.',
                'suggested_action': 'Reduce permissions of workflow ' + wf_id + ' to read-only (or release-write if tag trigger and trusted).'
            })
        elif permissions == 'release-write':
            if trigger == 'tag' and not runs_untrusted:
                benign_decisions.append({
                    'rule_id': 'S3',
                    'status': 'BENIGN',
                    'workflow_id': wf_id,
                    'permissions': permissions,
                    'redacted_evidence': 'Workflow ' + wf_id + ' has trigger=tag, runs_untrusted_code=false, permissions=release-write',
                    'rationale': 'Release-write permission is explicitly permitted for tag triggers without untrusted code.',
                    'suggested_action': 'No remediation required.'
                })
            else:
                findings.append({
                    'rule_id': 'S3',
                    'severity': 'HIGH',
                    'workflow_id': wf_id,
                    'permissions': permissions,
                    'redacted_evidence': 'Workflow ' + wf_id + ' has permissions=release-write with trigger=' + str(trigger) + ', runs_untrusted_code=' + str(runs_untrusted),
                    'rationale': 'Rule S3 violation: release-write is only allowed when trigger=tag and runs_untrusted_code=false.',
                    'suggested_action': 'Downgrade permissions of workflow ' + wf_id + ' to read-only.'
                })
        elif permissions == 'read-only':
            benign_decisions.append({
                'rule_id': 'S3',
                'status': 'BENIGN',
                'workflow_id': wf_id,
                'permissions': permissions,
                'redacted_evidence': 'Workflow ' + wf_id + ' has permissions=read-only',
                'rationale': 'Read-only permissions adhere to the principle of least privilege.',
                'suggested_action': 'No remediation required.'
            })
        else:
            findings.append({
                'rule_id': 'S3',
                'severity': 'HIGH',
                'workflow_id': wf_id,
                'permissions': permissions,
                'redacted_evidence': 'Workflow ' + wf_id + ' has invalid permissions ' + str(permissions),
                'rationale': 'Rule S3 violation: permissions must be read-only (or release-write under strict criteria).',
                'suggested_action': 'Set permissions in workflow ' + wf_id + ' to read-only.'
            })

        if log_env:
            if wf_active_secrets:
                findings.append({
                    'rule_id': 'S4',
                    'severity': 'MEDIUM',
                    'workflow_id': wf_id,
                    'secret_refs': wf_active_secrets,
                    'redacted_evidence': 'Workflow ' + wf_id + ' has log_environment=true with active secrets: ' + str(wf_active_secrets),
                    'rationale': 'Rule S4 violation: log_environment=true with active secret_ref models full environment logging.',
                    'suggested_action': 'Set log_environment=false on workflow ' + wf_id + ' or remove active secrets.'
                })
            else:
                benign_decisions.append({
                    'rule_id': 'S4',
                    'status': 'BENIGN',
                    'workflow_id': wf_id,
                    'secret_refs': wf_non_active_secrets,
                    'redacted_evidence': 'Workflow ' + wf_id + ' has log_environment=true but no active secrets',
                    'rationale': 'Environment logging is active but no active secret references exist.',
                    'suggested_action': 'No remediation required.'
                })
        else:
            benign_decisions.append({
                'rule_id': 'S4',
                'status': 'BENIGN',
                'workflow_id': wf_id,
                'redacted_evidence': 'Workflow ' + wf_id + ' has log_environment=false',
                'rationale': 'Environment logging is disabled.',
                'suggested_action': 'No remediation required.'
            })

        matched_sensitive = []
        for pattern in artifact_paths:
            for sensitive_path in CONFIGURED_SENSITIVE_PATHS:
                if fnmatch.fnmatch(sensitive_path, pattern):
                    matched_sensitive.append((pattern, sensitive_path))

        if matched_sensitive:
            for pattern, sensitive_path in matched_sensitive:
                findings.append({
                    'rule_id': 'S5',
                    'severity': 'HIGH',
                    'workflow_id': wf_id,
                    'pattern': pattern,
                    'matched_file': sensitive_path,
                    'redacted_evidence': 'Workflow ' + wf_id + ' artifact_paths pattern ' + pattern + ' matches configured sensitive file ' + sensitive_path,
                    'rationale': 'Rule S5 violation: artifact pattern matches sensitive file ' + sensitive_path + ', risking publication of secrets.',
                    'suggested_action': 'Update artifact_paths in workflow ' + wf_id + ' to exclude sensitive file ' + sensitive_path + '.'
                })
        else:
            benign_decisions.append({
                'rule_id': 'S5',
                'status': 'BENIGN',
                'workflow_id': wf_id,
                'artifact_paths': artifact_paths,
                'redacted_evidence': 'Workflow ' + wf_id + ' artifact_paths ' + str(artifact_paths) + ' do not match sensitive paths',
                'rationale': 'Artifact publication patterns do not capture any configured sensitive paths.',
                'suggested_action': 'No remediation required.'
            })

    return {
        'snapshot': str(snapshot_dir.name),
        'total_findings': len(findings),
        'total_benign_decisions': len(benign_decisions),
        'findings': findings,
        'benign_decisions': benign_decisions
    }

def format_summary_markdown(result):
    lines = []
    snapshot = result['snapshot']
    lines.append('# Audit Summary for Snapshot: ' + snapshot + '\n')
    lines.append('- **Total Findings (Risks):** ' + str(result['total_findings']))
    lines.append('- **Total Benign Decisions Recorded:** ' + str(result['total_benign_decisions']) + '\n')

    lines.append('## Identified Risks (Findings)\n')
    if not result['findings']:
        lines.append('No rule violations found.\n')
    else:
        for idx, f in enumerate(result['findings'], 1):
            target = f.get('workflow_id') or (f.get('file_path', '') + ':' + str(f.get('line', '')))
            sev = f.get('severity', 'UNKNOWN')
            ev = f.get('redacted_evidence', '')
            rat = f.get('rationale', '')
            act = f.get('suggested_action', '')
            lines.append('### ' + str(idx) + '. [' + f['rule_id'] + '] ' + target + ' (Severity: ' + sev + ')')
            lines.append('- **Evidence:** ' + ev + '')
            lines.append('- **Rationale:** ' + rat)
            lines.append('- **Suggested Action:** ' + act + '\n')

    lines.append('## Benign / Safe Decisions (Evidence of Policy Compliance and Suppression)\n')
    for idx, b in enumerate(result['benign_decisions'], 1):
        target = b.get('workflow_id') or (b.get('file_path', '') + ':' + str(b.get('line', '')))
        status = b.get('status', 'BENIGN')
        ev = b.get('redacted_evidence', '')
        rat = b.get('rationale', '')
        lines.append('### ' + str(idx) + '. [' + b['rule_id'] + '] ' + target + ' - ' + status)
        lines.append('- **Evidence:** ' + ev + '')
        lines.append('- **Rationale:** ' + rat + '\n')

    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description='PineBuild Offline Secrets and CI Auditor')
    parser.add_argument('snapshot_dir', type=str, help='Path to snapshot directory')
    parser.add_argument('--out-dir', type=str, default=None, help='Output directory')
    parser.add_argument('--stdout', action='store_true', help='Print summary to stdout')

    args = parser.parse_args()
    snapshot_path = Path(args.snapshot_dir).resolve()

    if not snapshot_path.is_dir():
        print('Error: Snapshot directory does not exist: ' + str(snapshot_path), file=sys.stderr)
        sys.exit(1)

    result = audit_snapshot(snapshot_path)

    out_dir = Path(args.out_dir).resolve() if args.out_dir else snapshot_path
    out_dir.mkdir(parents=True, exist_ok=True)

    findings_json_path = out_dir / 'findings.json'
    summary_md_path = out_dir / 'summary.md'

    with open(findings_json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    summary_text = format_summary_markdown(result)
    with open(summary_md_path, 'w', encoding='utf-8') as f:
        f.write(summary_text)

    if args.stdout or not args.out_dir:
        print(summary_text)
    print('\nAudit complete for ' + snapshot_path.name + '.')
    print(' - Findings: ' + str(findings_json_path))
    print(' - Summary: ' + str(summary_md_path))

if __name__ == '__main__':
    main()

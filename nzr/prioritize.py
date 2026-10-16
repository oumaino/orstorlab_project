import argparse, csv, json, sys
from pathlib import Path

def prioritize_findings(findings_data):
    findings = findings_data.get('findings', [])
    ci_findings = [f for f in findings if 'workflow_id' in f]
    repo_findings = [f for f in findings if 'file_path' in f]

    queue = []
    def ci_weight(f):
        rule = f.get('rule_id')
        weights = {'S2': 100, 'S3': 80, 'S5': 70, 'S4': 50}
        return weights.get(rule, 10)

    ci_findings_sorted = sorted(ci_findings, key=ci_weight, reverse=True)
    if ci_findings_sorted:
        top_ci = ci_findings_sorted[0]
        queue.append({
            'rank': 1,
            'category': 'Immediate Workflow Change (Capacity Limit: 1)',
            'target': top_ci.get('workflow_id'),
            'rule_id': top_ci.get('rule_id'),
            'severity': top_ci.get('severity'),
            'description': top_ci.get('rationale'),
            'action': top_ci.get('suggested_action')
        })

    if repo_findings:
        top_repo = repo_findings[0]
        target = top_repo.get('file_path') + ':' + str(top_repo.get('line'))
        queue.append({
            'rank': 2 if queue else 1,
            'category': 'Scheduled Repository Cleanup (Capacity Limit: 1)',
            'target': target,
            'rule_id': top_repo.get('rule_id'),
            'severity': top_repo.get('severity'),
            'description': top_repo.get('rationale'),
            'action': top_repo.get('suggested_action')
        })
    elif len(ci_findings_sorted) > 1:
        second_ci = ci_findings_sorted[1]
        queue.append({
            'rank': 2,
            'category': 'Secondary Workflow Remediation',
            'target': second_ci.get('workflow_id'),
            'rule_id': second_ci.get('rule_id'),
            'severity': second_ci.get('severity'),
            'description': second_ci.get('rationale'),
            'action': second_ci.get('suggested_action')
        })

    return queue

def main():
    parser = argparse.ArgumentParser(description='PineBuild Remediation Prioritizer')
    parser.add_argument('findings_json', type=str, help='Path to findings.json')
    parser.add_argument('--out-csv', type=str, default=None, help='Path to write CSV queue')

    args = parser.parse_args()
    findings_path = Path(args.findings_json).resolve()

    if not findings_path.is_file():
        print('Error: File not found: ' + str(findings_path), file=sys.stderr)
        sys.exit(1)

    with open(findings_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    queue = prioritize_findings(data)

    out_csv = Path(args.out_csv).resolve() if args.out_csv else findings_path.parent / 'remediation_queue.csv'

    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['rank', 'category', 'target', 'rule_id', 'severity', 'description', 'action']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in queue:
            writer.writerow(item)

    print('Prioritized queue written to ' + str(out_csv) + ':')
    for q in queue:
        print(' [' + str(q['rank']) + '] (' + q['category'] + ') Rule ' + q['rule_id'] + ' on ' + q['target'] + ' -> ' + q['action'])

if __name__ == '__main__':
    main()

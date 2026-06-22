import csv

records = []
with open('D:/DroidForensix/sample_metadata.csv', 'r', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        records.append(row)

analyzed = [r for r in records if r.get('status') == 'analyzed']
pending = [r for r in records if r.get('status') != 'analyzed']
error = [r for r in records if r.get('status', '').startswith('error')]
other = [r for r in records if r.get('status') not in ('analyzed', 'pending') and not r.get('status', '').startswith('error')]

print(f'Total: {len(records)}')
print(f'Analyzed: {len(analyzed)}')
print(f'Pending: {len(pending)}')
print(f'Errors: {len(error)}')
if pending:
    for r in pending:
        print(f'  {r["sample_name"]}: status={r["status"]}')

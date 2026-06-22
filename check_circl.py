import json

# Check one sample's C2 enrichment
f = 'D:/DroidForensix/analysis/work/00000a7eacfd7e392ea3aaee14bec0224e62bf72823a8101f6717d704dce3a79/step5_c2s.json'
with open(f) as fh:
    data = json.load(fh)

c2s = data.get('c2_infrastructure', [])
print(f'Total C2s: {len(c2s)}')
if c2s:
    first = c2s[0]
    has_circl = 'circl' in first
    print(f'Has CIRCL data: {has_circl}')
    print(f'C2 keys: {list(first.keys())}')
    if has_circl:
        print(f'CIRCL summary: pdns_domain={"Yes" if first["circl"].get("pdns_domain") else "No"}, pssl_ip={"Yes" if first["circl"].get("pssl_ip") else "No"}')
    else:
        print('No CIRCL enrichment found')
        
# Check pipeline_result.json instead
f2 = 'D:/DroidForensix/analysis/work/00000a7eacfd7e392ea3aaee14bec0224e62bf72823a8101f6717d704dce3a79/pipeline_result.json'
with open(f2) as fh:
    data2 = json.load(fh)
c2s2 = data2.get('c2_infrastructure', [])
if c2s2:
    first2 = c2s2[0]
    print(f'Pipeline result C2 keys: {list(first2.keys())}')
    has = 'circl' in first2
    print(f'Pipeline CIRCL: {has}')

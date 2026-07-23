import json, os
work_dir = r"D:\DroidForensix\analysis\work"
found = []
for d in os.listdir(work_dir):
    pr = os.path.join(work_dir, d, "pipeline_result.json")
    if os.path.isfile(pr):
        try:
            data = json.load(open(pr))
            c2 = data.get("c2_infrastructure", [])
            if c2:
                apk_path = data.get("apk_path", "")
                pkg = data.get("package_name", "N/A")
                found.append((d, len(c2), c2[0].get("domain", "?"), apk_path, pkg))
        except:
            pass

found.sort(key=lambda x: -x[1])
print(f"Found {len(found)} samples with C2:")
for d, count, first_domain, apk, pkg in found[:20]:
    apk_name = os.path.basename(apk) if apk else "?"
    print(f"  {d}  {count:2d} C2  first={first_domain}  pkg={pkg}  apk={apk_name}")

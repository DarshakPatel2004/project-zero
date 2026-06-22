# Android Sample Sources for DroidForensix

## Tier 1: Premium Sources (API Key Required)

### 1. AndroZoo ⭐ BEST
- **URL:** https://androzoo.uni.lu
- **API Key:** Yes — free for academic/research use
- **Size:** 20+ million APKs (both malware and benign)
- **How to request:**
  1. Go to https://androzoo.uni.lu/access
  2. Fill the form with your university email
  3. Mention "M.Sc. thesis on Android malware static analysis"
  4. Usually approved within 24-48 hours
- **Why it's best:** Massive collection, labeled with VirusTotal detections, sha256 indexed, simple REST API
- **Limit:** 10 downloads per minute

### 2. Koodous
- **URL:** https://koodous.com
- **API Key:** Yes — free for researchers
- **Size:** Curated Android malware, community-driven
- **How to request:**
  1. Create account at https://koodous.com/login
  2. Go to profile → API Key
  3. Email koodous team for higher rate limits if needed
- **Why good:** Community-curated, family labels, YARA rules available
- **Limit:** Rate-limited without approval

### 3. VirusShare
- **URL:** https://virusshare.com
- **API Key:** Requires account registration
- **Size:** Large malware corpus (not Android-specific)
- **How to request:**
  1. Register at https://virusshare.com/register
  2. Request access to Android subset
  3. Usually approved within a few days
- **Note:** Hashes only via API; downloads via torrent

---

## Tier 2: Free / No API Key Required

### 4. Contagio Mobile Dump ⭐ BEST FREE
- **URL:** https://contagiomobile.blogspot.com
- **API Key:** No
- **Size:** Hundreds of mobile malware samples
- **How to download:**
  1. Go to https://contagiomobile.blogspot.com
  2. Navigate to "Mobile Malware Dump" or specific family posts
  3. Download ZIP files (password: `infected`)
  4. Extract APKs manually
- **Why good:** High-quality, family-labeled, direct downloads
- **Limit:** Manual download, not programmatic

### 5. theZoo
- **URL:** https://github.com/ytisf/theZoo
- **API Key:** No
- **Size:** ~200 malware samples (mixed platforms)
- **How to use:**
  ```bash
  git clone https://github.com/ytisf/theZoo.git
  cd theZoo
  python3 theZoo.py
  # Search for android, download
  ```
- **Limit:** Mostly Windows; Android subset is small and outdated

### 6. MalwareBazaar (abuse.ch)
- **URL:** https://bazaar.abuse.ch
- **API Key:** No
- **Size:** Sparse Android coverage (~50-100 APKs)
- **How to use:**
  ```bash
  # Query via API (already scripted in scripts/download_samples.py)
  curl -X POST https://mb-api.abuse.ch/api/v1/ \
    -d 'query=get_taginfo' -d 'tag=apk' -d 'limit=100'
  ```
- **Limit:** Mostly Windows malware; Android samples are rare

---

## Tier 3: Curated GitHub Repos (No API Key)

### 7. AndroidMalware_2019
- **URL:** https://github.com/sk3ptre/AndroidMalware_2019
- **Size:** ~50 APKs from 2019, well-known families
- **How to use:**
  ```bash
  git clone https://github.com/sk3ptre/AndroidMalware_2019.git
  # APKs are in the repo directly
  ```

### 8. Android-Malware-Samples
- **URL:** https://github.com/ashishb/android-malware
- **Size:** ~100 APKs, organized by family
- **How to use:**
  ```bash
  git clone https://github.com/ashishb/android-malware.git
  # Find APKs in subdirectories
  ```

### 9. Drebin Dataset (Academic)
- **URL:** https://www.sec.cs.tu-bs.de/~danarp/drebin/
- **Size:** 5,560 malware samples from 2010-2012
- **How to request:**
  1. Email authors with research purpose
  2. Usually approved for academic use
- **Limit:** Old samples (2010-2012), but historically significant

---

## Tier 4: Benign / Legitimate APKs (Baseline)

### 10. F-Droid
- **URL:** https://f-droid.org
- **API Key:** No
- **Size:** 4,000+ open-source Android apps
- **How to use:** Already scripted in `scripts/download_samples.py`
- **Why needed:** Baseline entropy and string analysis comparison

### 11. APKMirror
- **URL:** https://www.apkmirror.com
- **API Key:** No
- **Size:** Popular commercial apps (WhatsApp, Instagram, etc.)
- **Limit:** No programmatic API; manual download or scraping

---

## Tier 5: Academic / Research Datasets (Registration Usually Required)

### 12. CICAndMal2017 (Canadian Institute for Cybersecurity)
- **URL:** https://www.unb.ca/cic/datasets/android-adware.html
- **API Key:** No — download after registration
- **Size:** ~10,000 Android malware samples (adware, ransomware, scareware, SMS malware)
- **How to request:**
  1. Go to https://www.unb.ca/cic/datasets/android-adware.html
  2. Fill the dataset request form with research purpose
  3. Download links are emailed after approval
- **Why good:** Large, labeled by malware category, includes network traffic captures
- **Limit:** Heavy download (tens of GB); must cite the dataset paper

### 13. AMD (Android Malware Dataset)
- **URL:** http://amd.arguslab.io
- **API Key:** No — direct download
- **Size:** ~24,000 malware samples from 2010–2016
- **How to use:**
  1. Visit http://amd.arguslab.io
  2. Download the dataset (torrent or HTTP)
  3. Samples are organized by family
- **Why good:** Large, family-labeled, widely used in research
- **Limit:** Older samples; dataset is ~120 GB unpacked

### 14. Drebin-215 / CCCS Android Malware Dataset
- **URL:** https://github.com/JJuhnDA/CCCSDataset
- **API Key:** No
- **Size:** 215 Android malware samples with family labels
- **How to use:**
  ```bash
  git clone https://github.com/JJuhnDA/CCCSDataset.git
  # APKs are in subdirectories by family
  ```
- **Why good:** Curated, malware families from real incidents
- **Limit:** Small but high quality

### 15. CIC-MalDroid-2020
- **URL:** https://www.unb.ca/cic/datasets/maldroid-2020.html
- **API Key:** No — registration required
- **Size:** ~12,000 malware + 2,000 benign APKs
- **How to request:**
  1. Go to https://www.unb.ca/cic/datasets/maldroid-2020.html
  2. Complete the dataset request form
- **Why good:** Balanced malware/benign set, family labels, modern samples
- **Limit:** Large download; registration can take a few days

### 16. MalShare
- **URL:** https://malshare.com
- **API Key:** Free API key required
- **Size:** Large repository of malware samples (not Android-specific)
- **How to request:**
  1. Register at https://malshare.com/register.php
  2. Generate an API key from your profile
  3. Query with `type:apk` or Android-specific hashes
- **Why good:** Good for targeted hash lookups
- **Limit:** Mostly Windows; Android samples need active hunting

### 17. VirusTotal Intelligence / Hunting
- **URL:** https://www.virustotal.com
- **API Key:** Premium (academic discounts available)
- **Size:** Massive
- **How to request:**
  1. Academic/researchers can apply for premium access via VirusTotal
  2. Use VT Intelligence queries like `type:apk positives:10+`
- **Why good:** Best for very recent, labeled malware
- **Limit:** Premium; strict rate limits

---

## Tier 6: Additional GitHub Repositories

### 18. AndroidMalware (dkongming)
- **URL:** https://github.com/dkongming/AndroidMalware
- **Size:** ~80 APKs, mixed families
- **How to use:**
  ```bash
  git clone https://github.com/dkongming/AndroidMalware.git
  ```

### 19. malware-samples (maldroid)
- **URL:** https://github.com/maldroid/malware-samples
- **Size:** ~40 APKs, CTF/research oriented
- **How to use:**
  ```bash
  git clone https://github.com/maldroid/malware-samples.git
  ```

### 20. Android-Malware-Samples (CyberNormie)
- **URL:** https://github.com/CyberNormie/MalwareSamples
- **Size:** Mixed; has an Android/ folder
- **How to use:**
  ```bash
  git clone https://github.com/CyberNormie/MalwareSamples.git
  ```

---

## Updated Notes

### MalwareBazaar API Access
As of 2026, `mb-api.abuse.ch` may return `401 Unauthorized` for unauthenticated requests.
Options:
1. Request a free API key at https://bazaar.abuse.ch/account/
2. Set `MALWAREBAZAAR_API_KEY` in `.env` and update `scripts/download_samples.py` to send it
3. Use the web UI for manual download if API access is unavailable

### AndroZoo
The AndroZoo `latest.csv.gz` metadata file is large (~2 GB compressed). Consider keeping it
and reusing it across runs to avoid re-downloading.

---

## Recommended Acquisition Strategy

### Immediate (Today)
1. **GitHub repos** — Run `scripts/fetch_github_malware.py` (~150-250 APKs)
2. **Contagio Mobile** — Download 20-30 APKs manually
3. **MalwareBazaar** — Request API key, then run `scripts/download_samples.py`
4. **F-Droid** — Run `scripts/download_samples.py --legit-only`
5. **CCCSDataset** — Clone `JJuhnDA/CCCSDataset` (~215 APKs)

### Short-term (1-3 days)
6. **AndroZoo** — Submit API key request NOW (best long-term source)
7. **Koodous** — Create account, get API key
8. **CICAndMal2017 / CIC-MalDroid-2020** — Submit dataset request forms
9. **AMD** — Download the AMD torrent/HTTP archive

### Backup
10. **VirusShare** — Register while waiting for AndroZoo
11. **MalShare** — Register for free API key

---

## Sample Target Breakdown

| Source | Count | Type | Status |
|--------|-------|------|--------|
| GitHub `ashishb/android-malware` | 307 | Malware | ✅ Fetched |
| GitHub `sk3ptre/AndroidMalware_2019` | 137 | Malware | ✅ Fetched (passworded ZIPs) |
| CICAndMal2017 (Adware/Scareware/SMSmalware) | 325 | Malware | ✅ Fetched |
| CICAndMal2017 (Ransomware/Benign) | — | Mixed | 🔲 Not found in `CICAndMal2017/` |
| CCCSDataset | ~215 | Malware | 🔲 Manual clone needed |
| Contagio Mobile | ~30 | Malware | 🔲 Manual download |
| MalwareBazaar | ~5-10 | Malware | ⚠️ API key now required |
| F-Droid | 8 | Legitimate | ✅ Fetched |
| AndroZoo-Drebin | 50 | Malware | ✅ Fetched |
| **Total** | **818** | Mixed | |
| AndroZoo / Koodous / CIC remainder | ~100+ | Both | 🔲 API/registration required |

---

## File Organization

```
samples/
├── malware/
│   ├── github/          # From cloned repos (ashishb, sk3ptre, dkongming, etc.)
│   ├── cccs/            # From CCCSDataset
│   ├── contagio/        # From Contagio Mobile
│   ├── bazaar/          # From MalwareBazaar
│   ├── koodous/         # From Koodous
│   └── androzoo/        # From AndroZoo (when approved)
└── legitimate/
    └── fdroid/          # From F-Droid
```

All samples are tracked in `sample_metadata.csv` with source, family, and SHA-256.

## Quick Fetch Commands

```bash
# Activate environment
source venv/bin/activate

# Fetch from GitHub repos (no API key)
python scripts/fetch_github_malware.py

# Fetch from CCCSDataset (no API key)
git clone https://github.com/JJuhnDA/CCCSDataset.git /tmp/cccs
python scripts/fetch_github_malware.py --cccs /tmp/cccs

# Fetch legitimate baseline
python scripts/download_samples.py --legit-only

# Fetch from AndroZoo (requires ANDROZOO_API_KEY)
source .env
python scripts/download_drebin_androzoo.py data/drebin_sha256_family.csv 100

# Fetch from MalwareBazaar (API key may be required)
python scripts/download_samples.py --malware-only
```

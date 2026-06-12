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

## Recommended Acquisition Strategy

### Immediate (Today)
1. **Contagio Mobile** — Download 20-30 APKs manually
2. **GitHub repos** — Clone AndroidMalware_2019 and ashishb/android-malware (~150 APKs)
3. **MalwareBazaar** — Run our script, harvest whatever Android samples exist (~5-10)
4. **F-Droid** — Download 10 legitimate apps for baseline

### Short-term (1-3 days)
5. **AndroZoo** — Submit API key request NOW (best long-term source)
6. **Koodous** — Create account, get API key

### Backup
7. **VirusShare** — Register while waiting for AndroZoo

---

## Sample Target Breakdown

| Source | Expected Count | Type |
|--------|---------------|------|
| GitHub repos | ~150 | Malware |
| Contagio Mobile | ~30 | Malware |
| MalwareBazaar | ~10 | Malware |
| F-Droid | ~10 | Legitimate |
| **Total immediate** | **~200** | Mixed |
| AndroZoo (pending) | ~50+ | Both |

---

## File Organization

```
samples/
├── malware/
│   ├── github/          # From cloned repos
│   ├── contagio/        # From Contagio Mobile
│   ├── bazaar/          # From MalwareBazaar
│   └── androzoo/        # From AndroZoo (when approved)
└── legitimate/
    └── fdroid/          # From F-Droid
```

All samples are tracked in `sample_metadata.csv` with source, family, and SHA-256.

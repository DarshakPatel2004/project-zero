# Screenshot Analysis — `ss/`

**Source:** 7 PNG captures of DroidForensix served at `http://localhost:5173`,
taken 17:30:56 → 17:32:16 on 2026-06-17 (~80 s of interaction).

**Toolchain used:** PNGs were OCR'd with `easyocr` (English model) since the Read
tool did not surface image content in this session. Per-image text dumps and a
combined JSON live in `ss_ocr/`. Frontend source at
`frontend/src/components/{AnalysisView,SmartDissection,ThreatIntelView,UploadPanel}.jsx`
was used to corroborate ambiguities.

**Sample under analysis (every screen):** SHA-256
`0000b2ee9720dd6028e5cac22cb3689f1067dd26…` (truncated), **1085.5 KB**, 179 classes,
916 strings. Package metadata mostly **Unknown** — the APK uploaded evidently
has stripped/non-standard manifest metadata.

---

## Persistent chrome (present on every screen)

* **Top bar** (y≈41–63): logo `DroidForensix` + tagline `DF | ANDROID MALWARE
  INTELLIGENCE` (left), page name in the middle (`Analysis Results` →
  `Threat Intelligence` after navigation at 17:32:08), `Backend Online`
  status pill (right, x≈1831).
* **Left rail** (x≈148–160):
  - `Upload & Analyze` (top, ~y 178) — the only nav entry.
  - `Analysis Results` (~y 246).
  - `Threat Intelligence` (~y 313) — second nav entry, becomes the active page
    on the last two screenshots.
* **Sticky footer** (~y 1043–1299): `Static Analysis Pipeline · CONNECTED`.

The OCR caught every page-name change, so the 7 frames represent a clean linear
flow through `Upload & Analyze` → `Analysis Results` (5 sub-tabs) → `Threat
Intelligence` (loading + dashboard).

---

## Screen 1 — `17_30_56.png` (1920×1386) — **Overview tab**

The main result page for the analyzed sample, default tab (`Overview`).

**Header card (right side, ~y 237–285):** a big `RISK` gauge with the verdict
`UNKNOWN LOW` underneath. Sample headline: `Unknown Package`,
`SHA256: 0000b2ee9720dd6028e5cac22cb3689f…`.

**KPI strip (y≈430–463), left → right:**

| Metric | Value |
|---|---|
| C2 Endpoints | 1 |
| Threat Chains | 88 |
| Obfuscation | 0 / 100 |
| Permissions | 0 |

**Tab bar (y≈551):** `Overview | Code Dissection | C2 Infrastructure | Threat
Chains | Manifest` — Overview is the active tab.

**Two-column body:**

* **Left — SAMPLE DETAILS** (y≈643–960):
  * Package Name → `Unknown`
  * SHA-256 → `0000b2ee9720dd6028e5cac22cb3689f1067dd26…` (truncated)
  * File Size → `1085.5 KB`
  * Classes → `179`
  * Total Strings → `916`
  * Encodings → (empty, no value rendered)
  * Payloads → (empty)
* **Right — RISK FACTORS** (y≈643+): shows a single bullet
  `1 C2 endpoint(s) detected`.

**Bottom — ASSESSMENT panel (y≈1265):** the LLM-as-a-judge card displays an
error: **`LLM assessment failed: [Errno 22] Invalid argument`**.
`Verdict: UNKNOWN` is shown above it.

**Verdict / classification on this sample:** the pipeline flags one C2 endpoint
and 88 threat chains but scores obfuscation 0/100, declares `UNKNOWN LOW` risk
and a null LLM verdict — i.e. a low-signal sample that produced one real
indicator plus a downstream LLM error.

**Notable issues:**
* `LLM assessment failed: [Errno 22] Invalid argument` is the headline
  problem on this screen. `[Errno 22]` is the OS-level "Invalid argument" code
  on Windows, typically raised by `subprocess`/file-handle APIs. Almost
  certainly an empty or unencoded string was passed to `subprocess.run`,
  `pathlib.Path.write_text`, or a sandbox API. Needs investigation in
  `analysis/step7_llm_assessment.py`.
* `Encodings` and `Payloads` rows render empty — no fallback "0" or "—".
* The risk verdict `UNKNOWN LOW` is rendered ambiguously: there is no
  clear visual separator between the gauge label `RISK` and the value
  `UNKNOWN LOW` immediately below it. EasyOCR also merged them, which
  suggests the spacing is too tight.

---

## Screen 2 — `17_31_22.png` (1920×1101) — **Code Dissection tab**

Same sample. User clicked `Code Dissection`.

The header card, KPI strip, and tab bar are identical to screen 1. The active
tab indicator has moved from `Overview` to `Code Dissection`.

**Body (y≈643+):**

* Filter row at the top of the tab: `Suspicious | All Classes | 470` (the
  `All Classes` toggle and a count of 470 entries), plus a search box on the
  right reading `Search class or method name…`.
* Section title: `SUSPICIOUS CLASSES` with `… result(s)` on the right.
* Empty state in the middle of the panel: **`No matching classes found`**.

**Issues:**
* `470` classes is shown next to `All Classes`, but the previous screen
  reported `Classes: 179`. That's a 2.6× discrepancy — either this tab
  counts inner/nested classes ordex separately, or one of the two numbers
  is wrong. Worth confirming whether `179` is the deduped top-level class
  count and `470` includes inner/anonymous classes.
* `… result(s)` literally renders three dots instead of a number
  (`{filtered.length} result(s)`) — the count is missing.
* The empty state is the only thing in the panel, but the filter row
  shows the Suspicious pill active with 0 results — so the tab itself
  is functional, just no suspicious classes matched.

---

## Screen 3 — `17_31_30.png` (1920×1012) — **C2 Infrastructure tab**

User clicked `C2 Infrastructure`.

Header & KPI strip identical. Tab bar: `C2 Infrastructure` active.

**Body:** a single C2 endpoint card.

* Top row: protocol badge `HTTPS`, confidence `90%`.
* URL: `https://collector.mobile.cnzz.com`  (OCR split this into
  `https: // collector.mobile.cnzz com` because of the way easyOCR handles
  punctuation and dots.)
* Meta row: `HOST / PORT — collector.mobile.cnzz.com : 443`
* Below: `TYPE — http_request` | `CLASSIFICATION — n/a`

**Other observations:**
* Only **1** C2 card is shown, matching the `1 C2 endpoint` KPI from screen 1.
* `cnzz.com` is a real domain — historically associated with Umeng / Alibaba's
  mobile analytics SDK. This explains the `Benign (SDK)` classification that
  appears on screen 7's C2 Classification panel. The classification of this
  one endpoint is `n/a` here because Phase 2 enrichment hasn't run yet.
* The card has no `Copy`, `Open in VirusTotal`, or `Whois` actions — a future
  affordance to add.

---

## Screen 4 — `17_31_38.png` (1920×1082) — **Threat Chains tab**

User clicked `Threat Chains`. Header & KPI strip identical. Tab bar: `Threat
Chains` active.

**Body:** one chain card visible, deep content.

* Card header: `chain_000`, severity badge `MEDIUM`, confidence `82%`.
* **Step 1 — ENCODED_STRING** (y≈737):
  `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIiOpJOxVuOODeRZ8pmGT3KdVB34b8mfgcY6UbjdmY880+D+X+8H2Sr8rOg+ull…`
  Source: `sources/com/cnzz/mobile/android/sdk/coos6g.java:89`
  (OCR mis-read dots as `l`; this is `cnzzlmobile → cnzz.mobile`.)
* **Step 2 — DECODING_FUNCTION:** `decode_base64()` at the same source
  location.
* **Step 3 — DECODED_ARTIFACT** (y≈974): a long base64-decoded blob of
  `@` / `-` / `:` punctuation + control characters, also linked to the same
  source line. This is the kind of output you get when you base64-decode a
  PEM-wrapped RSA public key that has been concatenated with garbage, or
  when the string is actually not base64 at all — the OCR garbling makes it
  hard to be sure, but visually it looks like the decoder ran on something
  that isn't a clean base64 string.

**Issues:**
* Only one chain rendered even though the KPI strip says **88 Threat
  Chains**. Either the table is paginated without a page indicator visible
  in the cropped frame, or only the highest-confidence chain is being shown
  by default with no obvious "view all" affordance.
* The decoded-artifact text overflows the card width — no truncation,
  wrapping, or "show more" toggle. The bottom of the artifact is also
  visually clipped at the page edge.
* The chain id `chain_000` plus the `chain_000` OCR is consistent with
  either a zero-indexed array or a missing id field — could be clearer
  (`chain_001`, or a UUID).

---

## Screen 5 — `17_31_46.png` (1920×1012) — **Manifest tab**

User clicked `Manifest`. Header & KPI strip identical. Tab bar: `Manifest`
active.

**Body — two columns:**

* **Left — APP DETAILS** (y≈643+):
  * Version Name → `Unknown`
  * Version Code → `Unknown`
  * Target SDK → `Unknown`
  * Min SDK → `Unknown`
* **Right — REQUESTED PERMISSIONS (0):** empty state `No permissions
  declared`.

**Issues:**
* All four version fields are `Unknown`. Either the manifest is missing
  from the APK, the parser doesn't extract them, or the sample was built
  without `versionName`/`versionCode`/SDK attributes (very unusual).
* `REQUESTED PERMISSIONS (0)` agrees with the `Permissions: 0` KPI,
  which is internally consistent — at least the manifest-side permission
  count matches.
* Combined with `Package Name: Unknown` from screen 1, **every**
  identity field on this sample is `Unknown`. The pipeline is reporting
  structural counts (179 classes, 916 strings, 1 C2, 88 chains) but no
  app metadata. Worth checking whether APK badging / `aapt dump badging`
  is being run at all for this sample.

---

## Screen 6 — `17_32_08.png` (1920×877) — **Threat Intelligence loading state**

User clicked the `Threat Intelligence` left-rail item. The page name in the
top bar switched from `Analysis Results` to `Threat Intelligence`. The
Analysis Results panels are no longer visible.

**Body:** a centered loading card.

* Title: `Loading Threat Intelligence`
* Subtitle: `Fetching C2 geo-location, DNS status, and classification data…`
* (A spinner or progress dots should be present to the right of the
  subtitle — OCR caught only `__.` from what is likely a CSS spinner.)

**Issues:**
* No progress percentage or phase indicator. The user has no idea whether
  this will take 1 second or 30.
* No "cancel" / "back to results" affordance.
* No skeleton of the upcoming dashboard — the screen jumps straight from
  a near-empty card to a fully populated dashboard (screen 7).

---

## Screen 7 — `17_32_16.png` (1920×1338) — **Threat Intelligence dashboard**

Page name in the top bar is now `Threat Intelligence`. Body is fully
populated.

**Page header (y≈194):**
* Title: `Threat Intelligence Dashboard`
* Subtitle: `Phase 2 enrichment: C2 verification, geo-location, and
  classification`

**KPI strip (4 cards, y≈350–393):** *(the OCR rendered `0%2` because two
adjacent cards `0` and `2` were merged — confirmed by source:
`StatCard value={c2s.length}` and `StatCard value={geoIps.length}`.)*

| Stat | Value | Source label |
|---|---|---|
| Total C2 Indicators | **2** | `c2s.length` |
| IPs Geo-Located | **0** | `geoIps.length` |
| Active C2 Rate | **0%** | `activeRate` |
| Malicious C2s | **0** | `classification.malicious` |

**Note on the `2`:** Phase 2 enrichment extracted **2** C2 indicators from
the single Phase 1 endpoint shown on screen 3 — likely the host split into
host + URL, or an additional related domain (e.g. a tracking subdomain).

**Malware family card (y≈530):** `MALWARE FAMILY — unknown` with a `NO
MATCH` badge on the right and the rationale
`no deterministic or LLM signal matched`.

**Two-column body:**

* **Left — DNS VERIFICATION STATUS** (y≈663): three status buckets
  `ACTIVE | LIKELY ACTIVE | DEAD` with no counts filled in below them (all
  three numbers render as blank/zero). The OCR shows the labels but no
  numeric values for these — consistent with `dns.active = dns.likely_active
  = dns.dead = 0` for this sample (since none of the 2 IPs resolved).
* **Right — C2 CLASSIFICATION** (y≈663–797):
  * `Benign (SDK)` — count `1`
  * `Suspicious` — count (blank)
  * `Malicious` — count (blank)
  * `Total C2s: …` (right side, y≈852) — the OCR didn't capture the
    number cleanly, but the source renders `Total C2s: {total}` where
    `total = c2s.length = 2`.

**Geographic Distribution (y≈951):** empty state `No geo-located IPs
available` — explains the `0` in the KPIs above. (Geo lookups either failed
or the IPs are hostnames without resolved A records.)

**THREAT INTELLIGENCE EXPORTS (y≈1195):** four download buttons:
* `CSV Blocklist` → `.csv`
* `STIX 2.0` → `.json`
* `YARA Rules` → `.yar`

(The OCR shows the third row as `Json` only — STIX is JSON. The fourth row
is `yar`. Three export formats are listed in source: CSV, STIX, YARA. The
labels also include the file extension as a sub-badge — that's why each
button is rendered with the format name on top and the extension on the
bottom line.)

**Issues:**
* The `0%2` OCR merge is a real visual problem too — the `0` (IPs
  Geo-Located) and `2` (Total C2 Indicators) cards are too close
  together, with no gutter that survives easyOCR. A spacing audit on
  `.threat-stats` would help.
* `DNS VERIFICATION STATUS` shows labels without numbers — either the
  numbers are zero-rendered (rendering `0` was suppressed) or the
  section truly has no data and the headers should be hidden when empty.
* `MALWARE FAMILY` showing `unknown / no deterministic or LLM signal
  matched` is internally consistent with the Phase 1 verdict
  (`UNKNOWN LOW`, no obfuscation) — the sample genuinely doesn't match
  known families, but the phrasing reads as defensive.
* `C2 CLASSIFICATION` only shows a non-zero count for `Benign (SDK)`
  (1), which matches the cnzz.com analytics SDK endpoint from screen 3.
  Good signal-to-noise: the dashboard correctly classifies the one real
  indicator as benign.
* The `THREAT INTELLIGENCE EXPORTS` buttons don't show whether the
  generated files will be empty (e.g. the CSV blocklist with only 2
  indicators), or any indication that the export includes a "no matches"
  prefix. Worth a preview/total-count chip on each button.

---

## Cross-screen summary

### Flow
1. **17:30:56** — `Overview`: full sample summary, broken LLM verdict
2. **17:31:22** — `Code Dissection`: class browser, empty Suspicious filter
3. **17:31:30** — `C2 Infrastructure`: one HTTPS endpoint to `cnzz.com`
4. **17:31:38** — `Threat Chains`: one base64-decode chain, MEDIUM / 82%
5. **17:31:46** — `Manifest`: every version field `Unknown`, no perms
6. **17:32:08** — `Threat Intelligence`: loading state
7. **17:32:16** — `Threat Intelligence`: dashboard with Phase 2 enrichment

### What the app does well
* Consistent shell — header, left rail, footer are stable; tab
  navigation is local to the result page.
* Internal consistency across tabs: `1 C2 endpoint` on Overview →
  1 card on C2 Infrastructure → 2 indicators after Phase 2 (host + URL);
  `0 permissions` KPI matches `REQUESTED PERMISSIONS (0)` empty state.
* Risk gauge + classification panel give a defensible bottom-line read.
* Phase 2 enrichment turns the single Phase 1 endpoint into actionable
  intel (DNS verification, classification, malware-family matching, geo).
* Export buttons cover the standard formats (CSV / STIX / YARA).

### Bugs and UX issues to fix
1. **`LLM assessment failed: [Errno 22] Invalid argument`** on screen 1.
   Real bug; OS-level invalid argument. Trace into
   `analysis/step7_llm_assessment.py` — likely an empty/None input being
   passed to a Windows API that rejects empty paths or arg lists.
2. **All identity fields `Unknown`** (Package Name, Version Name/Code,
   Target/Min SDK). Either the manifest is missing from this sample or
   `aapt dump badging` is not being run.
3. **Class-count mismatch:** `179` (Overview) vs `470` (Code Dissection
   `All Classes`). Decide what each number represents and label them.
4. **`… result(s)` placeholder** on Code Dissection Suspicious tab — the
  count is missing.
5. **`Threat Chains` tab shows only 1 of 88 chains** with no visible
   pagination control.
6. **Empty Encodings / Payloads rows** on Overview render with no
   fallback character — needs a `—` or `0`.
7. **KPI cards on Threat Intelligence dashboard are too tightly spaced**
   (`0` and `2` visually merge). Add gutters or borders.
8. **`DNS VERIFICATION STATUS` bucket counts** are blank/zero — render
   `0` explicitly or hide the section when empty.
9. **Threat Intelligence loading state** has no progress indication or
   skeleton.
10. **Threat Intel export buttons** don't preview what's inside (would
    a CSV with 2 rows really be useful?) — consider a count chip or a
    confirmation dialog.

### Data observations on this sample
* APK ~1 MB, 179 classes, 916 strings — small to mid-size Android app.
* One external HTTPS endpoint to `collector.mobile.cnzz.com` (Umeng/Alibaba
  mobile analytics SDK).
* One base64-decoded chain in the same `cnzz.mobile.android.sdk` package,
  82% confidence, medium severity — almost certainly the Umeng SDK's
  bundled public key, not malware.
* No permissions, no obfuscation, no malware-family match, no
  geo-located IPs. **This is almost certainly a benign analytics-SDK
  sample, not malware.** The pipeline correctly labels it `UNKNOWN LOW`,
  which is the right call given the absence of malicious indicators.

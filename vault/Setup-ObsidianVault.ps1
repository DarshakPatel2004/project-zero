# DroidForensix Obsidian Vault Setup for Windows
# PowerShell Script (Windows 7+)
# Usage: powershell -ExecutionPolicy Bypass -File Setup-ObsidianVault.ps1

param(
    [string]$VaultPath = "$env:USERPROFILE\Documents\my-forensics-vault"
)

# Color helpers
function Write-Header {
    param([string]$Text)
    Write-Host "=============================================" -ForegroundColor Blue
    Write-Host "  $Text" -ForegroundColor Blue
    Write-Host "=============================================" -ForegroundColor Blue
}

function Write-Step {
    param([string]$Text)
    Write-Host "`nStep: $Text" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Text)
    Write-Host "[OK] $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "[INFO] $Text" -ForegroundColor Cyan
}

# Main setup
Write-Header "DroidForensix Obsidian Vault Setup"

# Step 1: Clone obsidian-mind
Write-Step "Clone obsidian-mind template"

if (Test-Path $VaultPath) {
    Write-Info "Vault already exists at $VaultPath"
    $response = Read-Host "Continue anyway? (y/n)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        exit 1
    }
} else {
    New-Item -ItemType Directory -Path $VaultPath -Force | Out-Null
}

if (-not (Test-Path "$VaultPath\.git")) {
    try {
        git clone https://github.com/breferrari/obsidian-mind.git $VaultPath
        Write-Success "Cloned obsidian-mind"
    } catch {
        Write-Host "[ERROR] Failed to clone. Do you have Git installed?" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Success "Vault already cloned"
}

Set-Location $VaultPath

# Step 2: Create North Star
Write-Step "Create North Star (brain/North Star.md)"

$northStar = @"
# North Star

## Current Focus (Thesis Timeline)
- Complete DroidForensix research and validation (deadline: May 2027)
- Publish findings on Android malware C2 infrastructure
- Target venues: Virus Bulletin, DFRWS, ACSAC

## Active Projects

### DroidForensix (Primary)
- **Status:** 9-step pipeline validated, 277 samples analyzed
- **Metrics:** 1,711 C2 indicators, 63x speedup vs manual
- **Current Blocker:** Confirm "100% missed by all aggregators" claim
- **Next Steps:** Finalize LinkedIn article, then paper draft
- **Architecture:** AndroGuard, threat intel, geospatial, synthesis

### PhishScope (Secondary)
- **Status:** URL phishing detection system complete
- **Current:** Project report in progress
- **Models:** Logistic Regression, Random Forest, XGBoost ensemble
- **Dataset:** 186,230 URLs

### VulnForge (Maintenance)
- CVE aggregation from NVD, CISA KEV, AlienVault OTX
- Auto-generated Snort/Suricata/Sigma rules

## Technical Environment
- **Machine:** Lenovo LOQ 15 (Ryzen 7435HS, RTX 4050 6GB, 24GB RAM)
- **OS:** Windows
- **Local LLM:** Mistral 7B via Ollama (method annotation)
- **Dev:** OpenCode (primary coding environment), Claude Code (architecture/audit)
- **GitHub:** DarshakPatel2004

## Research Principles
- Reproducibility > novelty
- Ablation studies on each pipeline step
- All claims validated against final_summary.json
- Documentation for open-source release
- Know your threat model explicitly

## Key Metrics to Track
- Samples processed: 277
- C2 indicators extracted: 1,711
- Unique IPs geolocated: 203 (75% Chinese cloud providers)
- Location clusters: 26 (2D Leaflet map)
- Performance improvement: 63x over manual analysis
- Pipeline steps: 9 validated
- Method similarity: SHA-256 fingerprinting

## Constraints
- Thesis deadline: May 2027
- Windows-native development
- Local inference preferred (privacy-sensitive)
- No cloud storage of code/samples

## Recent Wins
- 9-step pipeline fully validated
- Frontend: useReducer + WebSocket architecture
- PDF export with Quick/Full modes and per-phase timing
- Geospatial layer with 26 location clusters
- Threat Synthesis Engine designed (steps 10-18)
"@

$northStar | Out-File "$VaultPath\brain\North Star.md" -Encoding UTF8 -Force
Write-Success "Created North Star"

# Step 3: Create DroidForensix project
Write-Step "Create DroidForensix active project"

$droidForensix = @"
---
title: DroidForensix
status: In Progress
quarter: Q3 2026
owner: Darshak Patel
project_type: Research
date: 2026-07-21
---

# DroidForensix

## Goal
Validate automated Android malware static analysis pipeline for publication at top-tier venues.

## Current Status
- **Pipeline:** 9 validated steps (AndroGuard, threat intel, geospatial, synthesis)
- **Samples:** 277 analyzed, 1,711 C2 indicators extracted
- **Performance:** 63x speedup vs manual analysis
- **Blockers:** Final claim validation (100% missed by all aggregators)
- **Architecture:** Fully modular, each step can be ablated

## Recent Progress
- Frontend rebuilt with useReducer + WebSocket architecture
- Leaflet geospatial layer with 26 location clusters (color-coded by infrastructure type)
- LLM method annotation via Mistral 7B (Ollama) - sequential bottleneck documented as tech debt
- PDF export (Quick + Full modes with per-phase timing)
- Threat intel: 4 parallel sources (VirusTotal, AlienVault OTX, Shodan, Censys)
- 75% C2 concentration in Chinese cloud providers

## Next Steps
- [ ] Validate "100% aggregator miss" claim against VirusTotal, OTX, Shodan, Censys
- [ ] Complete LinkedIn article draft
- [ ] Draft paper for Virus Bulletin (include ablation studies)
- [ ] Document threat model and assumptions
- [ ] Prepare open-source release (GitHub)

## Related
[[PhishScope]] [[VulnForge]]
"@

$droidForensix | Out-File "$VaultPath\work\active\DroidForensix.md" -Encoding UTF8 -Force
Write-Success "Created DroidForensix project"

# Step 4: Create C2 Validation Study
Write-Step "Create C2 Validation Study work note"

$c2Study = @"
---
title: C2 Indicator Validation
status: In Progress
date: 2026-07-21
project: DroidForensix
quarter: Q3 2026
tags: [validation, c2, threat-intel]
---

# C2 Indicator Validation Study

## Goal
Confirm that all 1,711 extracted C2 indicators are missed by major aggregators (VirusTotal, AlienVault OTX, Shodan, Censys).

## Method
1. Extract stratified sample of 200 random indicators (20% of total)
2. Query each aggregator via API
3. Log hit/miss per aggregator
4. Calculate coverage percentage
5. Analyze false positives vs true negatives

## Status
- [x] Sample selection (200 random C2 IPs)
- [ ] VirusTotal queries (in progress)
- [ ] AlienVault OTX queries
- [ ] Shodan queries
- [ ] Censys queries
- [ ] Cross-aggregator analysis
- [ ] Writeup and statistics

## Key Claim to Validate
**"100% of indicators missed by all aggregators"** - Need to verify this is accurate or refine to "X% missed by Y aggregator"

## Related
[[DroidForensix]]
"@

$c2Study | Out-File "$VaultPath\work\active\C2 Validation Study.md" -Encoding UTF8 -Force
Write-Success "Created C2 Validation Study"

# Step 5: Create secondary projects
Write-Step "Create secondary projects"

$phishScope = @"
---
title: PhishScope Project Report
status: In Progress
date: 2026-07-21
project: PhishScope
quarter: Q3 2026
---

# PhishScope Project Report

## Overview
URL phishing detection system using TF-IDF character n-grams + lexical features with ensemble models.

## System Specs
- **Dataset:** 186,230 URLs
- **Features:** TF-IDF (char n-grams) + Brand Similarity + Risky TLD + URL Length + Digit Ratio
- **Models:** Logistic Regression, Random Forest, XGBoost (ensemble)
- **Frontend:** Streamlit dashboard with SOC Control Sidebar
- **Export:** CSV batch processing, JSON export

## Status
- [x] Model training and validation
- [x] Dashboard implementation
- [ ] Project report (in progress)
- [ ] Publication considerations

## Related
[[DroidForensix]]
"@

$phishScope | Out-File "$VaultPath\work\active\PhishScope Report.md" -Encoding UTF8 -Force

$vulnForge = @"
---
title: VulnForge Maintenance
status: Maintenance
date: 2026-07-21
project: VulnForge
quarter: Q3 2026
---

# VulnForge

## Overview
CVE aggregation from NVD, CISA KEV, AlienVault OTX with auto-generated Snort/Suricata/Sigma rules.

## Status
- Maintenance-only
- Open-sourced
- Lower priority than DroidForensix

## Related
[[DroidForensix]]
"@

$vulnForge | Out-File "$VaultPath\work\active\VulnForge Maintenance.md" -Encoding UTF8 -Force
Write-Success "Created secondary projects"

# Step 6: Create competencies
Write-Step "Create competency framework"

$compDir = "$VaultPath\perf\competencies"
if (-not (Test-Path $compDir)) {
    New-Item -ItemType Directory -Path $compDir -Force | Out-Null
}

$staticAnalysis = @"
---
name: Static Analysis
level: Expert
target_level: Expert
date: 2026-07-21
---

# Static Analysis

## Definition
Ability to extract actionable threat intelligence from binary artifacts without execution, at scale and with reproducibility.

## Proficiency Table
| Level | Criteria |
|-------|----------|
| Beginner | Can parse APK structure, identify obvious malicious calls |
| Intermediate | Can write YARA rules, correlate across samples, use VirusTotal API |
| Expert | Can design pipelines (9+ steps), validate at scale, publish findings |

## Evidence
- [[DroidForensix]] - 9-step validated pipeline, 277 samples, 1,711 C2 indicators
- [[MAFIA]] - 95.1% accuracy on EMBER samples, 7-phase pipeline
- Threat intelligence integration (VirusTotal, OTX, Shodan, Censys)

## Related Work
- AndroGuard integration
- YARA rule authoring
- Threat intelligence correlation
"@

$staticAnalysis | Out-File "$compDir\Static Analysis.md" -Encoding UTF8 -Force

$researchComm = @"
---
name: Research Communication
level: Intermediate
target_level: Expert
date: 2026-07-21
---

# Research Communication

## Definition
Ability to articulate research findings clearly: writing papers, crafting ablation studies, validating claims.

## Proficiency Table
| Level | Criteria |
|-------|----------|
| Beginner | Can write clear technical summaries |
| Intermediate | Can draft papers, validate claims, prepare for publication |
| Expert | Published papers at top venues (Virus Bulletin, DFRWS, ACSAC) |

## Current Work
- DroidForensix paper draft (Virus Bulletin target)
- LinkedIn article on C2 infrastructure findings
- Reproducibility documentation

## Related
[[DroidForensix]]
"@

$researchComm | Out-File "$compDir\Research Communication.md" -Encoding UTF8 -Force
Write-Success "Created competency framework"

# Step 7: Create Brag Doc
Write-Step "Create Brag Doc (for review season)"

$bragDoc = @"
---
date: 2026-07-21
type: brag-doc
---

# Brag Doc

## Q3 2026

### DroidForensix Pipeline
- Designed and validated 9-step Android malware static analysis pipeline
- Processed 277 samples, extracted 1,711 C2 indicators
- Achieved 63x speedup vs manual analysis
- Built geospatial layer with 26 location clusters
- Integrated 4 parallel threat intelligence sources
- **Evidence:** [[DroidForensix]]

### Technical Architecture
- Frontend rebuild: useReducer + WebSocket for real-time updates
- PDF export with Quick/Full modes and per-phase timing
- Local LLM inference (Mistral 7B via Ollama) for method annotation
- **Related:** [[Static Analysis]]

### Research Validation
- Comprehensive C2 indicator validation study in progress
- Ablation study design (measure impact of each pipeline step)
- Ground truth comparison against VirusTotal, OTX, Shodan, Censys
- **Related:** [[C2 Validation Study]]
"@

$bragDoc | Out-File "$VaultPath\perf\Brag Doc.md" -Encoding UTF8 -Force
Write-Success "Created Brag Doc"

# Step 8: Git commit
Write-Step "Initialize git and commit"
try {
    git add .
    git commit -m "Initial vault setup for DroidForensix thesis research"
    Write-Success "Git initialized"
} catch {
    Write-Info "Git commit skipped (already committed or not a git repo)"
}

# Step 9: QMD Optional Setup
Write-Step "Check for QMD installation"
$qmdExists = & where.exe qmd 2>$null
if ($qmdExists) {
    Write-Success "QMD found"
    $qmdResponse = Read-Host "Run QMD bootstrap? (y/n)"
    if ($qmdResponse -eq 'y' -or $qmdResponse -eq 'Y') {
        try {
            node --experimental-strip-types scripts/qmd-bootstrap.ts
            Write-Success "QMD indexed"
        } catch {
            Write-Host "[ERROR] QMD bootstrap failed: $_" -ForegroundColor Red
        }
    }
} else {
    Write-Info "QMD not installed. Optional but recommended:"
    Write-Info "  npm install -g @tobilu/qmd"
    Write-Info "  cd $VaultPath"
    Write-Info "  node --experimental-strip-types scripts/qmd-bootstrap.ts"
}

# Summary
Write-Host "`n"
Write-Header "Setup Complete!"

Write-Info "Next Steps:"
Write-Host "1. Open Obsidian and open vault as folder:" -ForegroundColor White
Write-Host "   File > Open folder as vault > $VaultPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. Enable Obsidian CLI in Settings:" -ForegroundColor White
Write-Host "   Settings > General > Obsidian URI > Allow command line interface" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Set up OpenCode integration:" -ForegroundColor White
Write-Host "   Run: Setup-OpenCodeAlias.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Test with Claude Code:" -ForegroundColor White
Write-Host "   cd $VaultPath" -ForegroundColor Cyan
Write-Host "   claude" -ForegroundColor Cyan
Write-Host ""
Write-Host "5. In Claude, run: /om-standup" -ForegroundColor White
Write-Host ""
Write-Success "Your vault is ready at: $VaultPath"
Write-Success "North Star: $VaultPath\brain\North Star.md"
Write-Success "Active Projects: $VaultPath\work\active\"

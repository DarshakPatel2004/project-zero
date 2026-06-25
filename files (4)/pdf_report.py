"""
DroidForensix PDF Report Generator

Produces a forensic analysis report covering:
- Sample metadata
- LLM severity assessment (Step 7)
- Obfuscation indicators
- C2 infrastructure
- Suspicious class/method analysis with LLM summaries
"""

import io
from datetime import datetime, timezone
from typing import Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.platypus.flowables import HRFlowable


# ── Colour palette (dark-forensics feel on white paper) ──────────────────────
C_DARK       = colors.HexColor('#0f172a')
C_MID        = colors.HexColor('#1e293b')
C_ACCENT     = colors.HexColor('#6366f1')   # indigo
C_ROSE       = colors.HexColor('#f43f5e')
C_AMBER      = colors.HexColor('#f59e0b')
C_EMERALD    = colors.HexColor('#10b981')
C_CYAN       = colors.HexColor('#06b6d4')
C_MUTED      = colors.HexColor('#64748b')
C_LIGHT_BG   = colors.HexColor('#f8fafc')
C_BORDER     = colors.HexColor('#e2e8f0')
C_WHITE      = colors.white

SEVERITY_COLORS = {
    'critical': colors.HexColor('#ef4444'),
    'high':     colors.HexColor('#f97316'),
    'medium':   colors.HexColor('#eab308'),
    'low':      colors.HexColor('#22c55e'),
}

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


def _styles():
    base = getSampleStyleSheet()

    def s(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        'title': s('DFTitle',
            fontName='Helvetica-Bold', fontSize=22,
            textColor=C_DARK, spaceAfter=4, leading=28),
        'subtitle': s('DFSubtitle',
            fontName='Helvetica', fontSize=11,
            textColor=C_MUTED, spaceAfter=2),
        'h1': s('DFH1',
            fontName='Helvetica-Bold', fontSize=14,
            textColor=C_DARK, spaceBefore=14, spaceAfter=6,
            borderPad=0),
        'h2': s('DFH2',
            fontName='Helvetica-Bold', fontSize=11,
            textColor=C_ACCENT, spaceBefore=10, spaceAfter=4),
        'h3': s('DFH3',
            fontName='Helvetica-Bold', fontSize=9,
            textColor=C_MID, spaceBefore=6, spaceAfter=3),
        'body': s('DFBody',
            fontName='Helvetica', fontSize=9,
            textColor=C_DARK, leading=14, spaceAfter=4),
        'mono': s('DFMono',
            fontName='Courier', fontSize=8,
            textColor=C_DARK, leading=12, spaceAfter=2),
        'mono_small': s('DFMonoSmall',
            fontName='Courier', fontSize=7,
            textColor=C_MUTED, leading=11),
        'muted': s('DFMuted',
            fontName='Helvetica', fontSize=8,
            textColor=C_MUTED, leading=12),
        'label': s('DFLabel',
            fontName='Helvetica-Bold', fontSize=8,
            textColor=C_MUTED, spaceAfter=2),
        'llm_summary': s('DFLLMSummary',
            fontName='Helvetica-Oblique', fontSize=9,
            textColor=colors.HexColor('#334155'),
            leading=14, spaceAfter=3,
            leftIndent=8, borderPad=4),
        'finding': s('DFFinding',
            fontName='Helvetica', fontSize=9,
            textColor=C_DARK, leading=13, spaceAfter=2,
            leftIndent=12),
    }


def _hr(story, color=C_BORDER, thickness=0.5, space_before=4, space_after=8):
    story.append(Spacer(1, space_before))
    story.append(HRFlowable(width='100%', thickness=thickness, color=color))
    story.append(Spacer(1, space_after))


def _severity_pill(severity: str) -> str:
    """Return coloured inline text for severity."""
    col = SEVERITY_COLORS.get(severity.lower(), C_MUTED)
    hex_col = col.hexval() if hasattr(col, 'hexval') else '#64748b'
    return f'<font color="{hex_col}"><b>{severity.upper()}</b></font>'


def _safe(text: Any, max_len: int = 800) -> str:
    """Escape XML special chars and truncate for Paragraph safety."""
    s = str(text or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return s[:max_len] + ('…' if len(s) > max_len else '')


def _kv_table(data: list[tuple], col_widths=None) -> Table:
    """Two-column key-value table."""
    usable = PAGE_W - 2 * MARGIN
    col_widths = col_widths or [usable * 0.32, usable * 0.68]
    table_data = [[Paragraph(f'<b>{k}</b>', ParagraphStyle('kv_key',
                    fontName='Helvetica-Bold', fontSize=8, textColor=C_MUTED)),
                   Paragraph(_safe(v), ParagraphStyle('kv_val',
                    fontName='Helvetica', fontSize=9, textColor=C_DARK))]
                  for k, v in data]
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), C_LIGHT_BG),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [C_LIGHT_BG, C_WHITE]),
        ('GRID', (0, 0), (-1, -1), 0.3, C_BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    return t


# ── Section builders ─────────────────────────────────────────────────────────

def _section_cover(story, st, sample_result: dict, threat_data: dict, sample_id: str):
    """Cover / title block."""
    meta = sample_result.get('extraction', {})
    pkg = meta.get('package_name') or meta.get('apk_info', {}).get('package_name') or 'Unknown Package'
    severity = sample_result.get('llm_assessment', {}).get('severity', 'unknown')
    sev_col = SEVERITY_COLORS.get(severity, C_MUTED)

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph('DroidForensix', ParagraphStyle('brand',
        fontName='Helvetica-Bold', fontSize=10, textColor=C_ACCENT)))
    story.append(Paragraph('Android Malware Analysis Report', st['title']))
    story.append(Paragraph(f'Package: {pkg}', st['subtitle']))
    story.append(Spacer(1, 4))

    # Severity banner
    sev_table = Table(
        [[Paragraph(f'<b>Severity: {severity.upper()}</b>',
            ParagraphStyle('sev', fontName='Helvetica-Bold', fontSize=13,
                           textColor=C_WHITE, alignment=TA_CENTER))]],
        colWidths=[PAGE_W - 2 * MARGIN]
    )
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), sev_col),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('ROUNDEDCORNERS', [4]),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 6))

    # Meta row
    risk = sample_result.get('llm_assessment', {}).get('risk_score', 'N/A')
    generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    story.append(_kv_table([
        ('Sample ID', sample_id),
        ('Risk Score', f'{risk} / 100'),
        ('Report Generated', generated),
    ]))
    _hr(story, space_before=8)


def _section_metadata(story, st, sample_result: dict):
    story.append(Paragraph('1. Sample Metadata', st['h1']))
    extraction = sample_result.get('extraction', {})
    apk_info = extraction.get('apk_info', {})

    rows = [
        ('Package Name',    apk_info.get('package_name', 'N/A')),
        ('Version',         f"{apk_info.get('version_name', 'N/A')} (code {apk_info.get('version_code', 'N/A')})"),
        ('Min SDK',         apk_info.get('min_sdk_version', 'N/A')),
        ('Target SDK',      apk_info.get('target_sdk_version', 'N/A')),
        ('File Size',       f"{apk_info.get('file_size_bytes', 0):,} bytes" if apk_info.get('file_size_bytes') else 'N/A'),
        ('SHA-256',         sample_result.get('sample_id', 'N/A')),
        ('Multi-DEX',       str(apk_info.get('is_multidex', False))),
    ]
    story.append(_kv_table(rows))
    _hr(story)


def _section_llm_assessment(story, st, sample_result: dict):
    story.append(Paragraph('2. LLM Threat Assessment', st['h1']))
    llm = sample_result.get('llm_assessment', {})
    if not llm:
        story.append(Paragraph('LLM assessment not available for this sample.', st['muted']))
        _hr(story)
        return

    severity  = llm.get('severity', 'unknown')
    risk      = llm.get('risk_score', 'N/A')
    narrative = llm.get('narrative', '')
    threat    = llm.get('primary_threat', 'N/A')
    conf      = llm.get('confidence', None)
    actions   = llm.get('recommended_actions', [])

    story.append(_kv_table([
        ('Severity',        severity.upper()),
        ('Risk Score',      f'{risk} / 100'),
        ('Primary Threat',  threat.replace('_', ' ').title()),
        ('Confidence',      f'{int(conf * 100)}%' if conf is not None else 'N/A'),
    ]))
    story.append(Spacer(1, 6))

    if narrative:
        story.append(Paragraph('<b>Analyst Narrative</b>', st['label']))
        story.append(Paragraph(_safe(narrative), st['body']))

    if actions:
        story.append(Spacer(1, 4))
        story.append(Paragraph('<b>Recommended Actions</b>', st['label']))
        for action in actions:
            story.append(Paragraph(f'• {_safe(action)}', st['finding']))

    _hr(story)


def _section_obfuscation(story, st, obfuscation: dict):
    story.append(Paragraph('3. Obfuscation Analysis', st['h1']))
    if not obfuscation:
        story.append(Paragraph('Obfuscation data not available.', st['muted']))
        _hr(story)
        return

    score = obfuscation.get('obfuscation_score', 0)
    level = obfuscation.get('obfuscation_level', 'unknown')
    indicators = obfuscation.get('indicators', {})

    story.append(_kv_table([
        ('Obfuscation Score', f'{score} ({level.upper()})'),
        ('Total Classes',     str(indicators.get('total_classes', 'N/A'))),
        ('Total Methods',     str(indicators.get('total_methods', 'N/A'))),
        ('Reflection Usages', str(len(indicators.get('reflection', [])))),
        ('Dynamic Loading',   str(len(indicators.get('dynamic_loading', [])))),
        ('Crypto API Usages', str(len(indicators.get('crypto_apis', [])))),
        ('Suspicious APIs',   str(len(indicators.get('suspicious_apis', [])))),
        ('Dangerous Perms',   str(len(indicators.get('dangerous_permissions', [])))),
    ]))

    perms = indicators.get('dangerous_permissions', [])
    if perms:
        story.append(Spacer(1, 6))
        story.append(Paragraph('<b>Dangerous Permissions</b>', st['label']))
        for p in perms[:20]:
            story.append(Paragraph(f'• {_safe(p)}', st['mono_small']))

    _hr(story)


def _section_c2(story, st, threat_data: dict):
    story.append(Paragraph('4. C2 Infrastructure', st['h1']))
    c2s = threat_data.get('c2_infrastructure', [])
    if not c2s:
        story.append(Paragraph('No C2 indicators detected.', st['muted']))
        _hr(story)
        return

    story.append(Paragraph(f'{len(c2s)} indicator(s) identified.', st['body']))
    story.append(Spacer(1, 4))

    usable = PAGE_W - 2 * MARGIN
    headers = [
        Paragraph('<b>Indicator</b>', ParagraphStyle('th', fontName='Helvetica-Bold', fontSize=8, textColor=C_WHITE)),
        Paragraph('<b>Protocol</b>', ParagraphStyle('th', fontName='Helvetica-Bold', fontSize=8, textColor=C_WHITE)),
        Paragraph('<b>Status</b>', ParagraphStyle('th', fontName='Helvetica-Bold', fontSize=8, textColor=C_WHITE)),
        Paragraph('<b>Classification</b>', ParagraphStyle('th', fontName='Helvetica-Bold', fontSize=8, textColor=C_WHITE)),
    ]
    rows = [headers]
    for c2 in c2s[:50]:
        indicator = c2.get('domain') or c2.get('ip') or 'unknown'
        port = c2.get('port', '')
        path = c2.get('path', '/')
        detail = f'{indicator}:{port}{path}' if port else f'{indicator}{path}'
        rows.append([
            Paragraph(_safe(detail, 60), st['mono_small']),
            Paragraph(_safe(c2.get('protocol', 'N/A')), st['muted']),
            Paragraph(_safe(c2.get('status', 'N/A')), st['muted']),
            Paragraph(_safe(c2.get('ip_classification', 'N/A')), st['muted']),
        ])

    t = Table(rows, colWidths=[usable * 0.45, usable * 0.15, usable * 0.18, usable * 0.22])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_DARK),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [C_LIGHT_BG, C_WHITE]),
        ('GRID', (0, 0), (-1, -1), 0.3, C_BORDER),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    _hr(story)


def _section_methods(story, st, annotated_methods: list[dict]):
    story.append(Paragraph('5. Suspicious Method Analysis', st['h1']))

    if not annotated_methods:
        story.append(Paragraph('No suspicious methods analysed.', st['muted']))
        _hr(story)
        return

    story.append(Paragraph(
        f'{len(annotated_methods)} method(s) analysed with LLM annotation.',
        st['body']
    ))

    for i, entry in enumerate(annotated_methods):
        class_name  = entry.get('class_name', 'Unknown')
        method_name = entry.get('method_name', 'Unknown')
        llm         = entry.get('llm', {})
        line_anns   = entry.get('line_annotations', {})
        flags       = entry.get('flags', [])

        summary     = llm.get('summary', '')
        threat_type = llm.get('threat_type', 'unknown')
        confidence  = llm.get('confidence', None)

        block = []
        # Method header
        block.append(Paragraph(
            f'<b>{_safe(class_name)}</b> → <font face="Courier">{_safe(method_name)}</font>',
            st['h3']
        ))

        # Flags + threat type row
        meta_parts = []
        if flags:
            meta_parts.append(f'Flags: {", ".join(flags[:5])}')
        if threat_type and threat_type != 'unknown':
            meta_parts.append(f'Type: {threat_type.replace("_", " ").title()}')
        if confidence is not None:
            meta_parts.append(f'Confidence: {int(confidence * 100)}%')
        if meta_parts:
            block.append(Paragraph(' | '.join(meta_parts), st['muted']))

        # LLM summary
        if summary:
            block.append(Paragraph(f'<i>{_safe(summary)}</i>', st['llm_summary']))

        # Static line annotations
        if line_anns:
            block.append(Paragraph('<b>Pattern Annotations</b>', st['label']))
            for line_idx, ann in sorted(line_anns.items(), key=lambda x: int(x[0]))[:10]:
                block.append(Paragraph(
                    f'Line {int(line_idx) + 1}: {_safe(ann.get("label", ""))}',
                    st['finding']
                ))

        block.append(Spacer(1, 4))
        story.append(KeepTogether(block))

    _hr(story)


def _section_footer_note(story, st, mode: str):
    story.append(Paragraph(
        f'Report generated by DroidForensix · '
        f'{"Quick export (top 30 methods)" if mode == "quick" else "Full export (all suspicious methods)"} · '
        f'{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}',
        ParagraphStyle('footer', fontName='Helvetica', fontSize=7,
                       textColor=C_MUTED, alignment=TA_CENTER)
    ))


# ── Public entry point ────────────────────────────────────────────────────────

def generate_report(
    sample_id: str,
    sample_result: dict,
    threat_data: dict,
    obfuscation: dict,
    annotated_methods: list[dict],
    mode: str = 'quick',
) -> bytes:
    """
    Build the PDF report and return raw bytes.

    Parameters
    ----------
    sample_id          SHA-256 of the APK (used as identifier)
    sample_result      Full pipeline result dict from load_result()
    threat_data        Output of ti.build_threat_intel()
    obfuscation        Output of build_obfuscation_view()
    annotated_methods  List of {class_name, method_name, llm, line_annotations, flags}
    mode               'quick' | 'full'
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title=f'DroidForensix Report — {sample_id[:16]}',
        author='DroidForensix',
        subject='Android Malware Analysis Report',
    )

    st = _styles()
    story = []

    _section_cover(story, st, sample_result, threat_data, sample_id)
    _section_metadata(story, st, sample_result)
    _section_llm_assessment(story, st, sample_result)
    _section_obfuscation(story, st, obfuscation)
    _section_c2(story, st, threat_data)
    story.append(PageBreak())
    _section_methods(story, st, annotated_methods)
    _section_footer_note(story, st, mode)

    doc.build(story)
    return buf.getvalue()

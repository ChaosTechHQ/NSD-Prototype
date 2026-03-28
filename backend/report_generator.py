"""
report_generator.py — NSD v19 Session PDF Report
ChaosTech Defense LLC

Generates a professional tactical PDF report from the SignalDB.
Uses ReportLab (pre-installed on Pi via pip).

Report sections:
  1. Header — ChaosTech Defense branding, report metadata
  2. Session Summary — uptime, total detections, real vs simulated, scan rate
  3. RF Band Coverage Table — per-band detection count, top protocol, avg SNR
  4. Top Threats — highest-scoring real detections this session
  5. Detection Timeline — bar chart of detections per 5-minute interval
  6. Footer — classification marking, generation timestamp

Output: bytes (PDF) — caller writes to file or streams via HTTP response.
"""

import io
import time
import datetime
import logging
from typing import List, Optional

logger = logging.getLogger("nsd.report")

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.graphics.shapes import Drawing, Rect, String, Line
    from reportlab.graphics import renderPDF
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False
    logger.error("ReportLab not installed. Run: pip install reportlab")


C_BLACK      = colors.HexColor("#0a0a0a")
C_DARK_GREEN = colors.HexColor("#003300")
C_GREEN      = colors.HexColor("#00cc44")
C_RED        = colors.HexColor("#cc2200")
C_AMBER      = colors.HexColor("#cc8800")
C_YELLOW     = colors.HexColor("#ccaa00")
C_WHITE      = colors.white
C_LIGHT_GREY = colors.HexColor("#e8e8e8")
C_MID_GREY   = colors.HexColor("#cccccc")
C_DARK_GREY  = colors.HexColor("#444444")

LEVEL_COLORS = {
    "CRITICAL": C_RED,
    "HIGH":     C_AMBER,
    "MEDIUM":   C_YELLOW,
    "LOW":      C_GREEN,
}


def generate_report(db,
                    uptime_s: float,
                    scan_cycle_s: float,
                    hardware_ok: bool,
                    real_only: bool = True) -> bytes:
    if not REPORTLAB_OK:
        raise RuntimeError("ReportLab is not installed.")

    stats   = db.get_stats()
    records = db.get_recent(limit=500, real_only=real_only)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.6*inch, rightMargin=0.6*inch,
        topMargin=0.5*inch,  bottomMargin=0.5*inch,
    )

    story  = []
    styles = _build_styles()

    story += _build_header(styles, uptime_s, hardware_ok)
    story.append(Spacer(1, 0.15*inch))
    story += _build_summary(styles, stats, uptime_s, scan_cycle_s, hardware_ok)
    story.append(Spacer(1, 0.15*inch))
    story += _build_band_table(styles, records)
    story.append(Spacer(1, 0.15*inch))
    story += _build_top_threats(styles, records)
    story.append(Spacer(1, 0.15*inch))
    story += _build_timeline(styles, records)
    story.append(Spacer(1, 0.15*inch))
    story += _build_footer(styles)

    doc.build(story)
    return buf.getvalue()


def _build_header(styles, uptime_s: float, hardware_ok: bool) -> list:
    now_et   = _now_et()
    hw_str   = "HARDWARE ACTIVE — LIVE RF" if hardware_ok else "SIMULATION MODE"
    hw_color = "#006600" if hardware_ok else "#884400"

    header_data = [
        [
            Paragraph("<b>CHAOSTECH DEFENSE LLC</b>", styles["co_name"]),
            Paragraph(f'<font color="{hw_color}"><b>{hw_str}</b></font>', styles["hw_status"]),
        ],
        [
            Paragraph("NSD v19 — NEURO SWARM DISRUPTOR", styles["product"]),
            Paragraph(f"Report Generated: {now_et}", styles["meta_right"]),
        ],
        [
            Paragraph("RF SENSING SESSION REPORT", styles["report_title"]),
            Paragraph(f"Uptime: {_fmt_uptime(uptime_s)}", styles["meta_right"]),
        ],
    ]

    t = Table(header_data, colWidths=[4.5*inch, 2.9*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_BLACK),
        ("TEXTCOLOR",     (0, 0), (-1, -1), C_WHITE),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (0, -1),  8),
        ("RIGHTPADDING",  (1, 0), (1, -1),  8),
        ("LINEBELOW",     (0, -1), (-1, -1), 2, C_GREEN),
    ]))
    return [t]


def _build_summary(styles, stats: dict, uptime_s: float,
                   scan_cycle_s: float, hardware_ok: bool) -> list:
    total      = stats.get("total_all_time", 0)
    session    = stats.get("total_this_session", 0)
    real       = stats.get("total_real", 0)
    sim        = total - real
    oldest_ts  = stats.get("oldest_timestamp")
    session_id = stats.get("session_id", "N/A")

    start_str = "N/A"
    if oldest_ts:
        start_dt  = datetime.datetime.utcfromtimestamp(oldest_ts)
        start_str = _utc_to_et(start_dt).strftime("%m/%d/%Y %H:%M:%S ET")

    items = [
        ("Session ID",           session_id),
        ("Session Start",        start_str),
        ("System Uptime",        _fmt_uptime(uptime_s)),
        ("Avg Scan Cycle",       f"{scan_cycle_s:.2f} s"),
        ("Hardware Mode",        "LIVE RF" if hardware_ok else "SIMULATION"),
        ("Total Detections",     str(total)),
        ("This Session",         str(session)),
        ("Real RF Detections",   str(real)),
        ("Simulated Detections", str(sim)),
    ]

    mid   = (len(items) + 1) // 2
    left  = items[:mid]
    right = items[mid:]
    while len(right) < len(left):
        right.append(("", ""))

    rows = []
    for (lk, lv), (rk, rv) in zip(left, right):
        rows.append([
            Paragraph(f"<b>{lk}</b>", styles["sum_key"]),
            Paragraph(lv, styles["sum_val"]),
            Paragraph(""),
            Paragraph(f"<b>{rk}</b>", styles["sum_key"]) if rk else Paragraph(""),
            Paragraph(rv, styles["sum_val"]) if rv else Paragraph(""),
        ])

    title = Paragraph("SESSION SUMMARY", styles["section_title"])
    t = Table(rows, colWidths=[1.6*inch, 1.4*inch, 0.3*inch, 1.6*inch, 1.4*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_LIGHT_GREY),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_LIGHT_GREY, C_WHITE]),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("LINEBELOW",     (0, -1), (-1, -1), 0.5, C_MID_GREY),
    ]))
    return [title, Spacer(1, 0.05*inch), t]


def _build_band_table(styles, records) -> list:
    from collections import defaultdict
    band_data = defaultdict(lambda: {"count": 0, "snr_sum": 0.0, "snr_n": 0,
                                      "protocols": defaultdict(int),
                                      "levels": defaultdict(int)})
    for r in records:
        b = band_data[r.band]
        b["count"] += 1
        if r.snr_db is not None:
            b["snr_sum"] += r.snr_db
            b["snr_n"]   += 1
        if r.protocol:     b["protocols"][r.protocol]     += 1
        if r.threat_level: b["levels"][r.threat_level]    += 1

    if not band_data:
        return [Paragraph("RF BAND COVERAGE", styles["section_title"]),
                Paragraph("No detections recorded.", styles["body"])]

    header_row = [
        Paragraph("<b>BAND</b>",         styles["th"]),
        Paragraph("<b>DETECTIONS</b>",   styles["th"]),
        Paragraph("<b>TOP PROTOCOL</b>", styles["th"]),
        Paragraph("<b>AVG SNR</b>",      styles["th"]),
        Paragraph("<b>TOP LEVEL</b>",    styles["th"]),
    ]
    rows = [header_row]
    for band in sorted(band_data.keys()):
        b         = band_data[band]
        top_proto = max(b["protocols"], key=b["protocols"].get) if b["protocols"] else "—"
        avg_snr   = (b["snr_sum"] / b["snr_n"]) if b["snr_n"] else 0.0
        top_level = max(b["levels"],   key=b["levels"].get)   if b["levels"]   else "—"
        lc        = LEVEL_COLORS.get(top_level, C_DARK_GREY)
        rows.append([
            Paragraph(band.replace("_", " "), styles["td"]),
            Paragraph(str(b["count"]), styles["td_center"]),
            Paragraph(top_proto, styles["td"]),
            Paragraph(f"{avg_snr:.1f} dB", styles["td_center"]),
            Paragraph(f'<font color="#{_color_hex(lc)}"><b>{top_level}</b></font>',
                      styles["td_center"]),
        ])

    t = Table(rows, colWidths=[1.5*inch, 1.0*inch, 2.3*inch, 0.9*inch, 0.9*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BLACK),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_GREEN),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT_GREY, C_WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_MID_GREY),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
    ]))
    return [Paragraph("RF BAND COVERAGE", styles["section_title"]), Spacer(1, 0.05*inch), t]


def _build_top_threats(styles, records, top_n: int = 10) -> list:
    real_records = [r for r in records if not r.simulated and r.threat_score is not None]
    if not real_records:
        return [Paragraph("TOP THREATS", styles["section_title"]),
                Paragraph("No real RF threats detected in this session.", styles["body"])]

    top = sorted(real_records, key=lambda r: r.threat_score or 0, reverse=True)[:top_n]

    header_row = [
        Paragraph("<b>TIMESTAMP (ET)</b>", styles["th"]),
        Paragraph("<b>FREQ (MHz)</b>",     styles["th"]),
        Paragraph("<b>PROTOCOL</b>",       styles["th"]),
        Paragraph("<b>SNR (dB)</b>",       styles["th"]),
        Paragraph("<b>SCORE</b>",          styles["th"]),
        Paragraph("<b>LEVEL</b>",          styles["th"]),
    ]
    rows = [header_row]
    for r in top:
        dt_et  = _utc_to_et(datetime.datetime.utcfromtimestamp(r.timestamp_utc))
        ts_str = dt_et.strftime("%m/%d %H:%M:%S")
        lc     = LEVEL_COLORS.get(r.threat_level or "", C_DARK_GREY)
        rows.append([
            Paragraph(ts_str, styles["td_small"]),
            Paragraph(f"{r.freq_mhz:.3f}", styles["td_center"]),
            Paragraph(r.protocol or "—", styles["td_small"]),
            Paragraph(f"{r.snr_db:.1f}" if r.snr_db else "—", styles["td_center"]),
            Paragraph(str(r.threat_score or 0), styles["td_center"]),
            Paragraph(f'<font color="#{_color_hex(lc)}"><b>{r.threat_level or "—"}</b></font>',
                      styles["td_center"]),
        ])

    t = Table(rows, colWidths=[1.1*inch, 0.85*inch, 2.1*inch, 0.75*inch, 0.65*inch, 0.85*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BLACK),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_GREEN),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT_GREY, C_WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_MID_GREY),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]))
    return [Paragraph(f"TOP {min(top_n, len(top))} THREATS (REAL RF, BY SCORE)",
                      styles["section_title"]), Spacer(1, 0.05*inch), t]


def _build_timeline(styles, records) -> list:
    from collections import defaultdict
    buckets: dict = defaultdict(int)
    for r in records:
        if not r.simulated:
            bucket = int(r.timestamp_utc // 300) * 300
            buckets[bucket] += 1

    if not buckets:
        return [Paragraph("DETECTION TIMELINE", styles["section_title"]),
                Paragraph("No real RF detections to chart.", styles["body"])]

    sorted_buckets = sorted(buckets.items())
    if len(sorted_buckets) > 24:
        sorted_buckets = sorted_buckets[-24:]

    max_count = max(v for _, v in sorted_buckets) or 1
    chart_w   = 6.8 * inch
    chart_h   = 1.2 * inch
    bar_gap   = chart_w / len(sorted_buckets)
    bar_w     = bar_gap * 0.7
    pad_b     = 0.15 * inch

    d = Drawing(chart_w, chart_h + pad_b)
    d.add(Line(0, pad_b, chart_w, pad_b, strokeColor=C_DARK_GREY, strokeWidth=0.5))

    for i, (ts, count) in enumerate(sorted_buckets):
        x     = i * bar_gap + (bar_gap - bar_w) / 2
        bar_h = (count / max_count) * chart_h
        color = C_RED if count >= 3 else C_AMBER if count >= 1 else C_DARK_GREY
        d.add(Rect(x, pad_b, bar_w, bar_h, fillColor=color, strokeColor=None))
        if i % 4 == 0:
            dt_et = _utc_to_et(datetime.datetime.utcfromtimestamp(ts))
            d.add(String(x + bar_w / 2, 2, dt_et.strftime("%H:%M"),
                         fontSize=5, fillColor=C_DARK_GREY, textAnchor="middle"))

    return [Paragraph("DETECTION TIMELINE — REAL RF (5-MIN INTERVALS)",
                      styles["section_title"]), Spacer(1, 0.05*inch), d]


def _build_footer(styles) -> list:
    text = (
        f"Generated by NSD v19 — ChaosTech Defense LLC | {_now_et()} | "
        "FOR OFFICIAL USE ONLY — NOT FOR PUBLIC RELEASE | "
        "This report contains RF sensing data collected by passive receive-only hardware."
    )
    return [
        HRFlowable(width="100%", thickness=1, color=C_GREEN),
        Spacer(1, 0.04*inch),
        Paragraph(text, styles["footer"]),
    ]


def _build_styles() -> dict:
    s = {}
    def ps(name, **kwargs):
        defaults = dict(fontName="Helvetica", fontSize=8, leading=10, textColor=C_BLACK)
        defaults.update(kwargs)
        s[name] = ParagraphStyle(name, **defaults)

    ps("co_name",      fontSize=13, fontName="Helvetica-Bold", textColor=C_GREEN, leading=16)
    ps("product",      fontSize=9,  textColor=C_MID_GREY, leading=11)
    ps("report_title", fontSize=11, fontName="Helvetica-Bold", textColor=C_WHITE, leading=14)
    ps("hw_status",    fontSize=9,  alignment=TA_RIGHT, leading=11)
    ps("meta_right",   fontSize=7,  textColor=C_MID_GREY, alignment=TA_RIGHT, leading=9)
    ps("section_title",fontSize=9,  fontName="Helvetica-Bold", textColor=C_BLACK, leading=11,
       borderPad=2, borderWidth=0, borderColor=C_BLACK,
       backColor=C_LIGHT_GREY, leftIndent=4)
    ps("sum_key",      fontSize=7.5, fontName="Helvetica-Bold", textColor=C_DARK_GREY, leading=10)
    ps("sum_val",      fontSize=7.5, textColor=C_BLACK, leading=10)
    ps("th",           fontSize=7.5, fontName="Helvetica-Bold", textColor=C_GREEN,
       alignment=TA_CENTER, leading=10)
    ps("td",           fontSize=7,   textColor=C_BLACK, leading=9)
    ps("td_center",    fontSize=7,   textColor=C_BLACK, alignment=TA_CENTER, leading=9)
    ps("td_small",     fontSize=6.5, textColor=C_BLACK, leading=8)
    ps("body",         fontSize=8,   textColor=C_DARK_GREY, leading=10)
    ps("footer",       fontSize=6,   textColor=C_DARK_GREY, alignment=TA_CENTER, leading=8)
    return s


def _utc_to_et(dt_utc: datetime.datetime) -> datetime.datetime:
    offset = datetime.timedelta(hours=-4 if 3 <= dt_utc.month <= 11 else -5)
    return dt_utc + offset


def _now_et() -> str:
    utc_now  = datetime.datetime.utcnow()
    et       = _utc_to_et(utc_now)
    tz_label = "EDT" if 3 <= utc_now.month <= 11 else "EST"
    return et.strftime(f"%m/%d/%Y %H:%M:%S {tz_label}")


def _fmt_uptime(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _color_hex(c) -> str:
    try:
        return f"{int(c.red*255):02x}{int(c.green*255):02x}{int(c.blue*255):02x}"
    except Exception:
        return "000000"

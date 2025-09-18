# email_alerts.py
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, timezone
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from config import SENDGRID_API_KEY, SENDER_EMAIL, ALERT_RECIPIENTS, ENABLE_EMAIL_ALERTS
from logger import get_logger
from db import get_session, Device

logger = get_logger("email_alerts")

def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        try:
            return int(str(value))
        except Exception:
            return default

def safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        try:
            return float(str(value))
        except Exception:
            return default

class DeviceInfo:
    def __init__(self, device: Union[Device, Dict[str, Any]]):
        if isinstance(device, dict):
            self.ip = device.get('ip')
            self.org = device.get('org')
            self.country = device.get('country')
            self.num_open_ports = device.get('num_open_ports')
            self.cve_count = device.get('cve_count')
            self.vulnerabilities = device.get('vulnerabilities', [])
            self.risk_label = device.get('risk_label', 'low')
        else:
            self.ip = getattr(device, 'ip', None)
            self.org = getattr(device, 'org', None)
            self.country = getattr(device, 'country', None)
            self.num_open_ports = getattr(device, 'num_open_ports', 0)
            self.cve_count = getattr(device, 'cve_count', 0)
            self.vulnerabilities = getattr(device, 'vulnerabilities', [])
            self.risk_label = getattr(device, 'risk_label', 'low')

def send_email_alert(subject: str, html_content: str, to_emails: Optional[Union[str, List[str]]] = None) -> Optional[Any]:
    """
    Send email via SendGrid to given recipients or configured ALERT_RECIPIENTS.
    
    Args:
        subject: Email subject line
        html_content: HTML content of the email
        to_emails: Single email address or list of email addresses. If None, uses ALERT_RECIPIENTS
        
    Returns:
        Response from SendGrid API or None if alerts are disabled
    """
    if not ENABLE_EMAIL_ALERTS:
        logger.warning("Email alerts are disabled or not fully configured.")
        return None

    to_emails = to_emails or ALERT_RECIPIENTS
    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=to_emails,
        subject=subject,
        html_content=html_content
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        logger.info("SendGrid status: %s", response.status_code)
        return response
    except Exception as e:
        logger.exception("Failed to send email via SendGrid: %s", e)
        raise

def build_device_summary(devices: List[Union[Device, Dict[str, Any]]]) -> str:
    """Build a compact, professional HTML email with a clear summary and actionable remediation items.

    The HTML is intentionally conservative (simple grid, clear headings, and concise suggestions) so it renders
    well across common email clients.
    """
    # Refined, professional palette and table layout for email clients
    css = """
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; color:#21303a; background:#f6f9fb; margin:0; padding:20px; }
        .container { max-width:960px; margin:0 auto; }
        .card { background:#ffffff; border-radius:10px; padding:20px; box-shadow:0 2px 6px rgba(16,24,40,0.06); }
        .header { text-align:left; padding-bottom:10px; border-bottom:1px solid #e6eef6; margin-bottom:16px }
        .title { font-size:20px; color:#0b3142; margin:0 0 6px 0; }
        .muted { color:#586b75; font-size:13px }
        table { width:100%; border-collapse:collapse; font-size:13px; color:#21303a }
        thead th { text-align:left; padding:12px 14px; background:#f1f5f9; color:#0b3142; font-weight:700; border-bottom:1px solid #e6eef6 }
        tbody td { padding:12px 14px; border-bottom:1px solid #f0f5f9; vertical-align:top }
        tbody tr:nth-child(even) { background:#ffffff }
        tbody tr:nth-child(odd) { background:#fbfeff }
        .ip { font-weight:700; color:#0b3142; font-family: 'SFMono-Regular', Menlo, Monaco, 'Roboto Mono', monospace }
        .org { color:#475569; font-size:13px }
        .badge { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:700; font-size:12px }
        .badge-high { background:#feecec; color:#7b1f1f; border:1px solid #f5c6c6 }
        .badge-medium { background:#fff6eb; color:#92400e; border:1px solid #f6d7a0 }
        .badge-low { background:#eafaf0; color:#06603f; border:1px solid #c8f1d6 }
        .notes { color:#334155; font-size:12px }
        thead th.col-ip { width:28% }
        thead th.col-loc { width:12% }
        thead th.col-ports, thead th.col-cvss { width:10%; text-align:center }
        thead th.col-risk { width:12%; text-align:center }
        thead th.col-notes { width:28% }
        td.center { text-align:center }
        .legend { margin-top:12px; font-size:12px; color:#586b75 }
        .footer { margin-top:18px; font-size:12px; color:#64748b }
    """

    lines = []
    # Count devices by risk level
    risk_counts = {'high': 0, 'medium': 0, 'low': 0}
    remediation_blocks = []

    for d in devices:
        risk_level = getattr(d, 'risk_label', 0)
        if risk_level == 2:
            risk_counts['high'] += 1
        elif risk_level == 1:
            risk_counts['medium'] += 1
        else:
            risk_counts['low'] += 1

    lines.append(f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <style>{css}</style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="header">
                    <div class="title">Security Risk Alert Report</div>
                    <div class="muted">Generated on {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')}</div>
                </div>

                <div style="margin-bottom:12px">
                    <strong style="font-size:16px">Summary</strong>
                    <div class="muted">Total: {len(devices)} — High: {risk_counts['high']} • Medium: {risk_counts['medium']} • Low: {risk_counts['low']}</div>
                </div>

                <table role="table" aria-label="Device summary">
                    <thead>
                        <tr>
                            <th>IP / Org</th>
                            <th>Location</th>
                            <th>Open Ports</th>
                            <th>Max CVSS</th>
                            <th>Risk</th>
                            <th>Notes</th>
                        </tr>
                    </thead>
                    <tbody>
    """)

    # normalize input: allow SQLAlchemy Device objects or pandas rows/dicts
    normalized = []
    for d in devices:
        # if it's a SQLAlchemy Device (has attributes), use directly
        if hasattr(d, 'ip') and hasattr(d, 'num_open_ports'):
            normalized.append(d)
            continue
        # if it's a pandas Series or dict-like row, convert to a simple namespace
        try:
            from types import SimpleNamespace
            ip = d.get('ip') if isinstance(d, dict) else d.get('IP') if hasattr(d, 'get') else None
            # fallback to attribute access
            if ip is None and hasattr(d, 'ip'):
                ip = getattr(d, 'ip')
            obj = SimpleNamespace()
            obj.ip = ip or ''
            obj.org = (d.get('org') or d.get('Org')) if isinstance(d, dict) or hasattr(d, 'get') else getattr(d, 'org', '')
            obj.country = (d.get('country') or d.get('Country')) if isinstance(d, dict) or hasattr(d, 'get') else getattr(d, 'country', '')
            # numeric fields
            try:
                obj.num_open_ports = int(d.get('open_ports') if isinstance(d, dict) else d.get('Open Ports'))
            except Exception:
                obj.num_open_ports = int(getattr(d, 'num_open_ports', 0) or 0)
            try:
                obj.cve_count = int(d.get('cve_count') if isinstance(d, dict) else d.get('CVE Count'))
            except Exception:
                obj.cve_count = int(getattr(d, 'cve_count', 0) or 0)
            try:
                obj.max_cvss = float(d.get('max_cvss') if isinstance(d, dict) else d.get('Max CVSS'))
            except Exception:
                try:
                    obj.max_cvss = float(getattr(d, 'max_cvss', getattr(d, 'Max CVSS', 0.0)) or 0.0)
                except Exception:
                    obj.max_cvss = None
            # risk label or text
            obj.risk_label = getattr(d, 'risk_label', None)
            obj.risk = (d.get('risk') if isinstance(d, dict) else d.get('Risk')) if isinstance(d, dict) or hasattr(d, 'get') else getattr(d, 'risk', '')
            # last_seen as datetime or string
            obj.last_seen = None
            ls = None
            try:
                ls = d.get('last_seen') if isinstance(d, dict) else d.get('Last Seen')
            except Exception:
                ls = getattr(d, 'last_seen', None)
            # if ls is string, leave as string; build_device_summary handles str/None
            obj.last_seen = ls
            # vulnerabilities: DataFrame rows won't have details; leave empty list
            obj.vulnerabilities = []
            normalized.append(obj)
        except Exception:
            # fallback: skip malformed row
            continue

    # use normalized list moving forward
    devices = normalized

    # Helper to render risk badge HTML (uses simplified classes above)
    def _badge(risk_text):
        r = (risk_text or '').lower()
        if 'high' in r:
            return "<span class='badge badge-high'>HIGH</span>"
        if 'medium' in r:
            return "<span class='badge badge-medium'>MEDIUM</span>"
        if 'low' in r:
            return "<span class='badge badge-low'>LOW</span>"
        return "<span class='badge'>UNKNOWN</span>"

    for d in devices:
        max_cvss = f"{d.max_cvss:.1f}" if (hasattr(d, 'max_cvss') and d.max_cvss is not None) else "N/A"
        last_seen = d.last_seen.strftime("%Y-%m-%d %H:%M:%S") if hasattr(d, 'last_seen') and getattr(d, 'last_seen') and hasattr(d.last_seen, 'strftime') else (d.last_seen or "")
        risk_label = getattr(d, 'risk_label', None)
        risk_map = {0:'Low', 1:'Medium', 2:'High'}
        risk_text = risk_map.get(risk_label, 'Unknown') if risk_label is not None else 'Unknown'

        # Build 'why' explanation
        reasons = []
        if d.max_cvss and d.max_cvss >= 9:
            reasons.append(f"Critical CVSS {d.max_cvss:.1f}")
        elif d.max_cvss and d.max_cvss >= 7:
            reasons.append(f"High CVSS {d.max_cvss:.1f}")
        if d.num_open_ports and d.num_open_ports > 20:
            reasons.append(f"Many open ports ({d.num_open_ports})")
        if not reasons:
            reasons.append("Automated risk classification marked this device as high risk")

        # Smart remediation suggestions based on risk factors
        suggestions = []
        
        # CVSS-based recommendations
        if d.max_cvss and d.max_cvss >= 9:
            suggestions.append("CRITICAL: Immediate action required - Critical vulnerabilities detected!")
            suggestions.append("1. Deploy emergency patches within next 24 hours")
            suggestions.append("2. If patching not possible, implement strict access controls and monitoring")
            suggestions.append("3. Consider temporary service shutdown until patched")
        elif d.max_cvss and 7 <= d.max_cvss < 9:
            suggestions.append("HIGH: Urgent attention needed - High-severity vulnerabilities present")
            suggestions.append("1. Schedule patching within next 72 hours")
            suggestions.append("2. Implement additional logging and monitoring")
            suggestions.append("3. Review and restrict access permissions")
        elif d.max_cvss and 4 <= d.max_cvss < 7:
            suggestions.append("MEDIUM: Action required - Moderate-risk vulnerabilities found")
            suggestions.append("1. Include in next scheduled patch cycle")
            suggestions.append("2. Review security configurations")
        
        # Port exposure recommendations
        if d.num_open_ports:
            if d.num_open_ports > 20:
                suggestions.append(f"EXPOSURE RISK: Excessive open ports detected ({d.num_open_ports})")
                suggestions.append("1. Immediate port audit required - close all non-essential services")
                suggestions.append("2. Implement network segmentation")
                suggestions.append("3. Consider deploying a Web Application Firewall (WAF)")
            elif d.num_open_ports > 10:
                suggestions.append(f"EXPOSURE WARNING: High number of open ports ({d.num_open_ports})")
                suggestions.append("1. Review and justify each open port")
                suggestions.append("2. Implement strict firewall rules")
            else:
                suggestions.append(f"Port exposure: {d.num_open_ports} ports open")
                suggestions.append("1. Verify each port is necessary for operations")
        
        # CVE count based recommendations
        if d.cve_count:
            if d.cve_count > 5:
                suggestions.append(f"VULNERABILITY CONCENTRATION: Multiple CVEs detected ({d.cve_count})")
                suggestions.append("1. Perform comprehensive security audit")
                suggestions.append("2. Consider system upgrade or replacement")
            elif d.cve_count > 0:
                suggestions.append(f"Vulnerabilities present: {d.cve_count} CVEs detected")
                suggestions.append("1. Review each CVE and assess impact")
        
        # Organization-specific recommendations
        if 'university' in (d.org or '').lower():
            suggestions.append("EDUCATION SECTOR RECOMMENDATIONS:")
            suggestions.append("1. Review student/faculty data access controls")
            suggestions.append("2. Ensure FERPA compliance measures")
        elif any(word in (d.org or '').lower() for word in ['bank', 'financial', 'payment']):
            suggestions.append("FINANCIAL SECTOR RECOMMENDATIONS:")
            suggestions.append("1. Verify PCI-DSS compliance status")
            suggestions.append("2. Review transaction monitoring systems")
        
        # Add general recommendations based on risk level
        if risk_text.lower() == 'high':
            suggestions.append("GENERAL HIGH-RISK ACTIONS:")
            suggestions.append("1. Notify security incident response team")
            suggestions.append("2. Document all remediation steps for compliance")
            suggestions.append("3. Prepare incident report for stakeholders")
        
        # Isolation recommendation for high-risk cases
        if risk_text.lower() == 'high' or (d.max_cvss and d.max_cvss >= 7):
            suggestions.append("ISOLATION RECOMMENDED:")
            suggestions.append("1. Move device to quarantine network")
            suggestions.append("2. Implement strict access controls")
            suggestions.append("3. Monitor all traffic to/from device")

        # Compose HTML for the device
        risk_class = 'high' if risk_text.lower() == 'high' else ('medium' if risk_text.lower() == 'medium' else 'low')
        
        # compact notes: top 2 suggestion lines or reasons
        top_notes = []
        if suggestions:
            for s in suggestions:
                # skip section headings like 'GENERAL HIGH-RISK ACTIONS:'
                if s.endswith(':'):
                    continue
                top_notes.append(s)
                if len(top_notes) >= 2:
                    break

        notes_html = '<br>'.join(top_notes) if top_notes else 'See remediation section.'

        lines.append(f"""
                        <tr>
                            <td><div class='ip'>{d.ip}</div><div class='org'>{d.org or 'N/A'}</div></td>
                            <td>{d.country or 'N/A'}</td>
                            <td>{d.num_open_ports or 0}</td>
                            <td>{max_cvss}</td>
                            <td>{_badge(risk_text)}</td>
                            <td class='notes'>{notes_html}</td>
                        </tr>
        """)

        # Build remediation block separately for better layout below the table
        rem_lines = [f"<div style='margin-top:12px;padding:12px;border:1px solid #eef2f7;border-radius:6px;background:#fbfdff'>",
                     f"<strong>{d.ip} — {d.org or 'N/A'} ({risk_text})</strong>",
                     f"<div style='color:#475569;margin-top:6px'><em>Top findings:</em> {'; '.join(reasons)}</div>",
                     "<div style='margin-top:8px;color:#334155'>"]

        for s in suggestions:
            rem_lines.append(f"<div style='margin-bottom:4px'>• {s}</div>")

        rem_lines.append("</div></div>")
        remediation_blocks.append("\n".join(rem_lines))
    # Close table body and table
    lines.append("""
                    </tbody>
                </table>
    """)

    # Append remediation details for each device
    if remediation_blocks:
        lines.append("""
                <div style='margin-top:18px'>
                    <strong style='font-size:14px'>Remediation Guidance</strong>
                    <div class='muted' style='margin-top:6px'>Detailed recommendations per device</div>
        """)
        for rb in remediation_blocks:
            lines.append(rb)
        lines.append("""
                </div>
        """)

    # Legend and footer
    lines.append(f"""
                <div class='legend'>Legend: <span class='badge badge-high'>HIGH</span> <span class='badge badge-medium'>MEDIUM</span> <span class='badge badge-low'>LOW</span></div>
                <div class='footer'>If you need help triaging these devices, collect the device scan output and contact your security/ops team.</div>
            </div>
        </div>
    </body>
    </html>
    """)

    return "\n".join(lines)

def build_plaintext_summary(devices: List[Union[Device, Dict[str, Any]]]) -> str:
    """Simple plaintext fallback for email clients that do not render HTML well."""
    lines = [f"Security Risk Alert Report - Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"]
    for d in devices:
        max_cvss = safe_float(getattr(d, 'max_cvss', None))
        lines.append(f"IP: {getattr(d, 'ip', '')} | Org: {getattr(d, 'org', '')} | Risk: {getattr(d, 'risk_label', '')} | CVE Count: {getattr(d, 'cve_count', 0)} | Max CVSS: {max_cvss or 'N/A'}")
    return "\n".join(lines)

def notify_new_high_risk_devices():
    """
    Find devices with risk_label == 2 (High) and notified == False, send aggregated email and mark as notified.
    
    Risk Level Mapping:
    - 0: Low
    - 1: Medium
    - 2: High
    """
    if not ENABLE_EMAIL_ALERTS:
        logger.info("Email alerts disabled; skipping notification.")
        return

    session = get_session()
    try:
        # Get devices with high risk (risk_label == 2) that haven't been notified
        devices = session.query(Device).filter(Device.risk_label == 2, Device.notified == False).all()
        
        if not devices:
            logger.info("No new high-risk devices found for notification.")
            return
        if not devices:
            logger.debug("No new high-risk devices to notify.")
            return
        # Build a rich HTML body and send
        html_body = build_device_summary(devices)
        subject = f"[Threat Hunting] {len(devices)} New High-Risk Device(s) Detected"
        try:
            send_email_alert(subject, html_body)
            for d in devices:
                d.notified = True
            session.commit()
            logger.info("Notified about %d devices and updated DB flags.", len(devices))
        except Exception:
            logger.exception("Failed to send notification email; DB changes rolled back.")
            session.rollback()
    except Exception as e:
        logger.exception("Error checking DB for high-risk devices: %s", e)
    finally:
        session.close()

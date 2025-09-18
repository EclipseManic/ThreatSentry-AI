from types import SimpleNamespace
from email_alerts import build_device_summary, build_plaintext_summary
from datetime import datetime

# Create two dummy devices similar to ORM objects
d1 = SimpleNamespace(ip='192.0.2.10', org='Example Org', country='US', num_open_ports=22, cve_count=3, max_cvss=8.6, risk_label=2, vulnerabilities=[], last_seen=datetime.now())
d2 = SimpleNamespace(ip='192.0.2.11', org='Test Inc', country='GB', num_open_ports=3, cve_count=0, max_cvss=None, risk_label=1, vulnerabilities=[], last_seen=datetime.now())

html = build_device_summary([d1, d2])
text = build_plaintext_summary([d1, d2])
print('HTML length:', len(html))
print('HTML preview:\n', html[:800])
print('\nPlaintext preview:\n', text)

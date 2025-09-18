"""
Generate a realistic-looking synthetic training dataset for the threat-hunting model.
Writes JSON to `model/my_training_data.json`.
Usage: python generate_realistic_training_data.py --count 500
"""
import json
import random
import argparse
from ipaddress import IPv4Address

random.seed(42)

ORGS = [
    "Amazon AWS", "DigitalOcean", "Google Cloud", "Microsoft Azure", "Hetzner", "OVH", "Cloudflare", 
    "Linode", "Akamai", "Rackspace", "SmallCorp Inc.", "Factory IoT", "Retail POS", "University IT",
    "Managed Hosting", "ISP Backbone", "Edge Provider", "Security Lab"
]
COUNTRIES = ["US", "DE", "GB", "FR", "NL", "SE", "CN", "IN", "BR", "RU", "JP", "SG", "AU", "CA"]

# Reserved/Private first octets to avoid
PRIVATE_FIRST = {10, 127, 169, 172, 192, 0}
# Exclude multicast (224-239), reserved > 240
BAD_FIRST = set(range(224, 256)) | set(range(240, 256))


def random_public_ip():
    # produce a pseudo-random public IPv4 avoiding common private and reserved ranges
    while True:
        a = random.randint(1, 223)
        if a in PRIVATE_FIRST or a in BAD_FIRST:
            continue
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        ip = f"{a}.{b}.{c}.{d}"
        # avoid link-local
        if a == 169 and b == 254:
            continue
        return ip


def generate_record():
    # Choose device type mix
    t = random.random()
    if t < 0.65:
        # typical client/workstation
        num_open_ports = random.choices([1,2,3,4,5,6,7,8,9,10, 11, 12, 15], weights=[10,8,6,6,5,5,4,3,3,2,1,1,1])[0]
        org = random.choice(["SmallCorp Inc.", "Retail POS", "University IT", "Managed Hosting"])
        country = random.choice(COUNTRIES)
        cve_count = random.choices(range(0,6), weights=[50,20,10,8,7,5])[0]
        # low CVSS most likely
        max_cvss = round(random.random() * 4.5 + random.choice([0.0, 0.0, 0.2]), 1)
        exposure_days = random.randint(0, 90)
    elif t < 0.90:
        # server / web service
        num_open_ports = random.choice([10, 12, 16, 20, 22, 25, 53, 80, 443, 110, 143, 3389, 8080, 8443, 3306, 5432, 6379, 27017])
        # a subset may expose many ports
        if random.random() < 0.05:
            num_open_ports = random.randint(30, 120)
        org = random.choice(["Amazon AWS", "Google Cloud", "Microsoft Azure", "DigitalOcean", "OVH", "Hetzner", "Linode", "Managed Hosting"])
        country = random.choice(COUNTRIES)
        cve_count = random.randint(0, 60)
        # CVSS spread: many servers have medium/high CVEs
        max_cvss = round(random.choice([random.uniform(0,6), random.uniform(4,9), random.uniform(6.5,10)]) ,1)
        exposure_days = random.randint(10, 800)
    else:
        # IoT / embedded / high-port-count scanner / honeypot
        if random.random() < 0.5:
            # IoT: few ports, low CVSS but long exposure
            num_open_ports = random.randint(1, 6)
            cve_count = random.randint(0, 8)
            max_cvss = round(random.uniform(0,7),1)
            exposure_days = random.randint(30, 1000)
            org = random.choice(["Factory IoT", "Retail POS", "Edge Provider"]) 
            country = random.choice(COUNTRIES)
        else:
            # scanner/honeypot: many ports
            num_open_ports = random.randint(100, 400)
            cve_count = random.randint(10, 200)
            max_cvss = round(random.uniform(5,10),1)
            exposure_days = random.randint(30, 1500)
            org = random.choice(["Security Lab", "ISP Backbone", "Akamai", "Cloudflare"]) 
            country = random.choice(COUNTRIES)

    # Correlate CVE count and max_cvss slightly
    if cve_count > 30 and max_cvss < 6.0:
        max_cvss = round(random.uniform(6.0, 9.8), 1)
    if max_cvss >= 9.0 and cve_count < 5:
        cve_count = random.randint(5, 80)

    # derive label rules (0=Low,1=Medium,2=High)
    label = 0
    if max_cvss >= 9.0 or cve_count > 30 or num_open_ports > 200:
        label = 2
    elif max_cvss >= 7.0 or cve_count > 10 or num_open_ports > 50:
        label = 1
    else:
        label = 0

    return {
        "ip": random_public_ip(),
        "org": org,
        "country": country,
        "num_open_ports": int(num_open_ports),
        "cve_count": int(cve_count),
        "max_cvss": float(round(max_cvss, 1)),
        "exposure_days": int(exposure_days),
        "label": int(label)
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--count', type=int, default=500)
    parser.add_argument('--out', type=str, default='model/my_training_data.json')
    args = parser.parse_args()

    records = []
    ips = set()
    for _ in range(args.count):
        r = generate_record()
        # ensure unique IPs
        while r['ip'] in ips:
            r['ip'] = random_public_ip()
        ips.add(r['ip'])
        records.append(r)

    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=2)

    # print a small summary
    cnts = {0:0,1:0,2:0}
    for r in records:
        cnts[r['label']] += 1
    print(f"Wrote {len(records)} records to {args.out} (Low={cnts[0]}, Medium={cnts[1]}, High={cnts[2]})")


if __name__ == '__main__':
    main()

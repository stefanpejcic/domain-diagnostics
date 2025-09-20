# dns-visualizer.py
from flask import Flask, request, jsonify, render_template_string
import re
import os
import socket
import ssl
import time
import requests
import json
import dns.resolver
from datetime import datetime


# https://python-babel.github.io/flask-babel/
from flask_babel import Babel, _


# Import stuff from OpenPanel core
from app import app, inject_data, login_required_route

# Validation
def is_valid_domain(d):
    return bool(re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', d, re.I)) or \
           bool(re.match(r'^[a-z0-9-]{1,63}$', d, re.I))

def is_valid_host_or_ip(h):
    try:
        socket.inet_aton(h)
        return True
    except:
        return is_valid_domain(h)

def resolve_first_ip(host):
    try:
        socket.inet_aton(host)
        return host
    except:
        try:
            return socket.gethostbyname(host)
        except:
            return None

 
@app.route('/domains/diagnostics', methods=['GET', 'POST'])
@login_required_route
def domain_diagnostics():
    action = request.args.get('action')
    target = request.form.get('target') or request.args.get('target') or ''
    target = target.strip()

    if request.method == 'POST' and action:
        if not is_valid_host_or_ip(target):
            return "Error: Invalid domain or IP provided.", 400

        # WHOIS / RDAP
        if action == 'whois':
            domain = target.lower()
            url = f"https://rdap.org/ip/{domain}" if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else f"https://rdap.org/domain/{domain}"
            try:
                resp = requests.get(url, timeout=5)
                data = resp.json()
            except:
                return "Error: Unable to fetch WHOIS/RDAP info. Available TLDs: https://deployment.rdap.org/"
            lines = []
            if 'handle' in data: lines.append(f"Handle: {data['handle']}")
            if 'name' in data: lines.append(f"Name: {data['name']}")
            if 'ldhName' in data: lines.append(f"Domain: {data['ldhName']}")
            if 'entities' in data:
                lines.append("Entities:")
                for ent in data['entities']:
                    lines.append(f"  - {ent.get('handle','[unknown]')} ({ent.get('roles',[None])[0]})")
            if 'events' in data:
                for evt in data['events']:
                    lines.append(f"{evt['eventAction'].capitalize()}: {evt['eventDate']}")
            return "\n".join(lines)

        # PING (TCP connect style)
        if action == 'ping':
            host = target
            port = int(request.form.get('port', 80))
            count = 5
            timeout = 2.0
            bytes_size = 64
            ttl_default = 64

            ip = resolve_first_ip(host)
            if not ip:
                return "Error: Could not resolve host.", 400

            lines = [f"PING {host} ({ip}) {bytes_size}(84) bytes of data."]
            rtts = []
            transmitted = 0
            received = 0
            start_total = time.time()

            for i in range(1, count+1):
                transmitted += 1
                start = time.time()
                try:
                    s = socket.create_connection((ip, port), timeout=timeout)
                    s.close()
                    elapsed_ms = round((time.time() - start) * 1000, 3)
                    received += 1
                    lines.append(f"{bytes_size} bytes from {ip} ({ip}): icmp_seq={i} ttl={ttl_default} time={elapsed_ms:.3f} ms")
                    rtts.append(elapsed_ms)
                except Exception as e:
                    lines.append(f"Request timeout for icmp_seq {i} ({str(e)})")
                time.sleep(0.2)

            total_ms = round((time.time() - start_total) * 1000)
            loss_pct = round((transmitted - received)/transmitted * 100) if transmitted > 0 else 0
            if rtts:
                avg = sum(rtts)/len(rtts)
                mdev = (sum((x-avg)**2 for x in rtts)/len(rtts))**0.5
                lines.append(f"rtt min/avg/max/mdev = {min(rtts):.3f}/{avg:.3f}/{max(rtts):.3f}/{mdev:.3f} ms")
            else:
                lines.append("rtt min/avg/max/mdev = 0/0/0/0 ms")
            lines.append(f"--- {host} ping statistics ---")
            lines.append(f"{transmitted} packets transmitted, {received} received, {loss_pct}% packet loss, time {total_ms}ms")
            return "\n".join(lines)

        # SSL
        if action == 'ssl':
            host = target
            port = 443
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
            except Exception as e:
                return f"Error: Unable to connect: {e}"

            lines = [
                f"Subject: {dict(cert.get('subject',{})).get('commonName','[unknown]')}",
                f"Issuer: {dict(cert.get('issuer',{})).get('commonName','[unknown]')}",
                f"Valid From: {cert.get('notBefore','[unknown]')}",
                f"Valid To:   {cert.get('notAfter','[unknown]')}",
            ]
            if 'subjectAltName' in cert:
                lines.append("SANs: " + ", ".join([v for k,v in cert['subjectAltName']]))
            return "\n".join(lines)

        # Resolve
        if action == 'resolve':
            ip = resolve_first_ip(target)
            if not ip:
                return "Error: Could not resolve host.", 400
            return f"Resolved IP: {ip}"

        # DNS
        if action == 'dns':
            types = ['A','AAAA','CNAME','MX','NS','TXT','SRV']
            lines = []
            for t in types:
                try:
                    answers = dns.resolver.resolve(target, t)
                    if answers:
                        lines.append(f"{t} Records:")
                        for r in answers:
                            lines.append(f"  {r.to_text()}")
                except:
                    pass
            lines.append(f"Resolved IP: {resolve_first_ip(target)}")
            return "\n".join(lines)

        return "Error: Unknown action", 400
  
    template_path = os.path.join(os.path.dirname(__file__), 'domain-diagnostics.html')
    with open(template_path) as f:
        template = f.read()

    return render_template_string(
        template, title=_('Domain Diagnostics')
    )


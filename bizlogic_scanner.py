#!/usr/bin/env python3
"""
bizlogic_scanner.py 
Interactive, modular business-logic heuristic scanner with advanced exploitation
by: ek0ms-style 
ETHICS: Only test systems you own or have explicit permission to test.
This tool is intentionally conservative and rate-limited by default.
"""

import sys
import time
import re
import uuid
import json
import html
import random
import string
import os
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import requests
from bs4 import BeautifulSoup
from collections import deque, defaultdict
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

# ---------- Config ----------
DEFAULT_HEADERS = {
    "User-Agent": "BizLogicScanner/1.2 (+https://github.com/ekomsSavior)",
}
REQUEST_TIMEOUT = 10
CRAWL_MAX_PAGES = 50
CRAWL_SAME_DOMAIN_ONLY = True
RATE_LIMIT_SECONDS = 0.5  # default pause between requests
SAFE_REPEAT_LIMIT = 3     # safe number of repeats for non-destructive checks

# File paths - will be set dynamically based on scan time
REPORTS_DIR = "reports"
REPORT_FILE = None
REPORT_JSON = None
REPORT_HTML = None
NUCLEI_FILE = None

# ---------- Exploitation Config ----------
EXPLOIT_TIMEOUT = 15
TEST_EMAIL_DOMAIN = "test.example.com"  # Change to your test domain
TEST_PASSWORD = "TestPass123!"
MAX_EXPLOIT_ATTEMPTS = 5  # Safety limit for automated exploitation
EXPLOIT_RATE_LIMIT = 1.0  # Slower rate for exploitation

# ---------- Directory and File Management ----------
def setup_report_files(base_url):
    """Create reports directory and set up file paths with timestamp"""
    # Create reports directory if it doesn't exist
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
        print(f"[+] Created reports directory: ./{REPORTS_DIR}/")
    
    # Create scan-specific directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = urlparse(base_url).netloc.replace(':', '_').replace('/', '_')
    scan_dir = os.path.join(REPORTS_DIR, f"scan_{domain}_{timestamp}")
    
    if not os.path.exists(scan_dir):
        os.makedirs(scan_dir)
        print(f"[+] Created scan directory: ./{scan_dir}/")
    
    # Set global file paths
    global REPORT_FILE, REPORT_JSON, REPORT_HTML, NUCLEI_FILE
    REPORT_FILE = os.path.join(scan_dir, "bizlogic_report.txt")
    REPORT_JSON = os.path.join(scan_dir, "bizlogic_report.json")
    REPORT_HTML = os.path.join(scan_dir, "bizlogic_report.html")
    NUCLEI_FILE = os.path.join(scan_dir, "bizlogic_nuclei_templates.yaml")
    
    return scan_dir

# ---------- Utilities ----------
class ScannerSession:
    def __init__(self, base_url, rate_limit=RATE_LIMIT_SECONDS, headers=None):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.session = requests.Session()
        self.session.headers.update(headers or DEFAULT_HEADERS)
        self.rate_limit = rate_limit
        self.visited = set()
        self.pages = {}  # url -> (status_code, content)
        self.forms = defaultdict(list)  # url -> [forms]
        self.findings = []
        self.exploitation_results = []
        self.start_time = datetime.now(timezone.utc)
        self.authenticated = False
        self.discovery = {"robots": None, "sitemaps": [], "openapi": None, "openapi_paths": []}

    def _sleep(self):
        time.sleep(self.rate_limit)

    def safe_get(self, url, **kwargs):
        self._sleep()
        try:
            r = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, **kwargs)
            return r
        except Exception:
            return None

    def safe_post(self, url, data=None, json=None, **kwargs):
        self._sleep()
        try:
            r = self.session.post(url, data=data, json=json, timeout=REQUEST_TIMEOUT, allow_redirects=True, **kwargs)
            return r
        except Exception:
            return None

    def safe_head(self, url, **kwargs):
        self._sleep()
        try:
            r = self.session.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, **kwargs)
            return r
        except Exception:
            return None

    def crawl(self, start_path="/", max_pages=CRAWL_MAX_PAGES):
        """
        Conservative same-origin crawler that records pages and forms.
        """
        q = deque()
        root = urljoin(self.base_url, start_path)
        q.append(root)
        while q and len(self.pages) < max_pages:
            url = q.popleft()
            if url in self.visited:
                continue
            # same domain?
            parsed = urlparse(url)
            if CRAWL_SAME_DOMAIN_ONLY:
                if parsed.netloc != self.parsed_base.netloc:
                    continue
            r = self.safe_get(url)
            self.visited.add(url)
            if not r:
                continue
            self.pages[url] = (r.status_code, r.text)
            # parse for links and forms
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a.get("href")
                joined = urljoin(url, href)
                if joined not in self.visited and urlparse(joined).scheme in ("http", "https"):
                    q.append(joined)
            # capture forms
            for form in soup.find_all("form"):
                form_info = parse_form(form, url)
                self.forms[url].append(form_info)

def parse_form(soup_form, page_url):
    method = (soup_form.get("method") or "get").lower()
    action = soup_form.get("action") or page_url
    form_id = soup_form.get("id") or soup_form.get("name") or None
    classes = " ".join(soup_form.get("class") or []) or None
    inputs = []
    for inp in soup_form.find_all(["input", "textarea", "select"]):
        name = inp.get("name")
        itype = inp.get("type", inp.name)
        value = inp.get("value", "")
        inputs.append({"name": name, "type": itype, "value": value})
    raw = str(soup_form)[:2000]  # cap raw to avoid huge blobs
    return {"method": method, "action": urljoin(page_url, action), "inputs": inputs,
            "raw": raw, "id": form_id, "classes": classes}

def snippet_of(text, match, ctx=80):
    """
    Return a small snippet around the match for context.
    match: either a string (literal) or compiled regex match object (re.Match)
    """
    if not text:
        return ""
    try:
        if isinstance(match, re.Match):
            s = match.start()
            e = match.end()
        else:
            idx = text.lower().find(str(match).lower())
            if idx == -1:
                return ""
            s = idx
            e = idx + len(str(match))
        start = max(0, s - ctx)
        end = min(len(text), e + ctx)
        return text[start:end].replace("\n", " ").strip()
    except Exception:
        return ""

def short(s, n=120):
    return (s[:n] + "...") if s and len(s) > n else (s or "")

def severity_confidence_from_type(t):
    # basic mapping: adjust as you like
    sev = "Medium"
    conf = "Low"
    if "token" in t or "reset" in t or "exposure" in t:
        sev = "High"
        conf = "Medium"
    if "insecure_id" in t or "enumeration" in t or "ownership" in t:
        sev = "High"
        conf = "Medium"
    if "client_side" in t or "form_missing" in t:
        sev = "Medium"
        conf = "Low"
    return sev, conf

# ---------- Exploitation Utilities ----------
def generate_test_email():
    """Generate a random test email"""
    username = ''.join(random.choices(string.ascii_lowercase, k=8))
    return f"{username}@{TEST_EMAIL_DOMAIN}"

def generate_test_id(start=1000, end=9999):
    """Generate a test numeric ID"""
    return random.randint(start, end)

class ExploitationEngine:
    def __init__(self, session):
        self.sess = session
        self.results = []
        self.test_accounts = []

    def _sleep_exploit(self):
        """Slower sleep for exploitation to be safer"""
        time.sleep(EXPLOIT_RATE_LIMIT)

    def safe_get_exploit(self, url, **kwargs):
        self._sleep_exploit()
        try:
            r = self.sess.session.get(url, timeout=EXPLOIT_TIMEOUT, allow_redirects=True, **kwargs)
            return r
        except Exception:
            return None

    def safe_post_exploit(self, url, data=None, json=None, **kwargs):
        self._sleep_exploit()
        try:
            r = self.sess.session.post(url, data=data, json=json, timeout=EXPLOIT_TIMEOUT, allow_redirects=True, **kwargs)
            return r
        except Exception:
            return None

    def record_exploit_result(self, finding_id, exploit_type, success, details, evidence=None, payload_used=None):
        """Record exploitation attempt results"""
        result = {
            "finding_id": finding_id,
            "exploit_type": exploit_type,
            "success": success,
            "details": details,
            "evidence": evidence,
            "payload_used": payload_used,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.results.append(result)
        return result

    def exploit_insecure_id_enumeration(self, finding):
        """Exploit predictable ID enumeration with enhanced testing"""
        print(f"  [*] Attempting IDOR exploitation for {finding['url']}")
        
        original_url = finding['url']
        original_id = finding.get('parameter', '').strip()
        
        if not original_id.isdigit():
            return self.record_exploit_result(
                finding['id'], 'IDOR', False, 
                f"Non-numeric ID found: {original_id}"
            )
        
        # Test multiple ID patterns
        test_ids = [
            str(int(original_id) + 1),  # Next ID
            str(int(original_id) - 1),  # Previous ID
            str(int(original_id) + 100), # Jump pattern
            "1",  # First ID
            "999999"  # High ID
        ]
        
        successes = []
        
        for test_id in test_ids:
            test_url = original_url.replace(original_id, test_id)
            response = self.safe_get_exploit(test_url)
            
            if response and response.status_code == 200:
                # Check if content is meaningfully different (not just generic pages)
                original_content = self.sess.pages.get(original_url, (None, ""))[1] or ""
                test_content = response.text
                
                # Simple content differentiation
                if (len(test_content) > 100 and 
                    test_content != original_content and
                    "not found" not in test_content.lower() and
                    "error" not in test_content.lower()):
                    
                    successes.append({
                        'test_id': test_id,
                        'url': test_url,
                        'status': response.status_code,
                        'content_length': len(test_content),
                        'different_content': test_content != original_content
                    })
        
        if successes:
            return self.record_exploit_result(
                finding['id'], 'IDOR', True,
                f"Successfully accessed {len(successes)} resources with predictable IDs",
                json.dumps(successes[:3], indent=2),  # Limit evidence size
                f"Tested IDs: {test_ids}"
            )
        else:
            return self.record_exploit_result(
                finding['id'], 'IDOR', False,
                f"No accessible resources found with alternative IDs"
            )

    def exploit_token_in_url(self, finding):
        """Exploit token exposure in URLs with parameter manipulation"""
        print(f"  [*] Testing token exposure for {finding['url']}")
        
        url = finding['url']
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Identify token parameters
        token_params = [k for k in query_params.keys() 
                       if any(token_word in k.lower() for token_word in 
                             ['token', 'auth', 'session', 'key', 'secret'])]
        
        if not token_params:
            return self.record_exploit_result(
                finding['id'], 'TokenExposure', False,
                "No token parameters identified"
            )
        
        # Test strategies
        strategies = []
        
        # 1. Remove tokens completely
        clean_params = {k: v for k, v in query_params.items() if k not in token_params}
        clean_query = urlencode(clean_params, doseq=True)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if clean_query:
            clean_url += f"?{clean_query}"
        
        response = self.safe_get_exploit(clean_url)
        if response and response.status_code == 200:
            strategies.append(f"Access without tokens: {clean_url}")
        
        # 2. Test with empty tokens
        empty_params = query_params.copy()
        for token_param in token_params:
            empty_params[token_param] = ['']
        empty_query = urlencode(empty_params, doseq=True)
        empty_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{empty_query}"
        
        response = self.safe_get_exploit(empty_url)
        if response and response.status_code == 200:
            strategies.append(f"Access with empty tokens: {empty_url}")
        
        # 3. Test with predictable tokens
        predictable_params = query_params.copy()
        for token_param in token_params:
            predictable_params[token_param] = ['test', '123456', 'admin']
        # Test each predictable value
        for test_value in ['test', '123456', 'admin']:
            test_params = query_params.copy()
            for token_param in token_params:
                test_params[token_param] = [test_value]
            test_query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
            
            response = self.safe_get_exploit(test_url)
            if response and response.status_code == 200:
                strategies.append(f"Access with token='{test_value}': {test_url}")
                break
        
        if strategies:
            return self.record_exploit_result(
                finding['id'], 'TokenExposure', True,
                f"Multiple token bypass strategies successful",
                "\n".join(strategies[:3]),  # Limit output
                f"Tested parameters: {token_params}"
            )
        else:
            status = response.status_code if response else "No response"
            return self.record_exploit_result(
                finding['id'], 'TokenExposure', False,
                f"Token parameters appear required (Status: {status})"
            )

    def exploit_weak_password_recovery(self, finding):
        """Exploit weak password recovery mechanisms with comprehensive testing"""
        print(f"  [*] Testing password recovery for {finding['url']}")
        
        page_url = finding['url']
        forms = self.sess.forms.get(page_url, [])
        
        recovery_forms = []
        for form in forms:
            if any(keyword in form['action'].lower() for keyword in 
                  ['forgot', 'reset', 'recover', 'password']):
                recovery_forms.append(form)
        
        if not recovery_forms:
            return self.record_exploit_result(
                finding['id'], 'WeakPasswordRecovery', False,
                "No password recovery forms found"
            )
        
        results = []
        
        for form in recovery_forms:
            # Test with non-existent user
            test_email = generate_test_email()
            form_data = self._build_form_data(form, test_email)
            
            response = self._submit_form(form, form_data)
            
            if response:
                # Check for various success indicators
                success_indicators = [
                    'email has been sent', 'check your email', 'reset link',
                    'success', 'sent', 'instructions', 'password reset'
                ]
                
                response_lower = response.text.lower()
                if any(indicator in response_lower for indicator in success_indicators):
                    results.append(f"Recovery initiated for non-existent user: {test_email}")
                
                # Check for user enumeration
                error_indicators = [
                    'user not found', 'unknown user', 'invalid username',
                    'no account found', 'user does not exist'
                ]
                
                if any(indicator in response_lower for indicator in error_indicators):
                    results.append(f"User enumeration possible - distinct error for: {test_email}")
        
        if results:
            return self.record_exploit_result(
                finding['id'], 'WeakPasswordRecovery', True,
                f"Password recovery vulnerabilities detected",
                "\n".join(results),
                f"Test emails: {test_email}"
            )
        else:
            return self.record_exploit_result(
                finding['id'], 'WeakPasswordRecovery', False,
                "No exploitable password recovery mechanisms found"
            )

    def exploit_api_endpoints(self, finding):
        """Exploit discovered API endpoints"""
        print(f"  [*] Testing API endpoints for {finding['url']}")
        
        url = finding['url']
        
        # Test various HTTP methods
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        results = []
        
        for method in methods:
            try:
                if method == 'GET':
                    response = self.safe_get_exploit(url)
                elif method == 'POST':
                    response = self.safe_post_exploit(url, data={'test': 'data', 'action': 'list'})
                else:
                    # For other methods, use POST with X-HTTP-Method-Override
                    response = self.safe_post_exploit(url, data={'test': 'data'}, 
                                                    headers={'X-HTTP-Method-Override': method})
                
                if response and response.status_code not in [401, 403, 404, 405]:
                    results.append({
                        'method': method,
                        'status': response.status_code,
                        'content_sample': response.text[:500] if response.text else '',
                        'headers': dict(response.headers)
                    })
            except Exception as e:
                continue
        
        if results:
            return self.record_exploit_result(
                finding['id'], 'APIEndpoint', True,
                f"API endpoint responds to {len(results)} methods without authentication",
                json.dumps(results, indent=2),
                f"Tested methods: {methods}"
            )
        else:
            return self.record_exploit_result(
                finding['id'], 'APIEndpoint', False,
                "API endpoint requires authentication or returns errors"
            )

    def exploit_client_side_enforcement(self, finding):
        """Bypass client-side enforcement with direct form submission"""
        print(f"  [*] Testing client-side enforcement bypass for {finding['url']}")
        
        page_url = finding['url']
        forms = self.sess.forms.get(page_url, [])
        
        bypass_results = []
        
        for form in forms:
            # Look for forms with client-side validation indicators
            form_html = form.get('raw', '').lower()
            client_side_indicators = [
                'onsubmit', 'onclick', 'javascript:', 'validate', 'checkpassword',
                'required', 'disabled', 'readonly', 'if(!', 'return false'
            ]
            
            if any(indicator in form_html for indicator in client_side_indicators):
                
                # Prepare form submission bypassing client-side checks
                form_data = self._build_form_data(form, generate_test_email())
                
                # Try to bypass disabled/readonly fields by including them
                for inp in form['inputs']:
                    if inp.get('name') and (inp.get('disabled') or inp.get('readonly')):
                        form_data[inp['name']] = 'bypassed_value'
                
                response = self._submit_form(form, form_data)
                
                if response and response.status_code in [200, 302]:
                    # Check if submission was "successful"
                    success_indicators = [
                        'success', 'thank you', 'submitted', 'updated',
                        'created', 'completed'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in success_indicators):
                        bypass_results.append(f"Bypassed client-side validation for form at {form['action']}")
        
        if bypass_results:
            return self.record_exploit_result(
                finding['id'], 'ClientSideBypass', True,
                f"Successfully bypassed client-side validation",
                "\n".join(bypass_results),
                "Direct form submission bypassing JavaScript validation"
            )
        else:
            return self.record_exploit_result(
                finding['id'], 'ClientSideBypass', False,
                "No successful client-side bypasses achieved"
            )

    def exploit_openapi_paths(self):
        """Exploit OpenAPI discovered paths"""
        print(f"  [*] Testing OpenAPI discovered endpoints")
        
        openapi_paths = self.sess.discovery.get("openapi_paths", [])
        results = []
        
        for path in openapi_paths[:10]:  # Limit to first 10 paths
            response = self.safe_get_exploit(path)
            if response and response.status_code == 200:
                # Check if this looks like a functional endpoint
                if len(response.text) > 50:  # Not empty
                    results.append({
                        'path': path,
                        'status': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'size': len(response.text)
                    })
        
        if results:
            return self.record_exploit_result(
                'openapi_discovery', 'OpenAPIEndpoints', True,
                f"Discovered {len(results)} accessible OpenAPI endpoints",
                json.dumps(results, indent=2),
                f"Tested paths from OpenAPI discovery"
            )
        return None

    def _build_form_data(self, form, test_email):
        """Build form data with intelligent field mapping"""
        form_data = {}
        for inp in form['inputs']:
            if inp['name']:
                name_lower = inp['name'].lower()
                if any(field in name_lower for field in ['email', 'username', 'user']):
                    form_data[inp['name']] = test_email
                elif 'password' in name_lower:
                    form_data[inp['name']] = TEST_PASSWORD
                elif any(field in name_lower for field in ['security', 'question', 'answer']):
                    form_data[inp['name']] = 'test'
                elif inp.get('type') == 'hidden':
                    form_data[inp['name']] = inp.get('value', '')
                else:
                    form_data[inp['name']] = inp.get('value', 'test_value')
        return form_data

    def _submit_form(self, form, form_data):
        """Submit form with appropriate method"""
        if form['method'] == 'post':
            return self.safe_post_exploit(form['action'], data=form_data)
        else:
            return self.safe_get_exploit(form['action'], params=form_data)

    def run_exploits(self, findings):
        """Run appropriate exploits for each finding"""
        print("\n" + "="*60)
        print("STARTING EXPLOITATION PHASE")
        print("="*60)
        
        exploit_mapping = {
            'insecure_id_enumeration': self.exploit_insecure_id_enumeration,
            'token_in_url': self.exploit_token_in_url,
            'weak_password_recovery': self.exploit_weak_password_recovery,
            'public_api_endpoint': self.exploit_api_endpoints,
            'api_path_accessible': self.exploit_api_endpoints,
            'client_side_workflow_enforcement': self.exploit_client_side_enforcement,
            'weak_secret_questions': self.exploit_weak_password_recovery,
            'reset_token_in_get': self.exploit_token_in_url,
            'user_controlled_key_in_form': self.exploit_insecure_id_enumeration,
        }
        
        # First, exploit OpenAPI discovered paths if any
        if self.sess.discovery.get("openapi_paths"):
            openapi_result = self.exploit_openapi_paths()
            if openapi_result:
                self.results.append(openapi_result)
        
        # Exploit individual findings
        for finding in findings:
            finding_type = finding.get('type', '')
            exploit_func = exploit_mapping.get(finding_type)
            
            if exploit_func and finding.get('severity') in ['High', 'Medium']:
                print(f"\n[*] Exploiting {finding_type} at {finding['url']}")
                try:
                    result = exploit_func(finding)
                    status = "SUCCESS" if result['success'] else "FAILED"
                    print(f"  [+] Exploit result: {status} - {result['details']}")
                except Exception as e:
                    print(f"  [!] Exploit failed with error: {e}")
                    self.record_exploit_result(
                        finding['id'], finding_type, False,
                        f"Exploit failed with exception: {str(e)}"
                    )
        
        return self.results

# ---------- Findings helper ----------
def record_finding(sess: ScannerSession, f):
    """
    Ensure every finding has consistent fields:
    - id, url, type, title, severity, confidence, evidence, snippet, parameter, form_id, http_status, headers, remediation, safe_poc
    """
    fid = f.get("id") or str(uuid.uuid4())
    f_out = {
        "id": fid,
        "url": f.get("url"),
        "type": f.get("type"),
        "title": f.get("title") or f.get("type"),
        "severity": f.get("severity"),
        "confidence": f.get("confidence"),
        "http_status": f.get("http_status"),
        "headers": f.get("headers"),
        "parameter": f.get("parameter"),
        "form_id": f.get("form_id"),
        "snippet": short(f.get("snippet",""), 400),
        "evidence": short(f.get("evidence",""), 800),
        "remediation": f.get("remediation"),
        "safe_poc": f.get("safe_poc"),
    }
    # fallback severity/conf
    if not f_out["severity"] or not f_out["confidence"]:
        sev, conf = severity_confidence_from_type(str(f_out["type"] or ""))
        f_out["severity"] = f_out["severity"] or sev
        f_out["confidence"] = f_out["confidence"] or conf
    sess.findings.append(f_out)

# ---------- New discovery helpers ----------
def discover_robots_and_sitemaps(sess: ScannerSession):
    robots_url = urljoin(sess.base_url, "/robots.txt")
    r = sess.safe_get(robots_url)
    sess.discovery["robots"] = None
    if r and r.status_code == 200:
        sess.discovery["robots"] = r.text
        # parse for Sitemap entries
        sitemaps = re.findall(r"(?im)^sitemap:\s*(.+)$", r.text)
        for sm in sitemaps:
            smu = sm.strip()
            sess.discovery["sitemaps"].append(smu)
    # if no sitemaps, try common locations
    if not sess.discovery["sitemaps"]:
        common = ["/sitemap.xml", "/sitemap_index.xml"]
        for p in common:
            smu = urljoin(sess.base_url, p)
            r2 = sess.safe_get(smu)
            if r2 and r2.status_code == 200 and (r2.headers.get("content-type","").startswith("application/xml") or "<urlset" in r2.text or "<sitemapindex" in r2.text):
                sess.discovery["sitemaps"].append(smu)

def fetch_and_parse_sitemaps(sess: ScannerSession):
    for sm in sess.discovery.get("sitemaps", []):
        r = sess.safe_get(sm)
        if not r:
            continue
        # parse XML for <loc> tags
        try:
            root = ET.fromstring(r.content)
            for elem in root.iter():
                if elem.tag.lower().endswith("loc"):
                    url_text = elem.text.strip() if elem.text else None
                    if url_text and url_text not in sess.pages:
                        # only add same-origin
                        if urlparse(url_text).netloc == sess.parsed_base.netloc:
                            # do a conservative HEAD and maybe GET later
                            h = sess.safe_head(url_text)
                            if h and url_text not in sess.pages:
                                g = sess.safe_get(url_text)
                                if g:
                                    sess.pages[url_text] = (g.status_code, g.text)
        except Exception:
            continue

def discover_openapi(sess: ScannerSession):
    # Common locations
    candidates = ["/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/v3/api-docs", "/api-docs"]
    for c in candidates:
        u = urljoin(sess.base_url, c)
        r = sess.safe_get(u)
        if r and r.status_code == 200 and (r.headers.get("content-type","").startswith("application/json") or '"openapi"' in (r.text or "").lower() or '"swagger"' in (r.text or "").lower()):
            sess.discovery["openapi"] = u
            # attempt to extract paths
            try:
                j = r.json()
                paths = j.get("paths", {})
                if isinstance(paths, dict):
                    for p in paths.keys():
                        # build a concrete URL if possible (use base path)
                        candidate = urljoin(sess.base_url, p.lstrip("/"))
                        if urlparse(candidate).netloc == sess.parsed_base.netloc:
                            sess.discovery["openapi_paths"].append(candidate)
            except Exception:
                # attempt naive parse for path strings
                for m in re.finditer(r'\"/[^"]+\"', r.text):
                    p = m.group(0).strip('"')
                    if p.startswith("/"):
                        cand = urljoin(sess.base_url, p.lstrip("/"))
                        if urlparse(cand).netloc == sess.parsed_base.netloc:
                            sess.discovery["openapi_paths"].append(cand)
            break

# ---------- Checks (existing but extended) ----------
# [All check functions remain exactly the same - keeping them for brevity]
def check_unverified_ownership(sess: ScannerSession):
    keywords = ["claim", "become-owner", "register-organization", "transfer-ownership", "verify-ownership", "claim ownership"]
    for url, (status, text) in list(sess.pages.items()):
        if not text:
            continue
        lower = text.lower()
        for k in keywords:
            if k in lower:
                m = re.search(re.escape(k), lower)
                snippet = snippet_of(text, m) if m else short(text, 200)
                record_finding(sess, {
                    "url": url,
                    "type": "unverified_ownership_keyword",
                    "title": "Ownership claim wording found",
                    "severity": "High",
                    "confidence": "Medium",
                    "http_status": status,
                    "snippet": snippet,
                    "evidence": f"Found keyword '{k}' on page.",
                    "remediation": "Require out-of-band verification (DNS TXT, file-based token, domain-validated email). Add admin approval workflow and audit logging.",
                    "safe_poc": f"Manually review the page at {url}; check if the 'claim' action leads to a form that accepts only a name/email. Do NOT perform ownership claim automatically."
                })
    # forms with owner-like inputs
    for page, fs in sess.forms.items():
        for f in fs:
            for inp in f["inputs"]:
                if inp["name"] and re.search(r"(owner|ownership|claim|org_id|transfer)", str(inp["name"]), re.I):
                    snippet = short(f.get("raw",""), 500)
                    record_finding(sess, {
                        "url": page,
                        "type": "unverified_ownership_form",
                        "title": "Form contains ownership-related parameter",
                        "severity": "High",
                        "confidence": "High",
                        "form_id": f.get("id"),
                        "parameter": inp.get("name"),
                        "snippet": snippet,
                        "evidence": f"Form action {f['action']} contains ownership-related input {inp['name']}.",
                        "remediation": "Require multi-step verification for ownership changes and limit to authorized roles; log everything.",
                        "safe_poc": f"Inspect the form at {page} (view-source or use devtools). Check if ownership changes require an email/domain verification step."
                    })

def check_authentication_bypass_alternate_channel(sess: ScannerSession):
    for url in list(sess.pages.keys()):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if any(k.lower().startswith("token") or k.lower().endswith("_token") for k in qs.keys()):
            record_finding(sess, {
                "url": url,
                "type": "token_in_url",
                "title": "Authentication token found in URL/query string",
                "severity": "High",
                "confidence": "High",
                "http_status": sess.pages.get(url, (None, ""))[0],
                "headers": None,
                "parameter": ", ".join(qs.keys()),
                "snippet": short(parsed.query, 300),
                "evidence": f"Query parameters include token-like keys: {list(qs.keys())}",
                "remediation": "Do not accept authentication or authorization tokens via GET parameters; use Authorization headers or secure, short-lived cookies.",
                "safe_poc": f"Manually try removing the token query parameter from the URL and observe whether the resource still returns 200. Do not brute-force tokens."
            })
        # API-like pages or paths discovered via OpenAPI
    # also scan OpenAPI-discovered API paths (HEAD-only)
    for api in sess.discovery.get("openapi_paths", []):
        h = sess.safe_head(api)
        if h and h.status_code == 200:
            # get sample body snippet
            g = sess.safe_get(api)
            snippet = short(g.text if g else "", 300)
            record_finding(sess, {
                "url": api,
                "type": "api_path_accessible",
                "title": "OpenAPI-discovered API path accessible",
                "severity": "Medium",
                "confidence": "Medium",
                "http_status": h.status_code,
                "headers": dict(h.headers) if h else None,
                "snippet": snippet,
                "evidence": "OpenAPI path responded; review auth requirements.",
                "remediation": "Audit API endpoints and require appropriate auth/roles for sensitive actions.",
                "safe_poc": "Use an API client with test credentials to verify required authorization for endpoints."
            })

def check_authorization_bypass_user_controlled_key(sess: ScannerSession):
    id_like = re.compile(r"/(user|account|invoice|order)s?/?(\d{3,9})(/|$)", re.I)
    for url in list(sess.pages.keys()):
        m = id_like.search(url)
        if m:
            original_id = m.group(2)
            try:
                alt_id = str(int(original_id) + 1)
            except Exception:
                alt_id = None
            if alt_id:
                alt_url = url.replace(original_id, alt_id)
                h = sess.safe_head(alt_url)
                hstatus = h.status_code if h else None
                if hstatus == 200:
                    record_finding(sess, {
                        "url": url,
                        "type": "insecure_id_enumeration",
                        "title": "Predictable numeric ID may allow enumeration",
                        "severity": "High",
                        "confidence": "Medium",
                        "http_status": hstatus,
                        "parameter": original_id,
                        "snippet": f"Original: {short(url,200)} | Probe: {short(alt_url,200)} returned {hstatus}",
                        "evidence": f"HEAD probe to {alt_url} returned {hstatus}, suggesting predictable IDs.",
                        "remediation": "Use unguessable identifiers (UUIDs) or enforce server-side access checks for every resource.",
                        "safe_poc": f"Manually verify the behavior for adjacent IDs with a browser or curl --head. Do not enumerate at scale."
                    })
    for page, forms in sess.forms.items():
        for f in forms:
            for inp in f["inputs"]:
                if inp["name"] and re.search(r"(user_id|account_id|invoice_id|order_id)", str(inp["name"]), re.I):
                    record_finding(sess, {
                        "url": page,
                        "type": "user_controlled_key_in_form",
                        "title": "Form accepts client-controlled resource identifier",
                        "severity": "High",
                        "confidence": "Medium",
                        "form_id": f.get("id"),
                        "parameter": inp.get("name"),
                        "snippet": short(f.get("raw",""),400),
                        "evidence": f"Form contains parameter {inp['name']}.",
                        "remediation": "Validate server-side that the caller is allowed to reference the provided resource ID.",
                        "safe_poc": f"Inspect the form and try submitting with a test account only for resources you own."
                    })

def check_weak_password_recovery(sess: ScannerSession):
    for page, forms in sess.forms.items():
        for f in forms:
            action = f["action"]
            if re.search(r"forgot|reset.*password|password_reset|recover", action, re.I) or re.search(r"forgot|reset password", f.get("raw",""), re.I):
                inputs = [i["name"] for i in f["inputs"] if i.get("name")]
                if any(re.search(r"(security_question|mother_maiden|birthplace|pet_name)", name, re.I) for name in inputs):
                    record_finding(sess, {
                        "url": page,
                        "type": "weak_secret_questions",
                        "title": "Password recovery uses static knowledge-based questions",
                        "severity": "High",
                        "confidence": "Medium",
                        "form_id": f.get("id"),
                        "parameter": ", ".join(inputs),
                        "snippet": short(f.get("raw",""),400),
                        "evidence": f"Password recovery form requests static secret questions: {inputs}",
                        "remediation": "Avoid KBAs; prefer short single-use tokens via email/SMS and MFA.",
                        "safe_poc": f"Manually exercise the forgot-password flow for a test account and observe required verification steps."
                    })
                if urlparse(action).query:
                    record_finding(sess, {
                        "url": page,
                        "type": "reset_token_in_get",
                        "title": "Password reset token appears in GET/URL",
                        "severity": "High",
                        "confidence": "High",
                        "form_id": f.get("id"),
                        "parameter": short(urlparse(action).query,400),
                        "snippet": short(f.get("raw",""),400),
                        "evidence": f"Password reset form action includes query params: {action}",
                        "remediation": "Do not send sensitive tokens in URLs; use POST and ephemeral single-use tokens.",
                        "safe_poc": "Review email or flow manually where the reset link is produced; check whether token is in the URL."
                    })
    for url, (status, text) in sess.pages.items():
        if re.search(r"reset token:|temporary password|new password:|password reset code", text, re.I):
            m = re.search(r"(reset token:|temporary password|new password:|password reset code).{0,60}", text, re.I)
            record_finding(sess, {
                "url": url,
                "type": "potential_token_exposure",
                "title": "Potential password reset token or temporary password exposed in page content",
                "severity": "High",
                "confidence": "High",
                "http_status": status,
                "snippet": snippet_of(text, m) if m else short(text,300),
                "evidence": "Page text contains password reset artifacts.",
                "remediation": "Remove any printing of tokens/passwords to pages; keep tokens in server logs and deliver via secure channels.",
                "safe_poc": "Open the page manually and search for 'reset token' or 'temporary password' occurrences."
            })

def check_incorrect_ownership_assignment(sess: ScannerSession):
    for page, fs in sess.forms.items():
        for f in fs:
            if re.search(r"owner|assign|transfer", f["raw"], re.I) or re.search(r"owner", " ".join(i.get("name","") or "" for i in f["inputs"]), re.I):
                record_finding(sess, {
                    "url": page,
                    "type": "ownership_assignment_form",
                    "title": "Form that may allow ownership change",
                    "severity": "High",
                    "confidence": "Medium",
                    "form_id": f.get("id"),
                    "parameter": ", ".join([i.get("name") or "<unnamed>" for i in f["inputs"]]),
                    "snippet": short(f.get("raw",""),400),
                    "evidence": f"Form may allow ownership change: action {f['action']} inputs {[i['name'] for i in f['inputs']]}",
                    "remediation": "Ownership changes must require multi-factor verification and admin approval with audit trail.",
                    "safe_poc": "Manually review the flow for ownership changes and verify verification steps required."
                })
    for url, (_, text) in sess.pages.items():
        if re.search(r"\b(transfer ownership|claim ownership|assign owner)\b", text, re.I):
            m = re.search(r"\b(transfer ownership|claim ownership|assign owner)\b", text, re.I)
            record_finding(sess, {
                "url": url,
                "type": "ownership_mention",
                "title": "Ownership transfer wording on page",
                "severity": "Medium",
                "confidence": "Low",
                "http_status": sess.pages.get(url, (None, ""))[0],
                "snippet": snippet_of(text, m),
                "evidence": "Page mentions ownership transfer/claim.",
                "remediation": "Treat ownership flows as high-risk and require verification and logging.",
                "safe_poc": f"Inspect the page at {url} and check whether any actions allow ownership transfer without verification."
            })

def check_allocation_without_limits(sess: ScannerSession):
    for url, (status, text) in sess.pages.items():
        if re.search(r"/(create|new|upload|provision|allocate)", url, re.I) or re.search(r"\b(create|upload|provision)\b", text, re.I):
            r = sess.safe_get(url)
            rate_headers = []
            if r:
                for h in ("x-ratelimit-limit", "x-rate-limit", "x-ratelimit-remaining", "retry-after"):
                    if h in r.headers:
                        rate_headers.append({h: r.headers.get(h)})
            if not rate_headers:
                snippet = short(text,400)
                record_finding(sess, {
                    "url": url,
                    "type": "resource_allocation_no_rate_limit",
                    "title": "Create/upload-like endpoint with no rate-limit headers observed",
                    "severity": "Medium",
                    "confidence": "Low",
                    "http_status": r.status_code if r else status,
                    "headers": None,
                    "snippet": snippet,
                    "evidence": "Create-like endpoint found with no obvious rate-limit headers.",
                    "remediation": "Implement per-account quotas, rate-limiting headers, and throttles server-side; consider CAPTCHAs for unauthenticated flows.",
                    "safe_poc": "Attempt a manual small-scale create (one or two attempts) with a test account and observe server response headers and rate-limiting behavior."
                })
            else:
                # if headers exist, record as information
                record_finding(sess, {
                    "url": url,
                    "type": "resource_allocation_rate_headers",
                    "title": "Rate-limit headers present",
                    "severity": "Info",
                    "confidence": "High",
                    "http_status": r.status_code if r else status,
                    "headers": rate_headers,
                    "snippet": short(str(rate_headers),400),
                    "evidence": "Rate-limit headers detected.",
                    "remediation": "Verify server honors headers and enforces quotas.",
                    "safe_poc": "Review the headers and perform a manual test to confirm throttling behavior."
                })

def check_premature_release_of_resource(sess: ScannerSession):
    for url, (status, text) in sess.pages.items():
        if re.search(r"(pending|processing).{0,40}(available|download|access)", text, re.I):
            m = re.search(r"(pending|processing).{0,40}(available|download|access)", text, re.I)
            record_finding(sess, {
                "url": url,
                "type": "premature_release_text",
                "title": "Resource may be shown as available while pending/processing",
                "severity": "High",
                "confidence": "Medium",
                "http_status": status,
                "snippet": snippet_of(text, m),
                "evidence": "Page mentions resource is available/accessible while status is pending or processing.",
                "remediation": "Enforce finalization server-side before allowing downloads/access.",
                "safe_poc": "Manually attempt an authorized download only for test resources and verify access allowed only after completion."
            })
        soup = BeautifulSoup(text, "html.parser")
        links = soup.find_all("a", href=True)
        for a in links:
            href = a.get("href")
            if re.search(r"/downloads/|/files/|\.zip$|\.pdf$|/attachment/", href, re.I):
                context = a.parent.get_text(" ", strip=True) if a.parent else ""
                if re.search(r"(processing|pending|awaiting)", context, re.I):
                    record_finding(sess, {
                        "url": url,
                        "type": "direct_file_link_during_pending",
                        "title": "Direct file link appears in 'pending' context",
                        "severity": "High",
                        "confidence": "Medium",
                        "http_status": status,
                        "parameter": href,
                        "snippet": short(context,300),
                        "evidence": f"File link {href} appears in context mentioning 'pending' or 'processing'.",
                        "remediation": "Block direct object access until transaction finalization; verify server-side ownership and state.",
                        "safe_poc": "Inspect the link target manually (HEAD) to check whether it is accessible even when marked pending."
                    })

def check_single_unique_action_enforcement(sess: ScannerSession):
    token_pattern = re.compile(r"(?:token|code|invite)[=:\s]*[A-Za-z0-9_\-]{6,}", re.I)
    for url, (status, text) in sess.pages.items():
        m = token_pattern.search(text)
        if m:
            record_finding(sess, {
                "url": url,
                "type": "potential_token_exposure",
                "title": "Token-like string present on page",
                "severity": "High",
                "confidence": "Medium",
                "http_status": status,
                "snippet": snippet_of(text, m),
                "evidence": "Found token-like string that may be single-use token embedded in content.",
                "remediation": "Ensure tokens are single-use and not embedded in pages; clear them from UI/logs.",
                "safe_poc": "Open the page and search for the string; do not attempt to reuse tokens programmatically."
            })
        if re.search(r"\b(single[- ]use|one[- ]time|does not expire)\b", text, re.I):
            m2 = re.search(r"\b(single[- ]use|one[- ]time|does not expire)\b", text, re.I)
            record_finding(sess, {
                "url": url,
                "type": "single_use_policy_issue",
                "title": "Ambiguous single-use policy language",
                "severity": "Medium",
                "confidence": "Low",
                "http_status": status,
                "snippet": snippet_of(text, m2),
                "evidence": "Page mentions single-use or expiration policy in an ambiguous way.",
                "remediation": "Clarify policy and enforce server-side single-use checks.",
                "safe_poc": "Review policy wording and verify server behavior with a manual test account."
            })

def check_enforcement_of_behavioral_workflow(sess: ScannerSession):
    for url, (status, text) in sess.pages.items():
        if re.search(r"if\s*\(!.*approved|document\.getElementById\(.+disabled|return false;.*submit", text, re.I):
            record_finding(sess, {
                "url": url,
                "type": "client_side_workflow_enforcement",
                "title": "Workflow enforcement appears client-side",
                "severity": "Medium",
                "confidence": "Medium",
                "http_status": status,
                "snippet": short(text,400),
                "evidence": "JS patterns indicate workflow enforcement may be client-side only.",
                "remediation": "Enforce workflow constraints on server-side and validate state transitions.",
                "safe_poc": "Open devtools and check whether disabling client-side JS still allows actions (do not perform destructive actions)."
            })
        # forms missing CSRF or workflow state
        soup = BeautifulSoup(text, "html.parser")
        for f in soup.find_all("form"):
            hidden_inputs = [i.get("name") for i in f.find_all("input", type="hidden") if i.get("name")]
            has_csrf = any(re.search(r"csrf|token", name or "", re.I) for name in hidden_inputs)
            if not has_csrf:
                record_finding(sess, {
                    "url": url,
                    "type": "form_missing_workflow_state_or_csrf",
                    "title": "Form missing CSRF token or workflow state hidden field",
                    "severity": "Medium",
                    "confidence": "Medium",
                    "http_status": status,
                    "form_id": f.get("id") or f.get("name"),
                    "snippet": short(str(f)[:800],400),
                    "evidence": f"Form lacks visible CSRF token or workflow state hidden input: hidden inputs {hidden_inputs}",
                    "remediation": "Add server-validated CSRF tokens and explicit workflow state parameters validated server-side.",
                    "safe_poc": "Inspect form markup; try submitting a benign request if you control a test account to observe server-side validation."
                })

# ---------- Additional helpers: login detection and optional authenticated crawl ----------
def detect_login_pages(sess: ScannerSession):
    login_forms = []
    for page, forms in sess.forms.items():
        for f in forms:
            for inp in f["inputs"]:
                if inp.get("type") and inp["type"].lower() == "password":
                    login_forms.append({"page": page, "form": f})
                    break
    return login_forms

def prompt_for_auth_headers():
    print("\nLogin form(s) detected. You may optionally provide an Authorization header or Cookie value")
    print("to perform a **second-pass authenticated crawl**. This is *opt-in* and will only add the header")
    print("you supply to subsequent GET/HEAD requests during the auth-pass. DO NOT paste sensitive creds if unsure.")
    v = input("Paste header as `Authorization: Bearer <token>` or `Cookie: name=value; ...` (leave blank to skip) >>> ").strip()
    if not v:
        return None
    # naive parse
    if ":" in v:
        k, val = v.split(":",1)
        return {k.strip(): val.strip()}
    else:
        # assume cookie
        return {"Cookie": v.strip()}

def authenticated_crawl(sess: ScannerSession, headers):
    # apply headers to session temporarily and re-crawl discovered pages conservatively (HEAD + single GET pass for new pages)
    print("Starting authenticated conservative pass (HEAD + sparse GET) using supplied header...")
    saved = dict(sess.session.headers)
    sess.session.headers.update(headers)
    sess.authenticated = True
    # HEAD all known pages then GET only ones with 200
    for url in list(sess.pages.keys()):
        h = sess.safe_head(url)
        if h and h.status_code == 200:
            g = sess.safe_get(url)
            if g:
                sess.pages[url] = (g.status_code, g.text)
                # re-parse forms if changed
                soup = BeautifulSoup(g.text, "html.parser")
                sess.forms[url] = []
                for form in soup.find_all("form"):
                    sess.forms[url].append(parse_form(form, url))
    sess.session.headers = saved
    print("Authenticated pass complete.\n")

def ask_exploitation():
    """Ask user if they want to run exploitation phase"""
    print("\n" + "="*60)
    response = input("Do you want to attempt automated exploitation? (y/N) >>> ").strip().lower()
    return response in ['y', 'yes']

# ---------- Nuclei template exporter ----------
NUCLEI_TEMPLATE_MAP = {
    "token_in_url": {
        "id_suffix": "token-in-url",
        "severity": "high",
        "matchers": ["type: word", "words: token", "words: _token"]
    },
    "reset_token_in_get": {
        "id_suffix": "reset-token-in-get",
        "severity": "high",
        "matchers": ["type: word", "words: reset token"]
    },
    "insecure_id_enumeration": {
        "id_suffix": "id-enum",
        "severity": "high",
        "matchers": ["type: regex", "regex: '/[0-9]{3,9}'"]
    },
    "form_missing_workflow_state_or_csrf": {
        "id_suffix": "no-csrf",
        "severity": "medium",
        "matchers": ["type: word", "words: csrf"]
    }
}

def export_nuclei_templates(sess: ScannerSession, out_file=NUCLEI_FILE):
    # create simple templates for discovered types
    templates = []
    for f in sess.findings:
        t = f.get("type")
        if t in NUCLEI_TEMPLATE_MAP:
            mapping = NUCLEI_TEMPLATE_MAP[t]
            tmpl = {
                "id": f"bizlogic-{mapping['id_suffix']}-{f['id'][:8]}",
                "info": {"name": f"{mapping['id_suffix']} - {f.get('title')}", "author": "BizLogicScanner"},
                "requests": [{
                    "method": "GET",
                    "path": [f.get("url") or sess.base_url],
                    "matchers-condition": "and",
                    "matchers": [{"type": "word", "words": [w for w in mapping.get("matchers", [])]}]
                }]
            }
            templates.append(tmpl)
    # write a minimal YAML-ish output (nuclei uses YAML; here we create a JSON-to-YAML light)
    try:
        with open(out_file, "w", encoding="utf-8") as fh:
            fh.write("# Auto-generated minimal nuclei-like templates (manual tune recommended)\n")
            for t in templates:
                fh.write(json.dumps(t) + "\n")
        return out_file
    except Exception:
        return None

# ---------- Runner / Interactive UI & Reporting ----------

CHECKS = [
    ("Unverified ownership", check_unverified_ownership),
    ("Authentication bypass via alternate path/channel", check_authentication_bypass_alternate_channel),
    ("Authorization bypass via user-controlled key", check_authorization_bypass_user_controlled_key),
    ("Weak password recovery", check_weak_password_recovery),
    ("Incorrect ownership assignment", check_incorrect_ownership_assignment),
    ("Allocation without limits/throttling", check_allocation_without_limits),
    ("Premature release of resource", check_premature_release_of_resource),
    ("Improper enforcement of single unique action", check_single_unique_action_enforcement),
    ("Improper enforcement of behavioral workflow", check_enforcement_of_behavioral_workflow),
]

def print_banner():
    print("="*72)
    print("BizLogic ✩₊˚.⋆☾⋆⁺₊✧ Scanner + Exploitation")
    print("="*72)
    print("✩₊˚.⋆☾⋆⁺₊✧by:ek0ms savi0r✩₊˚.⋆☾⋆⁺₊✧")
    print()

def interactive_config():
    base = input("Target base URL (e.g. https://example.com) >>> ").strip()
    if not base:
        print("No target provided. Exiting.")
        sys.exit(1)
    if not base.startswith("http"):
        base = "https://" + base
    try:
        rate = float(input(f"Request rate limit seconds [{RATE_LIMIT_SECONDS}] >>> ") or RATE_LIMIT_SECONDS)
    except Exception:
        rate = RATE_LIMIT_SECONDS
    try:
        pages = int(input(f"Max crawl pages [{CRAWL_MAX_PAGES}] >>> ") or CRAWL_MAX_PAGES)
    except Exception:
        pages = CRAWL_MAX_PAGES
    return base, rate, pages

def summarize_and_report(sess: ScannerSession):
    # Generate human-readable summary
    lines = []
    header = f"BizLogic Scanner Report for {sess.base_url}\nStarted: {sess.start_time.isoformat()}\nCollected pages: {len(sess.pages)}\nAuthenticated pass: {sess.authenticated}\n"
    lines.append(header)
    lines.append("="*80)
    if sess.discovery.get("robots"):
        lines.append("robots.txt found. Sitemaps discovered: " + ", ".join(sess.discovery.get("sitemaps", []) or ["(none)"]))
    if sess.discovery.get("openapi"):
        lines.append(f"OpenAPI/Swagger discovered at: {sess.discovery.get('openapi')}, discovered API paths: {len(sess.discovery.get('openapi_paths',[]))}")
    lines.append("="*80)
    if not sess.findings:
        lines.append("No heuristic findings detected. That does not guarantee security.\n")
    else:
        # sort findings by severity mapping High -> first
        severity_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        sorted_findings = sorted(sess.findings, key=lambda x: severity_order.get(x.get("severity","Medium"), 1))
        counts = {}
        for f in sorted_findings:
            counts[f.get("severity")] = counts.get(f.get("severity"), 0) + 1
        lines.append("Summary counts by severity: " + ", ".join([f"{k}: {v}" for k,v in counts.items()]))
        lines.append("-"*80)
        for i, f in enumerate(sorted_findings, 1):
            lines.append(f"{i}. [{f.get('severity')}] {f.get('title')} ({f.get('type')})")
            lines.append(f"   URL: {f.get('url')}")
            if f.get("form_id"):
                lines.append(f"   Form: {f.get('form_id')}")
            if f.get("parameter"):
                lines.append(f"   Parameter / field: {f.get('parameter')}")
            if f.get("http_status"):
                lines.append(f"   HTTP status: {f.get('http_status')}")
            if f.get("headers"):
                lines.append(f"   Notable headers: {short(json.dumps(f.get('headers')),200)}")
            lines.append(f"   Confidence: {f.get('confidence')}")
            lines.append(f"   Evidence snippet: {f.get('snippet')}")
            lines.append(f"   Evidence summary: {f.get('evidence')}")
            lines.append(f"   Remediation: {f.get('remediation')}")
            lines.append(f"   Safe manual PoC / validation step: {f.get('safe_poc')}")
            lines.append("-"*80)
    
    # Add exploitation results if any
    if sess.exploitation_results:
        lines.append("\n" + "="*80)
        lines.append("EXPLOITATION RESULTS")
        lines.append("="*80)
        successful_exploits = [r for r in sess.exploitation_results if r.get('success')]
        failed_exploits = [r for r in sess.exploitation_results if not r.get('success')]
        
        lines.append(f"Successful Exploits: {len(successful_exploits)}")
        lines.append(f"Failed Exploits: {len(failed_exploits)}")
        lines.append("")
        
        for i, result in enumerate(successful_exploits, 1):
            lines.append(f"{i}. [SUCCESS] {result.get('exploit_type')}")
            lines.append(f"   Finding ID: {result.get('finding_id')}")
            lines.append(f"   Details: {result.get('details')}")
            if result.get('evidence'):
                lines.append(f"   Evidence: {result.get('evidence')}")
            if result.get('payload_used'):
                lines.append(f"   Payload: {result.get('payload_used')}")
            lines.append("")
    
    footer = f"\nScan finished at {datetime.now(timezone.utc).isoformat()}\n"
    lines.append(footer)
    report_text = "\n".join(lines)
    print(report_text)
    
    # Write reports to files
    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        print(f"[+] Saved report to: {REPORT_FILE}")
    except Exception as e:
        print(f"[-] Error saving text report: {e}")
    
    # JSON output
    try:
        with open(REPORT_JSON, "w", encoding="utf-8") as fh:
            json.dump({"target": sess.base_url, "started": sess.start_time.isoformat(),
                       "pages_collected": len(sess.pages), "authenticated": sess.authenticated,
                       "discovery": sess.discovery, "findings": sess.findings,
                       "exploitation_results": sess.exploitation_results}, fh, indent=2)
        print(f"[+] Saved JSON report to: {REPORT_JSON}")
    except Exception as e:
        print(f"[-] Error saving JSON report: {e}")
    
    # HTML output (simple)
    try:
        with open(REPORT_HTML, "w", encoding="utf-8") as fh:
            fh.write("<html><head><meta charset='utf-8'><title>BizLogic Scanner Report</title></head><body>")
            fh.write(f"<h2>BizLogic Scanner Report for {html.escape(sess.base_url)}</h2>")
            fh.write(f"<p>Started: {sess.start_time.isoformat()} — Authenticated pass: {sess.authenticated}</p>")
            if sess.discovery.get("openapi"):
                fh.write(f"<p>OpenAPI discovered at: {html.escape(sess.discovery.get('openapi'))} — {len(sess.discovery.get('openapi_paths',[]))} paths</p>")
            fh.write("<h3>Findings</h3><ol>")
            for f in sorted_findings:
                fh.write(f"<li><b>{html.escape(f.get('title'))}</b> — <i>{html.escape(f.get('severity') or '')}</i><br>")
                fh.write(f"URL: <a href=\"{html.escape(f.get('url') or '')}\">{html.escape(f.get('url') or '')}</a><br>")
                if f.get("parameter"):
                    fh.write(f"Parameter: {html.escape(str(f.get('parameter')))}<br>")
                fh.write(f"Confidence: {html.escape(f.get('confidence') or '')}<br>")
                fh.write(f"<pre style='white-space:pre-wrap'>{html.escape(f.get('snippet') or '')}</pre>")
                fh.write(f"<p>Remediation: {html.escape(f.get('remediation') or '')}</p>")
                fh.write("</li>")
            
            # Add exploitation results to HTML
            if sess.exploitation_results:
                fh.write("</ol><h3>Exploitation Results</h3><ul>")
                for result in sess.exploitation_results:
                    status = "SUCCESS" if result.get('success') else "FAILED"
                    color = "green" if result.get('success') else "red"
                    fh.write(f"<li style='color: {color}'><b>{status}</b>: {html.escape(result.get('exploit_type'))} - {html.escape(result.get('details'))}</li>")
                fh.write("</ul>")
            
            fh.write("</body></html>")
        print(f"[+] Saved HTML report to: {REPORT_HTML}")
    except Exception as e:
        print(f"[-] Error saving HTML report: {e}")

    # Nuclei export
    nucfile = export_nuclei_templates(sess)
    if nucfile:
        print(f"[+] Nuclei-like templates exported to: {nucfile} (manual tuning recommended).")
    else:
        print("[-] No nuclei templates exported.")

def run_scanner():
    print_banner()
    base, rate, pages = interactive_config()
    
    # Setup report files and directories
    scan_dir = setup_report_files(base)
    print(f"[+] Scan results will be saved to: ./{scan_dir}/")
    
    print("\nInitializing session and crawling (conservative)...\n")
    sess = ScannerSession(base, rate_limit=rate)
    # basic discovery before crawl
    discover_robots_and_sitemaps(sess)
    discover_openapi(sess)
    # initial crawl
    sess.crawl("/", max_pages=pages)
    # parse sitemaps to augment discovery
    if sess.discovery.get("sitemaps"):
        fetch_and_parse_sitemaps(sess)
    print(f"Crawl complete: {len(sess.pages)} pages gathered.\n")
    # detect login forms and optionally prompt for auth header
    logins = detect_login_pages(sess)
    if logins:
        print(f"Detected {len(logins)} page(s) with password inputs (possible login forms). Examples:")
        for L in logins[:3]:
            print(" -", L["page"])
        headers = prompt_for_auth_headers()
        if headers:
            authenticated_crawl(sess, headers)

    # Run checks in order and append findings
    for name, check_fn in CHECKS:
        print(f"Running check: {name} ...")
        try:
            check_fn(sess)  # checks call record_finding directly
            print(f"  -> Findings so far: {len(sess.findings)}")
        except Exception as e:
            print(f"  -> Check failed with exception: {e}")
    
    # Ask about exploitation
    if sess.findings and ask_exploitation():
        exploit_engine = ExploitationEngine(sess)
        sess.exploitation_results = exploit_engine.run_exploits(sess.findings)
    
    # Summarize & report
    summarize_and_report(sess)

if __name__ == "__main__":
    try:
        run_scanner()
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        sys.exit(0)

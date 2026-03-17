"""
Website Health Monitor Agent — vollständige Version
Prüft Performance, Security, SEO, Crawlability und Content-Qualität.
Schickt einen priorisierten Report via Slack.
"""

import os, time, json, ssl, socket, hashlib, re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
import anthropic

# ─── Konfiguration ────────────────────────────────────────────────────────────

TARGET_URL           = os.environ.get("TARGET_URL", "https://example.com")
SLACK_WEBHOOK_URL    = os.environ.get("SLACK_WEBHOOK_URL", "")
ANTHROPIC_API_KEY    = os.environ.get("ANTHROPIC_API_KEY", "")
PAGESPEED_API_KEY    = os.environ.get("PAGESPEED_API_KEY", "")  # Optional, kostenlos unter console.cloud.google.com

MAX_PAGES            = 60
SLOW_PAGE_MS         = 3000
REQUEST_TIMEOUT      = 15
CRAWL_DELAY          = 0.5
SSL_WARN_DAYS        = 30    # SSL-Warnung wenn Zertifikat in <30 Tagen abläuft


# ─── 1. SSL-Check ─────────────────────────────────────────────────────────────

def check_ssl(hostname: str) -> dict:
    result = {"valid": False, "days_remaining": None, "expiry_date": None, "issuer": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10), server_hostname=hostname) as conn:
            cert = conn.getpeercert()
            expiry_str = cert["notAfter"]
            expiry_dt  = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left  = (expiry_dt - datetime.now(timezone.utc)).days
            issuer     = dict(x[0] for x in cert.get("issuer", []))
            result.update({
                "valid": True,
                "days_remaining": days_left,
                "expiry_date": expiry_dt.strftime("%Y-%m-%d"),
                "issuer": issuer.get("organizationName", "Unknown"),
            })
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── 2. Security-Headers-Check ────────────────────────────────────────────────

def check_security_headers(url: str, session: requests.Session) -> dict:
    REQUIRED_HEADERS = {
        "Strict-Transport-Security":  "HSTS – erzwingt HTTPS",
        "X-Frame-Options":            "Clickjacking-Schutz",
        "X-Content-Type-Options":     "MIME-Sniffing verhindert",
        "Content-Security-Policy":    "XSS / Injection-Schutz",
        "Referrer-Policy":            "Referrer-Datenschutz",
        "Permissions-Policy":         "Feature-Beschränkungen",
    }
    missing, present = [], {}
    try:
        resp = session.get(url, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for h, desc in REQUIRED_HEADERS.items():
            val = headers.get(h.lower())
            if val:
                present[h] = val[:80]
            else:
                missing.append({"header": h, "description": desc})
    except Exception as e:
        return {"error": str(e), "missing": [], "present": {}}
    return {"missing": missing, "present": present}


# ─── 3. HTTPS-Redirect-Check ──────────────────────────────────────────────────

def check_https_redirect(domain: str, session: requests.Session) -> dict:
    http_url = f"http://{domain}"
    try:
        resp = session.get(http_url, timeout=10, allow_redirects=True)
        final = resp.url
        redirected_to_https = final.startswith("https://")
        return {
            "http_redirects_to_https": redirected_to_https,
            "final_url": final,
            "hops": len(resp.history),
        }
    except Exception as e:
        return {"error": str(e)}


# ─── 4. PageSpeed Insights (Google) ───────────────────────────────────────────

def check_pagespeed(url: str) -> dict:
    """Ruft Google PageSpeed Insights API ab – gibt Core Web Vitals zurück."""
    if not PAGESPEED_API_KEY:
        return {"skipped": True, "reason": "Kein PAGESPEED_API_KEY gesetzt"}

    results = {}
    for strategy in ("mobile", "desktop"):
        api_url = (
            f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
            f"?url={url}&strategy={strategy}&key={PAGESPEED_API_KEY}"
        )
        try:
            resp = requests.get(api_url, timeout=60)
            data = resp.json()
            cats  = data.get("lighthouseResult", {}).get("categories", {})
            audits = data.get("lighthouseResult", {}).get("audits", {})

            def score(key): return round((cats.get(key, {}).get("score", 0) or 0) * 100)
            def ms(key):    return audits.get(key, {}).get("numericValue", None)

            results[strategy] = {
                "performance_score":    score("performance"),
                "accessibility_score":  score("accessibility"),
                "seo_score":            score("seo"),
                "best_practices_score": score("best-practices"),
                "lcp_ms":    ms("largest-contentful-paint"),
                "cls":       audits.get("cumulative-layout-shift", {}).get("numericValue"),
                "ttfb_ms":   ms("server-response-time"),
                "fcp_ms":    ms("first-contentful-paint"),
                "speed_index_ms": ms("speed-index"),
            }
        except Exception as e:
            results[strategy] = {"error": str(e)}
    return results


# ─── 5. Robots.txt & Sitemap ──────────────────────────────────────────────────

def check_robots_and_sitemap(base_url: str, session: requests.Session) -> dict:
    result = {}
    parsed = urlparse(base_url)
    root   = f"{parsed.scheme}://{parsed.netloc}"

    # robots.txt
    try:
        r = session.get(f"{root}/robots.txt", timeout=10)
        result["robots_txt"] = {
            "accessible": r.status_code == 200,
            "status": r.status_code,
            "content_snippet": r.text[:300] if r.status_code == 200 else None,
            "blocks_all": "Disallow: /" in r.text and "User-agent: *" in r.text,
        }
        # Sitemap-URL aus robots.txt extrahieren
        sitemap_match = re.search(r"(?i)Sitemap:\s*(.+)", r.text)
        sitemap_url   = sitemap_match.group(1).strip() if sitemap_match else f"{root}/sitemap.xml"
    except Exception as e:
        result["robots_txt"] = {"accessible": False, "error": str(e)}
        sitemap_url = f"{root}/sitemap.xml"

    # sitemap.xml
    try:
        r = session.get(sitemap_url, timeout=10)
        urls_in_sitemap = len(re.findall(r"<loc>", r.text)) if r.status_code == 200 else 0
        result["sitemap"] = {
            "url": sitemap_url,
            "accessible": r.status_code == 200,
            "status": r.status_code,
            "url_count": urls_in_sitemap,
            "is_index": "<sitemapindex" in r.text,
        }
    except Exception as e:
        result["sitemap"] = {"accessible": False, "error": str(e)}

    # favicon
    try:
        r = session.get(f"{root}/favicon.ico", timeout=8)
        result["favicon"] = {"accessible": r.status_code == 200, "status": r.status_code}
    except Exception:
        result["favicon"] = {"accessible": False}

    return result


# ─── 6. Website-Crawler ───────────────────────────────────────────────────────

def crawl_website(base_url: str, session: requests.Session) -> dict:
    domain   = urlparse(base_url).netloc
    visited  = set()
    to_visit = [base_url]

    results = {
        "pages":                {},
        "broken_links":         [],
        "missing_images":       [],
        "slow_pages":           [],
        "missing_meta":         [],
        "redirect_chains":      [],
        "mixed_content":        [],   # HTTP-Ressourcen auf HTTPS-Seiten
        "duplicate_titles":     defaultdict(list),
        "duplicate_descs":      defaultdict(list),
        "missing_h1":           [],
        "multiple_h1":          [],
        "missing_canonical":    [],
        "missing_og_tags":      [],
        "missing_schema":       [],
        "noindex_pages":        [],
        "errors":               [],
    }

    def fetch(url):
        start = time.time()
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            return resp, int((time.time() - start) * 1000)
        except Exception:
            return None, -1

    while to_visit and len(visited) < MAX_PAGES:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        resp, load_ms = fetch(url)
        time.sleep(CRAWL_DELAY)

        if resp is None:
            results["errors"].append({"url": url, "reason": "timeout_or_connection_error"})
            continue

        status = resp.status_code
        page_info = {"status": status, "load_ms": load_ms, "title": None, "meta_desc": None}

        if len(resp.history) > 1:
            results["redirect_chains"].append({"url": url, "final_url": resp.url, "hops": len(resp.history)})

        if status >= 400:
            results["broken_links"].append({"source": "direct", "url": url, "status": status})
            results["pages"][url] = page_info
            continue

        if load_ms > SLOW_PAGE_MS:
            results["slow_pages"].append({"url": url, "load_ms": load_ms})

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            results["pages"][url] = page_info
            continue

        # ── Title & Meta Description ──
        title_tag  = soup.find("title")
        meta_desc  = soup.find("meta", attrs={"name": "description"})
        title_text = title_tag.get_text(strip=True) if title_tag else None
        desc_text  = meta_desc.get("content", "").strip() if meta_desc else None
        page_info["title"]     = title_text
        page_info["meta_desc"] = desc_text

        missing = []
        if not title_text: missing.append("title")
        if not desc_text:  missing.append("meta_description")
        if missing:
            results["missing_meta"].append({"url": url, "missing": missing})

        # ── Duplikat-Tracking ──
        if title_text:
            results["duplicate_titles"][title_text].append(url)
        if desc_text:
            results["duplicate_descs"][desc_text].append(url)

        # ── Heading-Struktur ──
        h1s = soup.find_all("h1")
        if not h1s:
            results["missing_h1"].append(url)
        elif len(h1s) > 1:
            results["multiple_h1"].append({"url": url, "count": len(h1s)})

        # ── Canonical ──
        canonical = soup.find("link", rel="canonical")
        if not canonical:
            results["missing_canonical"].append(url)

        # ── noindex ──
        robots_meta = soup.find("meta", attrs={"name": "robots"})
        if robots_meta and "noindex" in robots_meta.get("content", "").lower():
            results["noindex_pages"].append(url)

        # ── Open Graph Tags ──
        og_required = ["og:title", "og:description", "og:image"]
        missing_og  = [t for t in og_required if not soup.find("meta", property=t)]
        if missing_og:
            results["missing_og_tags"].append({"url": url, "missing": missing_og})

        # ── Structured Data ──
        schema_tags = soup.find_all("script", type="application/ld+json")
        if not schema_tags:
            results["missing_schema"].append(url)

        # ── Mixed Content ──
        if url.startswith("https://"):
            for tag, attr in [("img","src"),("script","src"),("link","href"),("iframe","src")]:
                for el in soup.find_all(tag):
                    val = el.get(attr,"")
                    if val.startswith("http://"):
                        results["mixed_content"].append({"page": url, "resource": val[:120], "type": tag})

        results["pages"][url] = page_info

        # ── Interne Links crawlen ──
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if not href or href.startswith(("#","mailto:","tel:","javascript:")):
                continue
            abs_url = urljoin(url, href)
            parsed  = urlparse(abs_url)
            if parsed.netloc == domain and abs_url not in visited:
                to_visit.append(abs_url)
            elif parsed.netloc and parsed.netloc != domain and abs_url not in visited:
                try:
                    r = session.head(abs_url, timeout=8, allow_redirects=True)
                    if r.status_code >= 400:
                        results["broken_links"].append({"source": url, "url": abs_url, "status": r.status_code})
                except Exception:
                    results["broken_links"].append({"source": url, "url": abs_url, "status": "unreachable"})
                time.sleep(0.2)

        # ── Bilder prüfen ──
        for img in soup.find_all("img"):
            src = img.get("src","").strip()
            alt = img.get("alt","").strip()
            if not src:
                results["missing_images"].append({"page": url, "src": "(kein src)", "issue": "missing_src"})
                continue
            abs_src = urljoin(url, src)
            if abs_src.startswith("data:"):
                continue
            try:
                r = session.head(abs_src, timeout=8, allow_redirects=True)
                if r.status_code >= 400:
                    results["missing_images"].append({"page": url, "src": abs_src, "issue": f"http_{r.status_code}"})
            except Exception:
                results["missing_images"].append({"page": url, "src": abs_src, "issue": "unreachable"})
            if not alt:
                results["missing_images"].append({"page": url, "src": abs_src, "issue": "missing_alt_text"})
            time.sleep(0.1)

    # Duplikate filtern
    results["duplicate_titles"] = {k: v for k, v in results["duplicate_titles"].items() if len(v) > 1}
    results["duplicate_descs"]  = {k: v for k, v in results["duplicate_descs"].items()  if len(v) > 1}
    results["total_pages_crawled"] = len(visited)
    return results


# ─── 7. Claude-Report-Generierung ─────────────────────────────────────────────

def build_report_summary(crawl: dict, ssl_r: dict, headers_r: dict, https_r: dict,
                         pagespeed_r: dict, infra_r: dict, target_url: str) -> dict:
    pages = crawl["pages"]
    load_times = [p["load_ms"] for p in pages.values() if p["load_ms"] > 0]

    return {
        "website": target_url,
        "crawl_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        # Performance
        "performance": {
            "pages_crawled": crawl["total_pages_crawled"],
            "avg_load_ms": int(sum(load_times) / len(load_times)) if load_times else 0,
            "slow_pages": crawl["slow_pages"][:5],
            "pagespeed": pagespeed_r,
        },
        # Security
        "security": {
            "ssl": ssl_r,
            "ssl_expiry_warning": ssl_r.get("days_remaining", 999) < SSL_WARN_DAYS,
            "headers": headers_r,
            "https_redirect": https_r,
            "mixed_content_count": len(crawl["mixed_content"]),
            "mixed_content_sample": crawl["mixed_content"][:5],
        },
        # Broken / Crawl
        "broken": {
            "broken_links": crawl["broken_links"][:10],
            "broken_link_count": len(crawl["broken_links"]),
            "redirect_chains": crawl["redirect_chains"][:5],
            "errors": crawl["errors"][:5],
        },
        # SEO On-Page
        "seo": {
            "missing_meta_count": len(crawl["missing_meta"]),
            "missing_meta_sample": crawl["missing_meta"][:5],
            "duplicate_titles": list(crawl["duplicate_titles"].items())[:3],
            "duplicate_descs":  list(crawl["duplicate_descs"].items())[:3],
            "missing_h1_count": len(crawl["missing_h1"]),
            "missing_h1_pages": crawl["missing_h1"][:5],
            "multiple_h1_count": len(crawl["multiple_h1"]),
            "missing_canonical_count": len(crawl["missing_canonical"]),
            "noindex_pages": crawl["noindex_pages"][:5],
            "missing_og_count": len(crawl["missing_og_tags"]),
            "missing_schema_count": len(crawl["missing_schema"]),
        },
        # Images
        "images": {
            "issues_count": len(crawl["missing_images"]),
            "sample": crawl["missing_images"][:5],
        },
        # Infrastructure
        "infrastructure": infra_r,
    }


def analyze_with_claude(summary: dict) -> str:
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    prompt = f"""Du bist ein erfahrener Website-Analyst. Hier sind die Ergebnisse des heutigen automatischen Website-Checks:

{json.dumps(summary, indent=2, ensure_ascii=False)}

Erstelle einen prägnanten Slack-Report auf Deutsch mit dieser Struktur:

*🔴/🟡/🟢 Gesamtstatus* – ein Satz, was heute am wichtigsten ist

*🚨 Kritisch* (max. 3 – nur echte Blocker: Security, Broken, SSL)
*⚠️ Warnung* (max. 4 – Performance, SEO-Lücken, fehlende Tags)
*✅ Gut* (max. 3 – was in Ordnung ist, kurz)

*📊 Performance-Snapshot*
• PageSpeed Mobile: X/100 | Desktop: Y/100
• Ø Ladezeit: Xms | LCP: Xms | CLS: X
• Langsamste Seite: URL (Xms)

*🔐 Sicherheit*
• SSL: X Tage bis Ablauf | Headers: X/6 vorhanden
• HTTPS-Redirect: ✅/❌ | Mixed Content: X Seiten

*🔗 Links & Crawl*
• Broken Links: X | Redirect-Chains: X | Fehler: X

*📝 SEO-Gesundheit*
• Fehlende Titles/Desc: X | Fehlende H1: X
• Duplikate: X | Kein Canonical: X | Kein Schema: X

*🎯 Prioritäten heute*
1. [Wichtigstes zuerst]
2. ...
3. ...

Halte es kurz und actionable. Nutze Slack-Markdown (*bold*, _italic_, `code`). Keine langen Einleitungen.
"""
    resp = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1800,
        messages=[{"role": "user", "content": prompt}]
    )
    return resp.content[0].text


# ─── 8. Slack ─────────────────────────────────────────────────────────────────

def send_to_slack(report_text: str, summary: dict):
    if not SLACK_WEBHOOK_URL:
        print("⚠️  Kein SLACK_WEBHOOK_URL – Report nur im Terminal:")
        print(report_text)
        return

    broken   = summary["broken"]["broken_link_count"]
    ssl_days = summary["security"]["ssl"].get("days_remaining", 999)
    sec_miss = len(summary["security"]["headers"].get("missing", []))
    color = "#e53935" if (broken > 0 or ssl_days < 14 or sec_miss >= 4) else \
            "#ff9800" if (broken > 0 or ssl_days < SSL_WARN_DAYS or sec_miss > 0) else "#2eb886"

    domain = urlparse(summary["website"]).netloc
    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"🔍 Website Health Report – {domain}"}},
                {"type": "divider"},
                {"type": "section", "text": {"type": "mrkdwn", "text": report_text}},
                {"type": "divider"},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": (
                    f"📄 {summary['performance']['pages_crawled']} Seiten  •  "
                    f"🔗 {broken} Broken Links  •  "
                    f"🐢 {len(summary['performance']['slow_pages'])} langsame Seiten  •  "
                    f"🔐 SSL: {ssl_days} Tage  •  "
                    f"📝 SEO-Issues: {summary['seo']['missing_meta_count']}  •  "
                    f"{summary['crawl_date']}"
                )}]}
            ]
        }]
    }
    r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
    print("✅ Slack OK" if r.status_code == 200 else f"❌ Slack Fehler: {r.status_code}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{'='*60}")
    print(f"🚀 Website Health Check: {TARGET_URL}")
    print(f"{'='*60}\n")
    t0 = time.time()

    parsed = urlparse(TARGET_URL)
    domain = parsed.netloc
    session = requests.Session()
    session.headers.update({"User-Agent": "WebsiteHealthMonitor/2.0"})

    # ── Security-Checks ──
    print("🔐 SSL-Check...")
    ssl_result     = check_ssl(domain)
    print(f"   {'✅' if ssl_result['valid'] else '❌'} SSL gültig: {ssl_result.get('days_remaining','?')} Tage verbleibend")

    print("🛡️  Security-Header-Check...")
    headers_result = check_security_headers(TARGET_URL, session)
    print(f"   ✅ {len(headers_result.get('present',{}))} Header vorhanden | ❌ {len(headers_result.get('missing',[]))} fehlen")

    print("🔀 HTTPS-Redirect-Check...")
    https_result   = check_https_redirect(domain, session)
    print(f"   {'✅' if https_result.get('http_redirects_to_https') else '❌'} HTTP → HTTPS Redirect")

    # ── PageSpeed ──
    print("\n⚡ Google PageSpeed Insights...")
    if PAGESPEED_API_KEY:
        pagespeed_result = check_pagespeed(TARGET_URL)
        mob = pagespeed_result.get("mobile", {})
        des = pagespeed_result.get("desktop", {})
        print(f"   Mobile:  Performance {mob.get('performance_score','?')}/100 | LCP {mob.get('lcp_ms','?')}ms")
        print(f"   Desktop: Performance {des.get('performance_score','?')}/100 | LCP {des.get('lcp_ms','?')}ms")
    else:
        pagespeed_result = {"skipped": True, "reason": "Kein API-Key"}
        print("   ⚠️  Übersprungen (PAGESPEED_API_KEY nicht gesetzt)")

    # ── robots.txt / Sitemap / Favicon ──
    print("\n🗺️  robots.txt, Sitemap, Favicon...")
    infra_result = check_robots_and_sitemap(TARGET_URL, session)
    print(f"   robots.txt: {'✅' if infra_result.get('robots_txt',{}).get('accessible') else '❌'}")
    print(f"   sitemap.xml: {'✅' if infra_result.get('sitemap',{}).get('accessible') else '❌'} ({infra_result.get('sitemap',{}).get('url_count',0)} URLs)")
    print(f"   favicon: {'✅' if infra_result.get('favicon',{}).get('accessible') else '❌'}")

    # ── Crawler ──
    print(f"\n🔍 Crawle Website (max. {MAX_PAGES} Seiten)...")
    crawl_result = crawl_website(TARGET_URL, session)
    print(f"   {crawl_result['total_pages_crawled']} Seiten gecrawlt in {int(time.time()-t0)}s")
    print(f"   🔗 {len(crawl_result['broken_links'])} Broken Links")
    print(f"   🐢 {len(crawl_result['slow_pages'])} langsame Seiten (>{SLOW_PAGE_MS}ms)")
    print(f"   🖼️  {len(crawl_result['missing_images'])} Bild-Probleme")
    print(f"   📝 {len(crawl_result['missing_meta'])} fehlende Titles/Descriptions")
    print(f"   🏷️  {len(crawl_result['missing_h1'])} Seiten ohne H1")
    print(f"   🔀 {len(crawl_result['mixed_content'])} Mixed-Content-Probleme")

    # ── Claude-Analyse ──
    print("\n🤖 Claude-Analyse...")
    summary = build_report_summary(crawl_result, ssl_result, headers_result, https_result,
                                   pagespeed_result, infra_result, TARGET_URL)
    report  = analyze_with_claude(summary)

    # ── Slack-Report ──
    print("\n📤 Sende Slack-Report...")
    send_to_slack(report, summary)

    # ── JSON-Export ──
    if os.environ.get("SAVE_REPORT"):
        fname = f"report_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        with open(fname, "w") as f:
            json.dump({"summary": summary, "crawl_details": crawl_result}, f, indent=2, ensure_ascii=False, default=str)
        print(f"💾 Detailreport: {fname}")

    print(f"\n✅ Fertig in {int(time.time()-t0)}s\n")


if __name__ == "__main__":
    main()

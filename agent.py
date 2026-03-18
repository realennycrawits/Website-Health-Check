"""
Website Health Monitor Agent — Multi-Site Version
Mehrere Websites möglich, Broken Links vollständig aufgelistet,
Security Headers nur als Info (keine Kritisch-Einstufung).
"""

import os, time, json, ssl, socket, re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
import anthropic

# ─── Konfiguration ────────────────────────────────────────────────────────────

# Mehrere URLs kommagetrennt: "https://site1.de, https://site2.de"
TARGET_URLS_RAW   = os.environ.get("TARGET_URLS", os.environ.get("TARGET_URL", "https://example.com"))
TARGET_URLS       = [u.strip() for u in TARGET_URLS_RAW.split(",") if u.strip()]

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
PAGESPEED_API_KEY = os.environ.get("PAGESPEED_API_KEY", "")

MAX_PAGES         = 60
SLOW_PAGE_MS      = 3000
REQUEST_TIMEOUT   = 15
CRAWL_DELAY       = 0.5
SSL_WARN_DAYS     = 30


def check_ssl(hostname):
    result = {"valid": False, "days_remaining": None, "expiry_date": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10), server_hostname=hostname) as conn:
            cert = conn.getpeercert()
            expiry_dt = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry_dt - datetime.now(timezone.utc)).days
            result.update({"valid": True, "days_remaining": days_left, "expiry_date": expiry_dt.strftime("%Y-%m-%d")})
    except Exception as e:
        result["error"] = str(e)
    return result


def check_security_headers(url, session):
    HEADERS = {
        "Strict-Transport-Security": "HSTS",
        "X-Frame-Options": "X-Frame-Options",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "Content-Security-Policy": "CSP",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
    }
    missing, present = [], {}
    try:
        resp = session.get(url, timeout=10)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        for h in HEADERS:
            if hdrs.get(h.lower()):
                present[h] = hdrs[h.lower()][:80]
            else:
                missing.append(h)
    except Exception as e:
        return {"error": str(e), "missing": [], "present": {}, "score": 0, "max": 6}
    return {"missing": missing, "present": present, "score": len(present), "max": len(HEADERS)}


def check_https_redirect(domain, session):
    try:
        resp = session.get(f"http://{domain}", timeout=10, allow_redirects=True)
        return {"http_redirects_to_https": resp.url.startswith("https://"), "hops": len(resp.history)}
    except Exception as e:
        return {"error": str(e)}


def check_pagespeed(url):
    if not PAGESPEED_API_KEY:
        return {"skipped": True}
    results = {}
    for strategy in ("mobile", "desktop"):
        try:
            resp = requests.get(
                f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={url}&strategy={strategy}&key={PAGESPEED_API_KEY}",
                timeout=60)
            data = resp.json()
            cats = data.get("lighthouseResult", {}).get("categories", {})
            audits = data.get("lighthouseResult", {}).get("audits", {})
            results[strategy] = {
                "performance_score": round((cats.get("performance", {}).get("score", 0) or 0) * 100),
                "lcp_ms": audits.get("largest-contentful-paint", {}).get("numericValue"),
                "cls":    audits.get("cumulative-layout-shift", {}).get("numericValue"),
                "ttfb_ms": audits.get("server-response-time", {}).get("numericValue"),
            }
        except Exception as e:
            results[strategy] = {"error": str(e)}
    return results


def check_robots_and_sitemap(base_url, session):
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    result = {}
    sitemap_url = f"{root}/sitemap.xml"
    try:
        r = session.get(f"{root}/robots.txt", timeout=10)
        result["robots_txt"] = {"accessible": r.status_code == 200, "blocks_all": "Disallow: /" in r.text}
        sm = re.search(r"(?i)Sitemap:\s*(.+)", r.text)
        if sm: sitemap_url = sm.group(1).strip()
    except Exception:
        result["robots_txt"] = {"accessible": False}
    try:
        r = session.get(sitemap_url, timeout=10)
        result["sitemap"] = {"accessible": r.status_code == 200, "url_count": len(re.findall(r"<loc>", r.text))}
    except Exception:
        result["sitemap"] = {"accessible": False}
    try:
        r = session.get(f"{root}/favicon.ico", timeout=8)
        result["favicon"] = {"accessible": r.status_code == 200}
    except Exception:
        result["favicon"] = {"accessible": False}
    return result


def crawl_website(base_url, session):
    domain = urlparse(base_url).netloc
    visited, to_visit = set(), [base_url]
    results = {
        "pages": {}, "broken_links": [], "missing_images": [], "slow_pages": [],
        "missing_meta": [], "redirect_chains": [], "mixed_content": [],
        "duplicate_titles": defaultdict(list), "duplicate_descs": defaultdict(list),
        "missing_h1": [], "multiple_h1": [], "missing_canonical": [],
        "missing_og_tags": [], "missing_schema": [], "noindex_pages": [], "errors": [],
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
        if url in visited: continue
        visited.add(url)
        resp, load_ms = fetch(url)
        time.sleep(CRAWL_DELAY)

        if resp is None:
            results["errors"].append({"url": url})
            continue

        status = resp.status_code
        page_info = {"status": status, "load_ms": load_ms, "title": None, "meta_desc": None}

        if len(resp.history) > 1:
            results["redirect_chains"].append({"url": url, "final_url": resp.url, "hops": len(resp.history)})

        if status >= 400:
            results["broken_links"].append({"source": "direkt", "url": url, "status": status})
            results["pages"][url] = page_info
            continue

        if load_ms > SLOW_PAGE_MS:
            results["slow_pages"].append({"url": url, "load_ms": load_ms})

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            results["pages"][url] = page_info
            continue

        title_tag = soup.find("title")
        meta_desc = soup.find("meta", attrs={"name": "description"})
        title_text = title_tag.get_text(strip=True) if title_tag else None
        desc_text = meta_desc.get("content", "").strip() if meta_desc else None
        page_info["title"] = title_text
        page_info["meta_desc"] = desc_text

        missing = []
        if not title_text: missing.append("title")
        if not desc_text: missing.append("meta_description")
        if missing: results["missing_meta"].append({"url": url, "missing": missing})

        if title_text: results["duplicate_titles"][title_text].append(url)
        if desc_text: results["duplicate_descs"][desc_text].append(url)

        h1s = soup.find_all("h1")
        if not h1s: results["missing_h1"].append(url)
        elif len(h1s) > 1: results["multiple_h1"].append({"url": url, "count": len(h1s)})

        if not soup.find("link", rel="canonical"):
            results["missing_canonical"].append(url)

        robots_meta = soup.find("meta", attrs={"name": "robots"})
        if robots_meta and "noindex" in robots_meta.get("content", "").lower():
            results["noindex_pages"].append(url)

        missing_og = [t for t in ["og:title", "og:description", "og:image"] if not soup.find("meta", property=t)]
        if missing_og: results["missing_og_tags"].append({"url": url, "missing": missing_og})

        if not soup.find_all("script", type="application/ld+json"):
            results["missing_schema"].append(url)

        if url.startswith("https://"):
            for tag, attr in [("img","src"),("script","src"),("link","href"),("iframe","src")]:
                for el in soup.find_all(tag):
                    val = el.get(attr, "")
                    if val.startswith("http://"):
                        results["mixed_content"].append({"page": url, "resource": val[:100]})

        results["pages"][url] = page_info

        seen_ext = set()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if not href or href.startswith(("#","mailto:","tel:","javascript:")): continue
            abs_url = urljoin(url, href)
            p = urlparse(abs_url)
            if p.netloc == domain:
                if abs_url not in visited: to_visit.append(abs_url)
            elif p.netloc and abs_url not in seen_ext:
                seen_ext.add(abs_url)
                try:
                    r = session.head(abs_url, timeout=8, allow_redirects=True)
                    if r.status_code >= 400:
                        results["broken_links"].append({"source": url, "url": abs_url, "status": r.status_code})
                except Exception:
                    results["broken_links"].append({"source": url, "url": abs_url, "status": "nicht erreichbar"})
                time.sleep(0.2)

        for img in soup.find_all("img"):
            src = img.get("src", "").strip()
            alt = img.get("alt", "").strip()
            if not src:
                results["missing_images"].append({"page": url, "src": "(kein src)", "issue": "fehlendes src"})
                continue
            abs_src = urljoin(url, src)
            if abs_src.startswith("data:"): continue
            try:
                r = session.head(abs_src, timeout=8, allow_redirects=True)
                if r.status_code >= 400:
                    results["missing_images"].append({"page": url, "src": abs_src, "issue": f"HTTP {r.status_code}"})
            except Exception:
                results["missing_images"].append({"page": url, "src": abs_src, "issue": "nicht erreichbar"})
            if not alt:
                results["missing_images"].append({"page": url, "src": abs_src, "issue": "kein alt-Text"})
            time.sleep(0.1)

    results["duplicate_titles"] = {k: v for k, v in results["duplicate_titles"].items() if len(v) > 1}
    results["duplicate_descs"]  = {k: v for k, v in results["duplicate_descs"].items()  if len(v) > 1}
    results["total_pages_crawled"] = len(visited)
    return results


def analyze_with_claude(crawl, ssl_r, headers_r, https_r, pagespeed_r, infra_r, target_url):
    pages = crawl["pages"]
    load_times = [p["load_ms"] for p in pages.values() if p["load_ms"] > 0]

    summary = {
        "website": target_url,
        "crawl_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "pages_crawled": crawl["total_pages_crawled"],
        "performance": {
            "avg_load_ms": int(sum(load_times) / len(load_times)) if load_times else 0,
            "slow_pages": crawl["slow_pages"],
            "pagespeed": pagespeed_r,
        },
        "ssl": ssl_r,
        "https_redirect": https_r,
        "security_headers_info": {
            "score": headers_r.get("score", 0),
            "max": headers_r.get("max", 6),
            "missing": headers_r.get("missing", []),
            "hinweis": "Nur zur Information – niedrige Priorität",
        },
        "mixed_content_count": len(crawl["mixed_content"]),
        "broken_links": {
            "count": len(crawl["broken_links"]),
            "alle": crawl["broken_links"],  # vollständige Liste
        },
        "redirect_chains": crawl["redirect_chains"],
        "seo": {
            "missing_meta": crawl["missing_meta"],
            "duplicate_titles": list(crawl["duplicate_titles"].items()),
            "missing_h1": crawl["missing_h1"],
            "multiple_h1": crawl["multiple_h1"],
            "missing_canonical": len(crawl["missing_canonical"]),
            "noindex_pages": crawl["noindex_pages"],
            "missing_og": len(crawl["missing_og_tags"]),
            "missing_schema": len(crawl["missing_schema"]),
        },
        "images": {
            "issues_count": len(crawl["missing_images"]),
            "details": crawl["missing_images"][:10],
        },
        "infrastructure": infra_r,
    }

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    domain = urlparse(target_url).netloc
    prompt = f"""Du bist ein Website-Analyst. Erstelle einen Slack-Report auf Deutsch für diese Check-Ergebnisse:

{json.dumps(summary, indent=2, ensure_ascii=False)}

Wichtige Regeln:
- Security Headers = NIEDRIGE Priorität, nur ganz kurz als Info erwähnen, NIEMALS als kritisches Problem
- Broken Links VOLLSTÄNDIG einzeln aufzählen (jede URL)
- Kritisch = nur: Broken Links, SSL <14 Tage, HTTPS-Redirect fehlt, noindex auf wichtigen Seiten

Struktur des Reports:

*🔴/🟡/🟢 {domain} – Gesamtstatus*
Ein Satz.

*🚨 Kritisch* (nur echte Blocker)
• ...

*🔗 Broken Links ({len(crawl["broken_links"])} gefunden)*
(Falls vorhanden: ALLE URLs einzeln aufzählen mit Status und Quelleseite)
• `url` → Status X | Gefunden auf: quelle

*⚠️ Warnungen*
• ...

*📊 Performance*
• Ø Ladezeit: Xms | Langsamste: URL (Xms)
• PageSpeed Mobile: X/100 | Desktop: X/100

*📝 SEO*
• Fehlende Titles/Desc: X | H1 fehlt: X | Kein Schema: X

*ℹ️ Security Headers* (zur Info)
• X/6 gesetzt

*✅ Gut*
• ...

*🎯 Top 3 Prioritäten*
1. ...

Nutze Slack-Markdown. Kurz und actionable.
"""

    resp = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    return resp.content[0].text, summary


def send_to_slack(report_text, summary, target_url):
    if not SLACK_WEBHOOK_URL:
        print(report_text)
        return

    broken   = summary["broken_links"]["count"]
    ssl_days = summary["ssl"].get("days_remaining", 999)
    color = "#e53935" if (broken > 0 or ssl_days < 14) else \
            "#ff9800" if ssl_days < SSL_WARN_DAYS else "#2eb886"

    domain = urlparse(target_url).netloc
    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"🔍 Website Health – {domain}"}},
                {"type": "divider"},
                {"type": "section", "text": {"type": "mrkdwn", "text": report_text}},
                {"type": "divider"},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": (
                    f"📄 {summary['pages_crawled']} Seiten  •  "
                    f"🔗 {broken} Broken Links  •  "
                    f"🐢 {len(summary['performance']['slow_pages'])} langsame Seiten  •  "
                    f"🔐 SSL: {ssl_days} Tage  •  "
                    f"{summary['crawl_date']}"
                )}]}
            ]
        }]
    }
    r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
    print("✅ Slack OK" if r.status_code == 200 else f"❌ Slack Fehler: {r.status_code}")


def check_one_site(target_url):
    print(f"\n{'='*55}\n🚀 Prüfe: {target_url}\n{'='*55}")
    t0 = time.time()
    domain = urlparse(target_url).netloc
    session = requests.Session()
    session.headers.update({"User-Agent": "WebsiteHealthMonitor/2.0"})

    print("🔐 SSL...");         ssl_r      = check_ssl(domain)
    print("🛡️  Headers...");    headers_r  = check_security_headers(target_url, session)
    print("🔀 HTTPS...");       https_r    = check_https_redirect(domain, session)
    print("⚡ PageSpeed...");   pagespeed_r = check_pagespeed(target_url)
    print("🗺️  Infra...");      infra_r    = check_robots_and_sitemap(target_url, session)
    print(f"🔍 Crawle...");     crawl_r    = crawl_website(target_url, session)

    print(f"   {crawl_r['total_pages_crawled']} Seiten | {len(crawl_r['broken_links'])} Broken Links | {len(crawl_r['slow_pages'])} langsam")
    print("🤖 Claude...");

    report_text, summary = analyze_with_claude(crawl_r, ssl_r, headers_r, https_r, pagespeed_r, infra_r, target_url)

    print("📤 Slack...")
    send_to_slack(report_text, summary, target_url)

    if os.environ.get("SAVE_REPORT"):
        fname = f"report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M')}.json".replace("/","_")
        with open(fname, "w") as f:
            json.dump({"summary": summary, "crawl": crawl_r}, f, indent=2, ensure_ascii=False, default=str)
        print(f"💾 {fname}")

    print(f"✅ {domain} fertig in {int(time.time()-t0)}s")


def main():
    print(f"\n🌐 Website Health Monitor – {len(TARGET_URLS)} Website(s)")
    for url in TARGET_URLS:
        print(f"   • {url}")
    for url in TARGET_URLS:
        try:
            check_one_site(url)
        except Exception as e:
            print(f"❌ Fehler bei {url}: {e}")
    print("\n🏁 Alle Checks abgeschlossen.")


if __name__ == "__main__":
    main()

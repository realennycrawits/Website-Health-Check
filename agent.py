"""
Website Health Monitor — Multi-Site, CSV-Export für Broken Links
Slack bekommt nur die kompakte Zusammenfassung + Link zur CSV in GitHub Actions.
"""

import os, time, json, ssl, socket, re, csv
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
import anthropic

TARGET_URLS_RAW   = os.environ.get("TARGET_URLS", os.environ.get("TARGET_URL", "https://example.com"))
TARGET_URLS       = [u.strip() for u in TARGET_URLS_RAW.split(",") if u.strip()]
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
PAGESPEED_API_KEY = os.environ.get("PAGESPEED_API_KEY", "")
GITHUB_RUN_URL    = (
    f"{os.environ.get('GITHUB_SERVER_URL','https://github.com')}/"
    f"{os.environ.get('GITHUB_REPOSITORY','')}/"
    f"actions/runs/{os.environ.get('GITHUB_RUN_ID','')}"
)

MAX_PAGES      = 60
SLOW_PAGE_MS   = 3000
REQUEST_TIMEOUT = 15
CRAWL_DELAY    = 0.5
SSL_WARN_DAYS  = 30


# ── Checks ────────────────────────────────────────────────────────────────────

def check_ssl(hostname):
    r = {"valid": False, "days_remaining": None, "expiry_date": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=10), server_hostname=hostname) as c:
            cert = c.getpeercert()
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            r.update({"valid": True, "days_remaining": days, "expiry_date": exp.strftime("%Y-%m-%d")})
    except Exception as e:
        r["error"] = str(e)
    return r

def check_security_headers(url, session):
    HDRS = ["Strict-Transport-Security","X-Frame-Options","X-Content-Type-Options",
            "Content-Security-Policy","Referrer-Policy","Permissions-Policy"]
    missing, present = [], {}
    try:
        resp = session.get(url, timeout=10)
        h = {k.lower(): v for k, v in resp.headers.items()}
        for hdr in HDRS:
            (present if h.get(hdr.lower()) else missing).append(hdr) if h.get(hdr.lower()) else missing.append(hdr)
            if h.get(hdr.lower()): present[hdr] = h[hdr.lower()][:80]
    except Exception as e:
        return {"error": str(e), "missing": [], "present": {}, "score": 0, "max": 6}
    return {"missing": missing, "present": present, "score": len(present), "max": len(HDRS)}

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
    for s in ("mobile", "desktop"):
        try:
            resp = requests.get(
                f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={url}&strategy={s}&key={PAGESPEED_API_KEY}",
                timeout=60)
            data = resp.json()
            cats = data.get("lighthouseResult", {}).get("categories", {})
            aud  = data.get("lighthouseResult", {}).get("audits", {})
            results[s] = {
                "performance_score": round((cats.get("performance", {}).get("score", 0) or 0) * 100),
                "lcp_ms":  aud.get("largest-contentful-paint", {}).get("numericValue"),
                "cls":     aud.get("cumulative-layout-shift", {}).get("numericValue"),
                "ttfb_ms": aud.get("server-response-time", {}).get("numericValue"),
            }
        except Exception as e:
            results[s] = {"error": str(e)}
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
    except:
        result["robots_txt"] = {"accessible": False}
    try:
        r = session.get(sitemap_url, timeout=10)
        result["sitemap"] = {"accessible": r.status_code == 200, "url_count": len(re.findall(r"<loc>", r.text))}
    except:
        result["sitemap"] = {"accessible": False}
    try:
        r = session.get(f"{root}/favicon.ico", timeout=8)
        result["favicon"] = {"accessible": r.status_code == 200}
    except:
        result["favicon"] = {"accessible": False}
    return result


# ── Crawler ───────────────────────────────────────────────────────────────────

def crawl_website(base_url, session):
    domain = urlparse(base_url).netloc
    visited, to_visit = set(), [base_url]
    res = {
        "pages": {}, "broken_links": [], "missing_images": [], "slow_pages": [],
        "missing_meta": [], "redirect_chains": [], "mixed_content": [],
        "duplicate_titles": defaultdict(list), "duplicate_descs": defaultdict(list),
        "missing_h1": [], "multiple_h1": [], "missing_canonical": [],
        "missing_og_tags": [], "missing_schema": [], "noindex_pages": [], "errors": [],
    }

    def fetch(url):
        t = time.time()
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            return r, int((time.time()-t)*1000)
        except:
            return None, -1

    while to_visit and len(visited) < MAX_PAGES:
        url = to_visit.pop(0)
        if url in visited: continue
        visited.add(url)
        resp, ms = fetch(url)
        time.sleep(CRAWL_DELAY)

        if resp is None:
            res["errors"].append({"url": url}); continue

        status = resp.status_code
        pi = {"status": status, "load_ms": ms, "title": None, "meta_desc": None}

        if len(resp.history) > 1:
            res["redirect_chains"].append({"url": url, "final_url": resp.url, "hops": len(resp.history)})
        if status >= 400:
            res["broken_links"].append({"source": "direkt", "url": url, "status": status})
            res["pages"][url] = pi; continue
        if ms > SLOW_PAGE_MS:
            res["slow_pages"].append({"url": url, "load_ms": ms})

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except:
            res["pages"][url] = pi; continue

        t_tag = soup.find("title")
        m_tag = soup.find("meta", attrs={"name": "description"})
        title = t_tag.get_text(strip=True) if t_tag else None
        desc  = m_tag.get("content","").strip() if m_tag else None
        pi["title"] = title; pi["meta_desc"] = desc

        missing = []
        if not title: missing.append("title")
        if not desc:  missing.append("meta_description")
        if missing: res["missing_meta"].append({"url": url, "missing": missing})
        if title: res["duplicate_titles"][title].append(url)
        if desc:  res["duplicate_descs"][desc].append(url)

        h1s = soup.find_all("h1")
        if not h1s: res["missing_h1"].append(url)
        elif len(h1s) > 1: res["multiple_h1"].append({"url": url, "count": len(h1s)})

        if not soup.find("link", rel="canonical"): res["missing_canonical"].append(url)

        rm = soup.find("meta", attrs={"name": "robots"})
        if rm and "noindex" in rm.get("content","").lower(): res["noindex_pages"].append(url)

        og_miss = [t for t in ["og:title","og:description","og:image"] if not soup.find("meta", property=t)]
        if og_miss: res["missing_og_tags"].append({"url": url, "missing": og_miss})
        if not soup.find_all("script", type="application/ld+json"): res["missing_schema"].append(url)

        if url.startswith("https://"):
            for tag, attr in [("img","src"),("script","src"),("link","href"),("iframe","src")]:
                for el in soup.find_all(tag):
                    v = el.get(attr,"")
                    if v.startswith("http://"): res["mixed_content"].append({"page": url, "resource": v[:100]})

        res["pages"][url] = pi

        seen_ext = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#","mailto:","tel:","javascript:")): continue
            abs_url = urljoin(url, href)
            p = urlparse(abs_url)
            if p.netloc == domain:
                if abs_url not in visited: to_visit.append(abs_url)
            elif p.netloc and abs_url not in seen_ext:
                seen_ext.add(abs_url)
                try:
                    r2 = session.head(abs_url, timeout=8, allow_redirects=True)
                    if r2.status_code >= 400:
                        res["broken_links"].append({"source": url, "url": abs_url, "status": r2.status_code})
                except:
                    res["broken_links"].append({"source": url, "url": abs_url, "status": "nicht erreichbar"})
                time.sleep(0.2)

        for img in soup.find_all("img"):
            src = img.get("src","").strip()
            alt = img.get("alt","").strip()
            if not src:
                res["missing_images"].append({"page": url, "src": "(kein src)", "issue": "fehlendes src"}); continue
            abs_src = urljoin(url, src)
            if abs_src.startswith("data:"): continue
            try:
                r2 = session.head(abs_src, timeout=8, allow_redirects=True)
                if r2.status_code >= 400:
                    res["missing_images"].append({"page": url, "src": abs_src, "issue": f"HTTP {r2.status_code}"})
            except:
                res["missing_images"].append({"page": url, "src": abs_src, "issue": "nicht erreichbar"})
            if not alt: res["missing_images"].append({"page": url, "src": abs_src, "issue": "kein alt-Text"})
            time.sleep(0.1)

    res["duplicate_titles"] = {k: v for k,v in res["duplicate_titles"].items() if len(v)>1}
    res["duplicate_descs"]  = {k: v for k,v in res["duplicate_descs"].items() if len(v)>1}
    res["total_pages_crawled"] = len(visited)
    return res


# ── CSV-Export der Broken Links ───────────────────────────────────────────────

def export_broken_links_csv(broken_links, domain):
    """Speichert alle Broken Links als CSV-Datei. Gibt den Dateinamen zurück."""
    if not broken_links:
        return None
    fname = f"broken_links_{domain}_{datetime.now().strftime('%Y%m%d')}.csv".replace("/","_")
    with open(fname, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "status", "gefunden_auf"])
        writer.writeheader()
        for bl in broken_links:
            writer.writerow({"url": bl["url"], "status": bl["status"], "gefunden_auf": bl.get("source","")})
    print(f"💾 CSV gespeichert: {fname} ({len(broken_links)} Einträge)")
    return fname


# ── Claude-Analyse ────────────────────────────────────────────────────────────

def analyze_with_claude(crawl, ssl_r, headers_r, https_r, pagespeed_r, infra_r, target_url):
    pages = crawl["pages"]
    load_times = [p["load_ms"] for p in pages.values() if p["load_ms"] > 0]
    broken_count = len(crawl["broken_links"])

    summary = {
        "website": target_url,
        "crawl_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "pages_crawled": crawl["total_pages_crawled"],
        "performance": {
            "avg_load_ms": int(sum(load_times)/len(load_times)) if load_times else 0,
            "slow_pages": crawl["slow_pages"],
            "pagespeed": pagespeed_r,
        },
        "ssl": ssl_r,
        "https_redirect": https_r,
        "security_headers": {"score": headers_r.get("score",0), "max": headers_r.get("max",6), "missing": headers_r.get("missing",[])},
        "mixed_content_count": len(crawl["mixed_content"]),
        "broken_links_count": broken_count,
        "redirect_chains_count": len(crawl["redirect_chains"]),
        "seo": {
            "missing_meta_count": len(crawl["missing_meta"]),
            "missing_meta_sample": crawl["missing_meta"][:3],
            "duplicate_titles_count": len(crawl["duplicate_titles"]),
            "missing_h1_count": len(crawl["missing_h1"]),
            "multiple_h1_count": len(crawl["multiple_h1"]),
            "missing_canonical_count": len(crawl["missing_canonical"]),
            "noindex_pages": crawl["noindex_pages"][:3],
            "missing_og_count": len(crawl["missing_og_tags"]),
            "missing_schema_count": len(crawl["missing_schema"]),
        },
        "images_issues_count": len(crawl["missing_images"]),
        "infrastructure": infra_r,
    }

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    domain = urlparse(target_url).netloc
    prompt = f"""Du bist ein Website-Analyst. Erstelle einen kompakten Slack-Report auf Deutsch.

{json.dumps(summary, indent=2, ensure_ascii=False)}

Wichtige Regeln:
- Security Headers = NUR kurze Info-Zeile, KEINE Kritisch-Einstufung
- Broken Links: NUR die Anzahl nennen ({broken_count}) – die vollständige Liste ist als CSV-Datei in GitHub verfügbar
- Kritisch = nur: Broken Links vorhanden, SSL <14 Tage, HTTPS fehlt, noindex auf wichtigen Seiten
- Report MUSS unter 2500 Zeichen bleiben (Slack-Limit!)

Struktur:
*🔴/🟡/🟢 {domain} – Gesamtstatus*
Ein Satz.

*🚨 Kritisch*
• ...

*⚠️ Warnungen*
• ...

*📊 Performance*
• Ø Ladezeit: Xms | Langsamste: URL (Xms)
• PageSpeed Mobile: X/100 | Desktop: X/100

*📝 SEO*
• Titles/Desc fehlen: X | H1 fehlt: X | Kein Schema: X

*ℹ️ Security Headers*
• X/6 gesetzt

*✅ Gut*
• ...

*🎯 Top 3 Prioritäten*
1. ...

Kurz, klar, unter 2500 Zeichen!
"""
    resp = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    return resp.content[0].text, summary


# ── Slack ─────────────────────────────────────────────────────────────────────

def send_to_slack(report_text, summary, broken_links, target_url, csv_filename):
    if not SLACK_WEBHOOK_URL:
        print("⚠️  Kein SLACK_WEBHOOK_URL – Report im Terminal:")
        print(report_text)
        return

    broken_count = summary["broken_links_count"]
    ssl_days     = summary["ssl"].get("days_remaining", 999)
    color = "#e53935" if (broken_count > 0 or ssl_days < 14) else \
            "#ff9800" if ssl_days < SSL_WARN_DAYS else "#2eb886"
    domain = urlparse(target_url).netloc

    # Broken-Links-Block: Link zur GitHub-Actions-CSV
    if broken_count > 0 and csv_filename:
        broken_block = (
            f"\n\n*🔗 {broken_count} Broken Link{'s' if broken_count != 1 else ''} gefunden*\n"
            f"Vollständige Liste als CSV-Datei: <{GITHUB_RUN_URL}|GitHub Actions → Artifacts öffnen>"
        )
    elif broken_count > 0:
        broken_block = f"\n\n*🔗 {broken_count} Broken Links gefunden* (Details im Log)"
    else:
        broken_block = ""

    # Report auf maximal 2500 Zeichen kürzen
    max_report = 2500 - len(broken_block)
    final_text = report_text[:max_report] + broken_block

    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"🔍 Website Health – {domain}"}},
                {"type": "divider"},
                {"type": "section", "text": {"type": "mrkdwn", "text": final_text}},
                {"type": "divider"},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": (
                    f"📄 {summary['pages_crawled']} Seiten  •  "
                    f"🔗 {broken_count} Broken Links  •  "
                    f"🐢 {len(summary['performance']['slow_pages'])} langsam  •  "
                    f"🔐 SSL: {ssl_days} Tage  •  "
                    f"{summary['crawl_date']}"
                )}]}
            ]
        }]
    }

    r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
    if r.status_code == 200:
        print("✅ Slack OK")
    else:
        print(f"❌ Slack Fehler: {r.status_code} – {r.text}")


# ── Main ──────────────────────────────────────────────────────────────────────

def check_one_site(target_url):
    print(f"\n{'='*55}\n🚀 Prüfe: {target_url}\n{'='*55}")
    t0 = time.time()
    domain = urlparse(target_url).netloc
    session = requests.Session()
    session.headers.update({"User-Agent": "WebsiteHealthMonitor/2.0"})

    print("🔐 SSL...");          ssl_r       = check_ssl(domain)
    print("🛡️  Headers...");     headers_r   = check_security_headers(target_url, session)
    print("🔀 HTTPS...");        https_r     = check_https_redirect(domain, session)
    print("⚡ PageSpeed...");    pagespeed_r = check_pagespeed(target_url)
    print("🗺️  Infra...");       infra_r     = check_robots_and_sitemap(target_url, session)
    print(f"🔍 Crawle...");      crawl_r     = crawl_website(target_url, session)

    broken = crawl_r["broken_links"]
    print(f"   {crawl_r['total_pages_crawled']} Seiten | {len(broken)} Broken Links | {len(crawl_r['slow_pages'])} langsam")

    # Broken Links als CSV speichern
    csv_file = export_broken_links_csv(broken, domain)

    print("🤖 Claude...")
    report_text, summary = analyze_with_claude(crawl_r, ssl_r, headers_r, https_r, pagespeed_r, infra_r, target_url)

    print("📤 Slack...")
    send_to_slack(report_text, summary, broken, target_url, csv_file)

    if os.environ.get("SAVE_REPORT"):
        fname = f"report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M')}.json".replace("/","_")
        with open(fname, "w") as f:
            json.dump({"summary": summary, "crawl": crawl_r}, f, indent=2, ensure_ascii=False, default=str)
        print(f"💾 JSON: {fname}")

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

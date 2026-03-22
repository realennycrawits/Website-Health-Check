"""
Website Health Monitor — Multi-Site
- HEAD → GET Fallback bei 403/405 (keine False Positives)
- Alle Listen > 5 Einträge → eigene CSV-Datei als GitHub Artifact
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

MAX_PAGES       = 60
SLOW_PAGE_MS    = 3000
REQUEST_TIMEOUT = 15
CRAWL_DELAY     = 0.5
SSL_WARN_DAYS   = 30
CSV_THRESHOLD   = 5   # Ab dieser Anzahl → CSV statt Slack-Text


# ── Hilfsfunktionen ───────────────────────────────────────────────────────────

def safe_head_get(session, url, timeout=8):
    """
    Prüft den HTTP-Status einer Ressource (wird nur für Bilder verwendet).
    Strategie: HEAD zuerst → bei 403/405 nochmal mit GET (verhindert False Positives).
    Gibt (status_code, error_string) zurück.
    """
    try:
        r = session.head(url, timeout=timeout, allow_redirects=True)
        # Manche Server blockieren HEAD → nochmal mit GET versuchen
        if r.status_code in (403, 405):
            try:
                r2 = session.get(url, timeout=timeout, allow_redirects=True, stream=True)
                r2.close()  # Body nicht laden
                return r2.status_code, None
            except Exception:
                pass  # HEAD-Ergebnis behalten
        return r.status_code, None
    except requests.exceptions.Timeout:
        return None, "timeout"
    except requests.exceptions.ConnectionError:
        return None, "connection_error"
    except Exception as e:
        return None, str(e)


def write_csv(filename, rows, fieldnames):
    """Schreibt eine CSV-Datei und gibt den Dateinamen zurück."""
    if not rows:
        return None
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"   💾 {filename} ({len(rows)} Einträge)")
    return filename


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
            if h.get(hdr.lower()):
                present[hdr] = h[hdr.lower()][:80]
            else:
                missing.append(hdr)
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
            res["errors"].append({"url": url, "fehler": "timeout/connection"}); continue

        status = resp.status_code
        pi = {"status": status, "load_ms": ms, "title": None, "meta_desc": None}

        if len(resp.history) > 1:
            res["redirect_chains"].append({
                "url": url, "final_url": resp.url,
                "hops": len(resp.history), "zwischenstopps": " → ".join(r.url for r in resp.history)
            })
        if status >= 400:
            res["broken_links"].append({"url": url, "status": status, "gefunden_auf": "direkt"})
            res["pages"][url] = pi; continue
        if ms > SLOW_PAGE_MS:
            res["slow_pages"].append({"url": url, "ladezeit_ms": ms})

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
        if missing: res["missing_meta"].append({"url": url, "fehlt": ", ".join(missing)})
        if title: res["duplicate_titles"][title].append(url)
        if desc:  res["duplicate_descs"][desc].append(url)

        h1s = soup.find_all("h1")
        if not h1s:
            res["missing_h1"].append({"url": url})
        elif len(h1s) > 1:
            res["multiple_h1"].append({"url": url, "anzahl_h1": len(h1s), "texte": " | ".join(h.get_text(strip=True)[:50] for h in h1s)})

        if not soup.find("link", rel="canonical"):
            res["missing_canonical"].append({"url": url})

        rm = soup.find("meta", attrs={"name": "robots"})
        if rm and "noindex" in rm.get("content","").lower():
            res["noindex_pages"].append({"url": url, "robots_content": rm.get("content","")})

        og_miss = [t for t in ["og:title","og:description","og:image"] if not soup.find("meta", property=t)]
        if og_miss: res["missing_og_tags"].append({"url": url, "fehlt": ", ".join(og_miss)})

        if not soup.find_all("script", type="application/ld+json"):
            res["missing_schema"].append({"url": url})

        if url.startswith("https://"):
            for tag, attr in [("img","src"),("script","src"),("link","href"),("iframe","src")]:
                for el in soup.find_all(tag):
                    v = el.get(attr,"")
                    if v.startswith("http://"):
                        res["mixed_content"].append({"seite": url, "ressource": v[:120], "typ": tag})

        res["pages"][url] = pi

        # ── Nur interne Links crawlen – externe werden ignoriert ──
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#","mailto:","tel:","javascript:")): continue
            abs_url = urljoin(url, href)
            p = urlparse(abs_url)
            if p.netloc == domain and abs_url not in visited:
                to_visit.append(abs_url)

        # ── Bilder prüfen ──────────────────────────────────────────────────────
        # Kritisch:    defekte Bilder (404, timeout, kein src)
        # Informativ:  kein alt-Text, kein width/height, kein lazy loading,
        #              schlechtes Format (kein WebP/AVIF), zu große Dateigröße (>300KB)
        for img in soup.find_all("img"):
            src     = img.get("src","").strip()
            alt     = img.get("alt","").strip()
            width   = img.get("width","").strip()
            height  = img.get("height","").strip()
            loading = img.get("loading","").strip().lower()

            if not src:
                res["missing_images"].append({
                    "seite": url, "src": "(kein src)",
                    "problem": "fehlendes src-Attribut",
                    "schwere": "kritisch", "alt_text": "",
                    "dateigroesse_kb": "", "format": "", "hinweis": ""
                })
                continue

            abs_src = urljoin(url, src)
            if abs_src.startswith("data:"): continue

            # HTTP-Status + Dateigröße in einem Request
            dateigroesse_kb = ""
            format_ext = abs_src.split("?")[0].rsplit(".",1)[-1].lower() if "." in abs_src else ""
            try:
                r_img = session.head(abs_src, timeout=8, allow_redirects=True)
                # HEAD → GET Fallback bei 403/405
                if r_img.status_code in (403, 405):
                    r_img = session.get(abs_src, timeout=8, allow_redirects=True, stream=True)
                    r_img.close()
                status_img = r_img.status_code
                # Dateigröße aus Content-Length Header lesen (kein extra Request nötig)
                cl = r_img.headers.get("content-length")
                if cl and cl.isdigit():
                    dateigroesse_kb = round(int(cl) / 1024, 1)
            except requests.exceptions.Timeout:
                res["missing_images"].append({
                    "seite": url, "src": abs_src,
                    "problem": "nicht erreichbar (timeout)",
                    "schwere": "kritisch", "alt_text": alt,
                    "dateigroesse_kb": "", "format": format_ext, "hinweis": ""
                })
                time.sleep(0.1); continue
            except Exception as e:
                res["missing_images"].append({
                    "seite": url, "src": abs_src,
                    "problem": f"nicht erreichbar ({e})",
                    "schwere": "kritisch", "alt_text": alt,
                    "dateigroesse_kb": "", "format": format_ext, "hinweis": ""
                })
                time.sleep(0.1); continue

            # Kritisch: Bild existiert nicht
            if status_img >= 400:
                res["missing_images"].append({
                    "seite": url, "src": abs_src,
                    "problem": f"HTTP {status_img}",
                    "schwere": "kritisch", "alt_text": alt,
                    "dateigroesse_kb": dateigroesse_kb, "format": format_ext, "hinweis": ""
                })
                time.sleep(0.1); continue

            # ── Informative Checks (schwere = "info") ──────────────────────
            hinweise = []

            if not alt:
                hinweise.append("kein alt-Text")

            if not width or not height:
                hinweise.append("fehlendes width/height (CLS-Risiko)")

            if loading != "lazy":
                hinweise.append("kein loading=lazy")

            if format_ext in ("jpg","jpeg","png","gif","bmp","tiff"):
                hinweise.append(f"Format {format_ext.upper()} – WebP/AVIF wäre besser")

            if dateigroesse_kb and dateigroesse_kb > 300:
                hinweise.append(f"groß ({dateigroesse_kb} KB > 300 KB)")

            if hinweise:
                res["missing_images"].append({
                    "seite": url, "src": abs_src,
                    "problem": " | ".join(hinweise),
                    "schwere": "info", "alt_text": alt,
                    "dateigroesse_kb": dateigroesse_kb, "format": format_ext,
                    "hinweis": "Nur zur Information – kein kritisches Problem"
                })

            time.sleep(0.1)

    res["duplicate_titles"] = {k: v for k,v in res["duplicate_titles"].items() if len(v)>1}
    res["duplicate_descs"]  = {k: v for k,v in res["duplicate_descs"].items() if len(v)>1}
    res["total_pages_crawled"] = len(visited)
    return res


# ── CSV-Export ────────────────────────────────────────────────────────────────

def export_csvs(crawl, domain):
    """
    Exportiert alle Listen mit > CSV_THRESHOLD Einträgen als eigene CSV-Datei.
    Gibt ein Dict {kategorie: dateiname} zurück.
    """
    date = datetime.now().strftime("%Y%m%d")
    d = domain.replace("/","_").replace(":","")
    files = {}

    def maybe_csv(key, rows, fieldnames, label):
        if len(rows) > CSV_THRESHOLD:
            fname = f"{d}_{date}_{key}.csv"
            write_csv(fname, rows, fieldnames)
            files[label] = (fname, len(rows))

    maybe_csv("broken_links", crawl["broken_links"],
              ["url","status","gefunden_auf"], "Broken Links")

    maybe_csv("broken_images",
              [r for r in crawl["missing_images"] if r.get("schwere") == "kritisch"],
              ["seite","src","problem","dateigroesse_kb","format","alt_text"],
              "Defekte Bilder")

    maybe_csv("image_optimierung",
              [r for r in crawl["missing_images"] if r.get("schwere") == "info"],
              ["seite","src","problem","dateigroesse_kb","format","alt_text","hinweis"],
              "Bild-Optimierungspotenzial")

    maybe_csv("slow_pages", crawl["slow_pages"],
              ["url","ladezeit_ms"], "Langsame Seiten")

    maybe_csv("missing_meta", crawl["missing_meta"],
              ["url","fehlt"], "Fehlende Meta-Tags")

    maybe_csv("missing_h1", crawl["missing_h1"],
              ["url"], "Seiten ohne H1")

    maybe_csv("multiple_h1", crawl["multiple_h1"],
              ["url","anzahl_h1","texte"], "Mehrere H1-Tags")

    maybe_csv("missing_canonical", crawl["missing_canonical"],
              ["url"], "Fehlende Canonical-Tags")

    maybe_csv("missing_schema", crawl["missing_schema"],
              ["url"], "Fehlendes Schema-Markup")

    maybe_csv("missing_og", crawl["missing_og_tags"],
              ["url","fehlt"], "Fehlende OG-Tags")

    maybe_csv("mixed_content", crawl["mixed_content"],
              ["seite","ressource","typ"], "Mixed Content")

    maybe_csv("redirect_chains", crawl["redirect_chains"],
              ["url","final_url","hops","zwischenstopps"], "Redirect-Chains")

    maybe_csv("noindex_pages", crawl["noindex_pages"],
              ["url","robots_content"], "noindex-Seiten")

    # Duplikate flach aufbereiten
    dup_title_rows = [{"titel": t, "anzahl": len(urls), "urls": " | ".join(urls)} for t,urls in crawl["duplicate_titles"].items()]
    maybe_csv("duplicate_titles", dup_title_rows,
              ["titel","anzahl","urls"], "Doppelte Titles")

    dup_desc_rows = [{"beschreibung": d[:80], "anzahl": len(urls), "urls": " | ".join(urls)} for d,urls in crawl["duplicate_descs"].items()]
    maybe_csv("duplicate_descs", dup_desc_rows,
              ["beschreibung","anzahl","urls"], "Doppelte Descriptions")

    return files


# ── Claude-Analyse ────────────────────────────────────────────────────────────

def analyze_with_claude(crawl, ssl_r, headers_r, https_r, pagespeed_r, infra_r, target_url, csv_files):
    pages = crawl["pages"]
    load_times = [p["load_ms"] for p in pages.values() if p["load_ms"] > 0]

    summary = {
        "website": target_url,
        "crawl_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "pages_crawled": crawl["total_pages_crawled"],
        "performance": {
            "avg_load_ms": int(sum(load_times)/len(load_times)) if load_times else 0,
            "slow_pages_count": len(crawl["slow_pages"]),
            "slow_pages_sample": crawl["slow_pages"][:3],
            "pagespeed": pagespeed_r,
        },
        "ssl": ssl_r,
        "https_redirect": https_r,
        "security_headers": {"score": headers_r.get("score",0), "max": headers_r.get("max",6), "missing": headers_r.get("missing",[])},
        "mixed_content_count": len(crawl["mixed_content"]),
        "broken_links_count": len(crawl["broken_links"]),
        "broken_links_sample": crawl["broken_links"][:5],
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
        "images": {
            "broken_count":       len([i for i in crawl["missing_images"] if i.get("schwere") == "kritisch"]),
            "optimierung_count":  len([i for i in crawl["missing_images"] if i.get("schwere") == "info"]),
            "kein_alt_count":     len([i for i in crawl["missing_images"] if "kein alt-Text" in i.get("problem","")]),
            "falsches_format":    len([i for i in crawl["missing_images"] if "Format" in i.get("problem","")]),
            "zu_gross":           len([i for i in crawl["missing_images"] if "KB >" in i.get("problem","")]),
            "kein_lazy":          len([i for i in crawl["missing_images"] if "loading=lazy" in i.get("problem","")]),
            "kein_cls_attrs":     len([i for i in crawl["missing_images"] if "width/height" in i.get("problem","")]),
            "hinweis": "Optimierungen sind informativ, keine kritischen Probleme",
        },
        "infrastructure": infra_r,
        "csvs_erstellt": [f"{label} ({cnt} Einträge)" for label,(fname,cnt) in csv_files.items()],
    }

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    domain = urlparse(target_url).netloc

    csv_hinweis = ""
    if csv_files:
        csv_liste = "\n".join(f"• {label}: {cnt} Einträge" for label,(fname,cnt) in csv_files.items())
        csv_hinweis = f"\n\nFolgende Kategorien wurden als CSV in GitHub Artifacts gespeichert:\n{csv_liste}"

    prompt = f"""Du bist ein Website-Analyst. Erstelle einen kompakten Slack-Report auf Deutsch.

{json.dumps(summary, indent=2, ensure_ascii=False)}

Regeln:
- Security Headers = NUR kurze Info-Zeile, keine Kritisch-Einstufung
- Bei Kategorien mit CSV: nur Anzahl nennen, kein Aufzählen der URLs
- Kritisch = nur: Broken Links, SSL <14 Tage, HTTPS fehlt, noindex auf wichtigen Seiten
- Report MUSS unter 2500 Zeichen bleiben

Struktur:
*🔴/🟡/🟢 {domain} – Gesamtstatus*
Ein Satz.

*🚨 Kritisch*
• ...

*⚠️ Warnungen*
• ...

*📊 Performance*
• Ø Ladezeit: Xms | Langsamste Seiten: X über {SLOW_PAGE_MS}ms
• PageSpeed Mobile: X/100 | Desktop: X/100

*📝 SEO*
• Titles/Desc fehlen: X | H1 fehlt: X | Kein Schema: X | Kein Canonical: X

*🖼️ Bilder*
• Defekt (kritisch): X
• Optimierungspotenzial (nur Info): kein Alt-Text X | Format X | >300KB X | kein lazy X | kein width/height X

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
    return resp.content[0].text, summary, csv_hinweis


# ── Slack ─────────────────────────────────────────────────────────────────────

def send_to_slack(report_text, summary, csv_files, csv_hinweis, target_url):
    if not SLACK_WEBHOOK_URL:
        print("⚠️  Kein SLACK_WEBHOOK_URL – Report im Terminal:")
        print(report_text)
        return

    broken_count = summary["broken_links_count"]
    ssl_days     = summary["ssl"].get("days_remaining", 999)
    color = "#e53935" if (broken_count > 0 or ssl_days < 14) else \
            "#ff9800" if ssl_days < SSL_WARN_DAYS else "#2eb886"
    domain = urlparse(target_url).netloc

    # CSV-Block anhängen falls vorhanden
    artifacts_block = ""
    if csv_files:
        artifacts_block = (
            f"\n\n*📁 Detailreports als CSV verfügbar*\n"
            + "\n".join(f"• {label}: {cnt} Einträge" for label,(fname,cnt) in csv_files.items())
            + f"\n→ <{GITHUB_RUN_URL}|GitHub Actions → Artifacts öffnen>"
        )

    max_report = 2800 - len(artifacts_block)
    final_text = report_text[:max_report] + artifacts_block

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
                    f"🐢 {summary['performance']['slow_pages_count']} langsam  •  "
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

    bl = len(crawl_r["broken_links"])
    sl = len(crawl_r["slow_pages"])
    im = len(crawl_r["missing_images"])
    print(f"   {crawl_r['total_pages_crawled']} Seiten | {bl} Broken Links | {sl} langsam | {im} Bild-Probleme")

    print("📁 Exportiere CSVs...")
    csv_files = export_csvs(crawl_r, domain)
    if not csv_files:
        print("   (alle Listen unter Schwellenwert, keine CSVs nötig)")

    print("🤖 Claude...")
    report_text, summary, csv_hinweis = analyze_with_claude(
        crawl_r, ssl_r, headers_r, https_r, pagespeed_r, infra_r, target_url, csv_files)

    print("📤 Slack...")
    send_to_slack(report_text, summary, csv_files, csv_hinweis, target_url)

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

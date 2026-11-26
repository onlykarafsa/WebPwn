#!/usr/bin/env python3
"""WebPwn Sentinel 4.0 - single-file, scope-locked web assessment toolkit.

Only use against systems you own or are explicitly authorized to test.
Network methods are GET/HEAD only. No exploit execution, file reads, uploads,
credential attacks, destructive actions, proxying, or out-of-scope redirects.
Python 3.10+, standard library only.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import secrets
import ssl
import sys
import time
import unittest
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler

VERSION = "4.0.0"
UA = f"WebPwn-Sentinel/{VERSION} (+authorized-security-assessment)"
MAX_BODY_DEFAULT = 500_000


class ScopeError(ValueError):
    pass


def origin_of(url: str) -> str:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ScopeError("Yalnızca tam http:// veya https:// URL kabul edilir.")
    if p.username or p.password:
        raise ScopeError("URL içinde kullanıcı adı/şifre kullanılamaz.")
    try:
        port = p.port
    except ValueError as exc:
        raise ScopeError("URL portu geçersiz.") from exc
    host = p.hostname.lower().rstrip(".")
    if "*" in host or host.startswith(".") or host.endswith("."):
        raise ScopeError("Wildcard veya geçersiz host kabul edilmez; tam host yazılmalı.")
    default = 443 if p.scheme == "https" else 80
    authority = f"{host}:{port}" if port and port != default else host
    return f"{p.scheme}://{authority}"


@dataclass(frozen=True)
class Scope:
    origin: str
    max_requests: int = 80
    delay_ms: int = 150

    @classmethod
    def for_target(cls, target: str, max_requests: int, delay_ms: int) -> "Scope":
        origin = origin_of(target)
        if not 1 <= max_requests <= 500:
            raise ScopeError("İstek sınırı 1-500 arasında olmalı.")
        if not 0 <= delay_ms <= 5000:
            raise ScopeError("İstek aralığı 0-5000 ms arasında olmalı.")
        return cls(origin, max_requests, delay_ms)

    def check(self, url: str) -> None:
        if origin_of(url) != self.origin:
            raise ScopeError(f"Scope dışı hedef engellendi: {origin_of(url)}")


@dataclass
class ResponseData:
    status: int
    url: str
    headers: dict[str, str]
    body: str
    length: int
    elapsed_ms: float
    error: str = ""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SafeHTTP:
    """GET/HEAD-only HTTP client with strict origin, limits and TLS verification."""
    def __init__(self, scope: Scope, timeout: float = 8.0, max_body: int = MAX_BODY_DEFAULT):
        self.scope, self.timeout, self.max_body = scope, timeout, max_body
        self.count, self.last = 0, 0.0
        self.opener = build_opener(NoRedirect())

    def request(self, method: str, url: str, headers: dict[str, str] | None = None) -> ResponseData:
        method = method.upper()
        if method not in ("GET", "HEAD"):
            raise ValueError("Güvenlik sınırı: yalnızca GET ve HEAD kullanılabilir.")
        self.scope.check(url)
        if self.count >= self.scope.max_requests:
            return ResponseData(0, url, {}, "", 0, 0, "İstek bütçesi doldu.")
        wait = self.scope.delay_ms / 1000 - (time.monotonic() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.count += 1
        self.last = time.monotonic()
        current = url
        safe_headers = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
        for k, v in (headers or {}).items():
            key = k.strip()
            if not key or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                raise ValueError(f"Geçersiz header adı: {key!r}")
            if key.lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection"}:
                raise ValueError(f"Header değiştirilemez: {key}")
            if "\r" in v or "\n" in v:
                raise ValueError("Header değeri satır sonu içeremez.")
            safe_headers[key] = v
        started = time.monotonic()
        for _ in range(4):
            self.scope.check(current)
            req = Request(current, method=method, headers=safe_headers)
            try:
                with self.opener.open(req, timeout=self.timeout) as resp:
                    raw = b"" if method == "HEAD" else resp.read(self.max_body + 1)[:self.max_body]
                    charset = resp.headers.get_content_charset() or "utf-8"
                    body = raw.decode(charset, errors="replace")
                    return ResponseData(resp.status, resp.geturl(), {k.lower(): v for k, v in resp.headers.items()}, body,
                                        len(raw), round((time.monotonic()-started)*1000, 2))
            except HTTPError as exc:
                if exc.code in (301, 302, 303, 307, 308):
                    loc = exc.headers.get("Location")
                    if not loc:
                        return ResponseData(exc.code, current, {k.lower(): v for k,v in exc.headers.items()}, "", 0,
                                            round((time.monotonic()-started)*1000,2), "Yönlendirme Location içermiyor.")
                    nxt = urljoin(current, loc)
                    try:
                        self.scope.check(nxt)
                    except ScopeError as e:
                        return ResponseData(exc.code, current, {k.lower():v for k,v in exc.headers.items()}, "", 0,
                                            round((time.monotonic()-started)*1000,2), str(e))
                    current = nxt
                    continue
                raw = exc.read(self.max_body + 1)[:self.max_body]
                charset = exc.headers.get_content_charset() or "utf-8"
                return ResponseData(exc.code, current, {k.lower():v for k,v in exc.headers.items()},
                                    raw.decode(charset, errors="replace"), len(raw),
                                    round((time.monotonic()-started)*1000,2))
            except (URLError, TimeoutError, OSError, ssl.SSLError) as exc:
                return ResponseData(0, current, {}, "", 0, round((time.monotonic()-started)*1000,2), str(exc))
        return ResponseData(0, current, {}, "", 0, round((time.monotonic()-started)*1000,2), "Yönlendirme sınırı aşıldı.")


@dataclass
class Finding:
    title: str
    category: str
    severity: str
    status: str
    confidence: float
    url: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


@dataclass
class ScanReport:
    target: str
    started_at: str
    finished_at: str = ""
    request_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        if not any(f.title == finding.title and f.url == finding.url for f in self.findings):
            self.findings.append(finding)


def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:10000], b[:10000]).ratio()


def query_urls(base: str, body: str) -> list[str]:
    # Only same-origin links with query parameters are candidates.
    found = []
    for raw in re.findall(r'''(?:href|action)=["']([^"']+)["']''', body, re.I):
        u = urljoin(base, raw)
        try:
            if origin_of(u) == origin_of(base) and urlsplit(u).query:
                found.append(u)
        except ScopeError:
            pass
    return list(dict.fromkeys(found))[:8]


def scan_target(client: SafeHTTP, target: str, active_safe: bool = False) -> ScanReport:
    target = target.rstrip("/")
    client.scope.check(target)
    report = ScanReport(target, datetime.now(timezone.utc).isoformat())
    home = client.request("GET", target + "/")
    if home.error:
        report.notes.append("Ana sayfa isteği başarısız: " + home.error)
        report.request_count = client.count
        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report
    report.metadata = {"status": home.status, "content_type": home.headers.get("content-type", ""),
                       "server": home.headers.get("server", ""), "body_length": home.length,
                       "body_sha256": hashlib.sha256(home.body.encode()).hexdigest()}
    checks = [
        ("content-security-policy", "CSP başlığı görünmüyor", "medium", "İçeriğe uygun Content-Security-Policy tanımlayın."),
        ("x-content-type-options", "X-Content-Type-Options başlığı görünmüyor", "low", "X-Content-Type-Options: nosniff ekleyin."),
        ("referrer-policy", "Referrer-Policy başlığı görünmüyor", "low", "Uygun bir Referrer-Policy belirleyin."),
    ]
    for header, title, sev, rec in checks:
        if header not in home.headers:
            report.add(Finding(title, "security-header", sev, "potential", .80, target + "/",
                               f"Yanıtta {header} başlığı gözlenmedi.", {"header": header}, rec))
    set_cookie = home.headers.get("set-cookie", "").lower()
    if set_cookie:
        for attr in ("httponly", "secure", "samesite"):
            if attr not in set_cookie:
                report.add(Finding(f"Cookie {attr} niteliği eksik", "cookie", "medium" if attr != "samesite" else "low",
                                   "potential", .75, target + "/", f"Set-Cookie içinde {attr} gözlenmedi.",
                                   {"set_cookie_preview": set_cookie[:160]}, f"Oturum cookie'sine uygun {attr} niteliğini ekleyin."))
    # Control response: random nonexistent path prevents generic 200 fallback false positives.
    baseline_url = target + "/.__wpx_missing_" + secrets.token_hex(8)
    baseline = client.request("GET", baseline_url)
    candidates = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/openapi.json", "/swagger.json", "/health"]
    for path in candidates:
        if client.count >= client.scope.max_requests: break
        url = target + path
        resp = client.request("GET", url)
        generic = resp.status == baseline.status and similarity(resp.body, baseline.body) >= .90
        if resp.status == 200 and resp.length > 0 and not generic:
            report.add(Finding(f"Erişilebilir kaynak: {path}", "public-resource", "info", "confirmed", .90, url,
                               "Kaynak yolu HTTP 200 ve kontrol yanıtından farklı içerik döndürdü.",
                               {"status": resp.status, "length": resp.length, "content_type": resp.headers.get("content-type", "")},
                               "Kaynağın herkese açık olmasının tasarım gereği olup olmadığını kontrol edin."))
    if active_safe:
        for url in query_urls(target + "/", home.body):
            parts = urlsplit(url)
            params = list(dict.fromkeys(k for k, _ in parse_qsl(parts.query, keep_blank_values=True)))
            for param in params[:3]:
                if client.count >= client.scope.max_requests: break
                marker = "wpx" + secrets.token_hex(5)
                pairs = parse_qsl(parts.query, keep_blank_values=True)
                changed, done = [], False
                for k,v in pairs:
                    if k == param and not done: changed.append((k, marker)); done=True
                    else: changed.append((k,v))
                test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(changed), ""))
                response = client.request("GET", test_url)
                if marker in response.body:
                    report.add(Finding(f"Parametre yansıması: {param}", "input-reflection", "low", "potential", .55,
                                       url, "Benzersiz metin yanıt gövdesinde bulundu; XSS kanıtı değildir.",
                                       {"parameter": param, "marker": marker},
                                       "Yansıtılan verinin HTML/attribute/JS bağlamında güvenli kodlandığını doğrulayın."))
    report.request_count = client.count
    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


def save_report(report: ScanReport, prefix: str) -> tuple[str, str]:
    data = asdict(report)
    json_path = prefix + ".json"
    md_path = prefix + ".md"
    Path(json_path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [f"# WebPwn Sentinel {VERSION} raporu", "", f"- Hedef: `{report.target}`",
             f"- İstek: {report.request_count}", f"- Bulgu: {len(report.findings)}", "", "## Bulgular"]
    if not report.findings: lines.append("Bulgu kaydedilmedi.")
    for f in report.findings:
        lines += [f"### [{f.severity.upper()}] {f.title}", f"- Durum: `{f.status}` · Güven: `{f.confidence:.0%}`",
                  f"- URL: `{f.url}`", f"- Detay: {f.detail}", f"- Öneri: {f.recommendation}", ""]
    Path(md_path).write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def show_response(r: ResponseData, body_limit: int = 5000) -> None:
    print(f"\nHTTP {r.status or 'ERROR'} | {r.elapsed_ms:.1f} ms | {r.length} byte | {r.url}")
    if r.error: print("HATA:", r.error)
    for k,v in r.headers.items(): print(f"{k}: {v}")
    print("\n--- RESPONSE BODY (önizleme) ---")
    print(r.body[:body_limit] if r.body else "<boş>")
    if len(r.body) > body_limit: print(f"\n...[{len(r.body)-body_limit} karakter daha kesildi]")


def repeater(client: SafeHTTP, start_url: str) -> None:
    """Interactive same-origin GET/HEAD repeater; request history stays in memory."""
    client.scope.check(start_url)
    current_url, method, headers = start_url, "GET", {}
    history: list[tuple[str, str, dict[str,str], ResponseData]] = []
    print("\nWebPwn Repeater — yalnızca GET/HEAD; hedef origin kilitli.")
    print("Komutlar: send | url | method | header | headers | history | save | help | quit")
    print("İlk URL:", current_url)
    while True:
        try: cmd = input("\nrepeater> ").strip().lower()
        except (EOFError, KeyboardInterrupt): print(); break
        if cmd in ("quit", "q", "exit"): break
        if cmd == "help":
            print("url   : aynı origin içindeki yeni URL veya /path")
            print("method: GET ya da HEAD")
            print("header: Header-Name: value (Host/Content-Length gibi kritik header'lar kilitli)")
            print("headers: etkin özel header'ları göster | send: isteği gönder | save: son yanıt gövdesini kaydet")
            continue
        if cmd == "url":
            value = input("URL veya path: ").strip()
            candidate = urljoin(client.scope.origin + "/", value)
            try: client.scope.check(candidate); current_url = candidate
            except ScopeError as e: print("ENGELLENDİ:", e)
            continue
        if cmd == "method":
            value = input("GET/HEAD: ").strip().upper()
            if value in ("GET", "HEAD"): method = value
            else: print("Yalnızca GET veya HEAD.")
            continue
        if cmd == "header":
            line = input("Header-Name: value: ")
            if ":" not in line: print("Biçim hatalı."); continue
            k,v = line.split(":",1)
            try:
                # Validate header by applying the same validation before storing.
                if k.strip().lower() in {"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection"}:
                    raise ValueError("Bu header değiştirilemez.")
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", k.strip()) or "\r" in v or "\n" in v:
                    raise ValueError("Header biçimi geçersiz.")
                headers[k.strip()] = v.strip(); print("Header eklendi/değiştirildi.")
            except ValueError as e: print("ENGELLENDİ:", e)
            continue
        if cmd == "headers":
            print(json.dumps(headers, ensure_ascii=False, indent=2) if headers else "Özel header yok.")
            continue
        if cmd == "history":
            for i,(m,u,h,r) in enumerate(history,1): print(f"{i}. {m} {u} -> {r.status} ({r.length} byte)")
            continue
        if cmd == "save":
            if not history: print("Önce send çalıştır."); continue
            path = input("Dosya adı [response.txt]: ").strip() or "response.txt"
            Path(path).write_text(history[-1][3].body, encoding="utf-8")
            print("Yanıt gövdesi kaydedildi:", path)
            continue
        if cmd == "send":
            try:
                client.scope.check(current_url)
                response = client.request(method, current_url, headers)
                history.append((method, current_url, dict(headers), response))
                show_response(response)
                print(f"İstek bütçesi: {client.count}/{client.scope.max_requests}")
            except (ValueError, ScopeError) as e: print("İstek engellendi:", e)
            continue
        if cmd: print("Bilinmeyen komut. help yaz.")


# Local-only demonstration server.
class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/item?"):
            from urllib.parse import parse_qs
            value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            body = f"<html><h1>Demo item</h1><p>{value}</p><a href='/item?q=demo'>item</a></html>"
        elif self.path == "/robots.txt": body = "User-agent: *\nDisallow: /private\n"
        elif self.path == "/.well-known/security.txt": body = "Contact: mailto:security@example.invalid\n"
        elif self.path == "/": body = "<html><title>WebPwn demo</title><a href='/item?q=demo'>item</a></html>"
        else:
            raw = b"not found"
            self.send_response(404); self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        raw = body.encode(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def log_message(self, *_): pass


class SelfTests(unittest.TestCase):
    def test_scope_origin_lock(self):
        s = Scope.for_target("http://127.0.0.1:8000", 10, 0)
        s.check("http://127.0.0.1:8000/a")
        with self.assertRaises(ScopeError): s.check("http://localhost:8000/a")
    def test_wildcard_rejected(self):
        with self.assertRaises(ScopeError): origin_of("https://*.example.org")
    def test_unsafe_method_rejected(self):
        s = Scope.for_target("http://127.0.0.1", 10, 0); c = SafeHTTP(s)
        with self.assertRaises(ValueError): c.request("POST", "http://127.0.0.1/")
    def test_header_injection_rejected(self):
        s = Scope.for_target("http://127.0.0.1", 10, 0); c = SafeHTTP(s)
        with self.assertRaises(ValueError): c.request("GET", "http://127.0.0.1/", {"X-Test":"a\nb"})
    def test_similarity(self): self.assertGreater(similarity("same", "same"), .99)
    def test_redirect_scope_check(self):
        s = Scope.for_target("http://127.0.0.1", 10, 0)
        with self.assertRaises(ScopeError): s.check("http://example.com/")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"WebPwn Sentinel {VERSION} — tek dosyalı web güvenlik aracı")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "repeater"):
        p = sub.add_parser(name)
        p.add_argument("target", help="Tam URL; ör. http://127.0.0.1:8000")
        p.add_argument("--authorized", action="store_true", help="Bu hedefi test etmeye yetkili olduğunu onayla")
        p.add_argument("--max-requests", type=int, default=80)
        p.add_argument("--delay-ms", type=int, default=150)
        p.add_argument("--active-safe", action="store_true", help="İzinli scope içinde düşük etkili parametre yansıma kontrolü")
        p.add_argument("--out", default="webpwn-report")
    demo = sub.add_parser("demo", help="Yalnızca localhost eğitim sunucusu")
    demo.add_argument("--port", type=int, default=8000)
    sub.add_parser("self-test", help="Dahili güvenlik testlerini çalıştır")
    args = parser.parse_args(argv)
    if args.command == "self-test":
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelfTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    if args.command == "demo":
        if not 1024 <= args.port <= 65535: print("Port 1024-65535 aralığında olmalı."); return 2
        print(f"Demo yalnızca http://127.0.0.1:{args.port} üzerinde çalışıyor. Durdurmak için Ctrl+C.")
        HTTPServer(("127.0.0.1", args.port), DemoHandler).serve_forever(); return 0
    if not args.authorized:
        print("Güvenlik kilidi: devam etmek için --authorized ekle; yalnızca sahip olduğun/izinli hedeflerde kullan.", file=sys.stderr)
        return 2
    try:
        scope = Scope.for_target(args.target, args.max_requests, args.delay_ms)
        client = SafeHTTP(scope)
        if args.command == "repeater":
            repeater(client, args.target); return 0
        report = scan_target(client, args.target, args.active_safe)
        jp, mp = save_report(report, args.out)
        print(f"Tarama tamamlandı: {report.request_count} istek, {len(report.findings)} bulgu")
        print("JSON:", jp); print("Markdown:", mp)
        for f in report.findings: print(f"[{f.severity}/{f.status}] {f.title} — {f.url}")
        return 0
    except (ScopeError, ValueError) as exc:
        print("Hata:", exc, file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())

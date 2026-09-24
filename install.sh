#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IndexNow + Sitemap 极简站群自动化脚本（Debian 12 / 宝塔）

功能：
1. 读取 domain.txt（兼容 domian.txt）
2. 为 @ / www / m / 3g / wap 五类 host 检测可访问性
3. 在每个站点根目录部署统一 IndexNow 密钥文件
4. 扫描站点根目录第一层 PHP 文件，转换为同名 .html URL
5. 排除敏感 PHP 文件，不处理泛目录动态 URL
6. 为每个 host 生成独立、符合单 host 规则的 Sitemap
7. 按 host 分组向 IndexNow 发送 POST 请求
8. 支持 dry-run、单域名处理、运行锁、日志和 CSV 报告

仅使用 Python 标准库，兼容 Python 3.9+。
"""

from __future__ import annotations

import argparse
import configparser
import csv
import fcntl
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import socket
import ssl
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from xml.etree import ElementTree as ET

APP_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = APP_DIR / "config.ini"
VERSION = "1.0.0"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
PHP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*\.php$", re.IGNORECASE)


class NoRedirect(HTTPRedirectHandler):
    """禁止 urllib 自动跟随跳转，以便检查当前 host 的真实响应。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(frozen=True)
class HostTarget:
    base_domain: str
    prefix: str
    host: str
    scheme: str
    site_dir: Path

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host}"


@dataclass
class AppConfig:
    app_dir: Path
    site_root: Path
    domain_file: Path
    typo_domain_file: Path
    log_dir: Path
    state_dir: Path
    report_dir: Path
    backup_dir: Path
    endpoint: str
    timeout: float
    batch_size: int
    retries: int
    retry_delay: float
    user_agent: str
    prefixes: List[str]
    preferred_scheme: str
    allow_http_fallback: bool
    allow_redirect_status: bool
    verify_tls: bool
    scan_root_only: bool
    exclude_php: set[str]
    exclude_name_contains: List[str]
    sitemap_base_filename: str
    sitemap_prefix_template: str
    include_lastmod: bool
    file_owner: str
    file_group: str
    file_mode: int
    log_max_bytes: int
    log_backup_count: int
    verify_key_publicly: bool
    verify_homepage: bool
    verify_inner_pages: bool
    max_inner_pages: int
    request_pause: float


class RunLock:
    def __init__(self, path: Path):
        self.path = path
        self.fp = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fp = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(f"已有任务正在运行，锁文件：{self.path}") from exc
        self.fp.seek(0)
        self.fp.truncate()
        self.fp.write(f"pid={os.getpid()}\nstarted={datetime.now().isoformat()}\n")
        self.fp.flush()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fp is not None:
            try:
                fcntl.flock(self.fp.fileno(), fcntl.LOCK_UN)
            finally:
                self.fp.close()
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass


def parse_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def load_config(path: Path) -> AppConfig:
    cp = configparser.ConfigParser(interpolation=None)
    if not path.is_file():
        raise FileNotFoundError(f"配置文件不存在：{path}")
    cp.read(path, encoding="utf-8")

    app_dir = Path(cp.get("paths", "app_dir", fallback=str(APP_DIR))).resolve()
    site_root = Path(cp.get("paths", "site_root", fallback="/www/wwwroot")).resolve()
    domain_file = Path(cp.get("paths", "domain_file", fallback=str(app_dir / "domain.txt"))).resolve()
    typo_domain_file = Path(cp.get("paths", "typo_domain_file", fallback=str(app_dir / "domian.txt"))).resolve()
    log_dir = Path(cp.get("paths", "log_dir", fallback=str(app_dir / "logs"))).resolve()
    state_dir = Path(cp.get("paths", "state_dir", fallback=str(app_dir / "state"))).resolve()
    report_dir = Path(cp.get("paths", "report_dir", fallback=str(app_dir / "reports"))).resolve()
    backup_dir = Path(cp.get("paths", "backup_dir", fallback=str(app_dir / "backup"))).resolve()

    prefixes = split_csv(cp.get("hosts", "prefixes", fallback="@,www,m,3g,wap"))
    if "@" not in prefixes:
        prefixes.insert(0, "@")

    exclude_php = {x.lower() for x in split_csv(cp.get("php", "exclude", fallback="index.php,config.php,common.php,function.php,functions.php,database.php,db.php,connect.php,api.php,ajax.php,callback.php,cron.php,install.php,update.php,test.php,debug.php,error.php,404.php"))}
    exclude_contains = [x.lower() for x in split_csv(cp.get("php", "exclude_name_contains", fallback="config,common,function,database,connect,api,ajax,callback,cron,install,update,test,debug,error,404"))]

    mode_text = cp.get("files", "mode", fallback="0644").strip()
    file_mode = int(mode_text, 8)

    return AppConfig(
        app_dir=app_dir,
        site_root=site_root,
        domain_file=domain_file,
        typo_domain_file=typo_domain_file,
        log_dir=log_dir,
        state_dir=state_dir,
        report_dir=report_dir,
        backup_dir=backup_dir,
        endpoint=cp.get("indexnow", "endpoint", fallback="https://api.indexnow.org/indexnow").strip(),
        timeout=cp.getfloat("indexnow", "timeout", fallback=15.0),
        batch_size=max(1, min(cp.getint("indexnow", "batch_size", fallback=500), 10000)),
        retries=max(0, cp.getint("indexnow", "retries", fallback=2)),
        retry_delay=max(0.0, cp.getfloat("indexnow", "retry_delay", fallback=2.0)),
        user_agent=cp.get("http", "user_agent", fallback=f"IndexNowAuto/{VERSION}"),
        prefixes=prefixes,
        preferred_scheme=cp.get("hosts", "preferred_scheme", fallback="https").strip().lower(),
        allow_http_fallback=parse_bool(cp.get("hosts", "allow_http_fallback", fallback="true")),
        allow_redirect_status=parse_bool(cp.get("hosts", "allow_redirect_status", fallback="true")),
        verify_tls=parse_bool(cp.get("http", "verify_tls", fallback="true")),
        scan_root_only=parse_bool(cp.get("php", "scan_root_only", fallback="true")),
        exclude_php=exclude_php,
        exclude_name_contains=exclude_contains,
        sitemap_base_filename=cp.get("sitemap", "base_filename", fallback="sitemap.xml").strip(),
        sitemap_prefix_template=cp.get("sitemap", "prefix_filename_template", fallback="sitemap-{prefix}.xml").strip(),
        include_lastmod=parse_bool(cp.get("sitemap", "include_lastmod", fallback="true")),
        file_owner=cp.get("files", "owner", fallback="www").strip(),
        file_group=cp.get("files", "group", fallback="www").strip(),
        file_mode=file_mode,
        log_max_bytes=max(1024, cp.getint("logging", "max_bytes", fallback=10 * 1024 * 1024)),
        log_backup_count=max(1, cp.getint("logging", "backup_count", fallback=5)),
        verify_key_publicly=parse_bool(cp.get("checks", "verify_key_publicly", fallback="true")),
        verify_homepage=parse_bool(cp.get("checks", "verify_homepage", fallback="true")),
        verify_inner_pages=parse_bool(cp.get("checks", "verify_inner_pages", fallback="false")),
        max_inner_pages=max(0, cp.getint("php", "max_inner_pages", fallback=200)),
        request_pause=max(0.0, cp.getfloat("http", "request_pause", fallback=0.1)),
    )


def setup_logging(cfg: AppConfig, verbose: bool) -> logging.Logger:
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("indexnow_auto")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = RotatingFileHandler(
        cfg.log_dir / "run.log",
        maxBytes=cfg.log_max_bytes,
        backupCount=cfg.log_backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)
    return logger


def ensure_dirs(cfg: AppConfig) -> None:
    for path in (cfg.app_dir, cfg.log_dir, cfg.state_dir, cfg.report_dir, cfg.backup_dir):
        path.mkdir(parents=True, exist_ok=True)


def normalize_domain(raw: str) -> Optional[str]:
    value = raw.strip().lower()
    if not value or value.startswith("#"):
        return None
    if "#" in value:
        value = value.split("#", 1)[0].strip()
    if not value:
        return None
    if "://" in value:
        value = urlsplit(value).hostname or ""
    else:
        value = value.split("/", 1)[0]
        if ":" in value and not value.startswith("["):
            value = value.split(":", 1)[0]
    value = value.rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not DOMAIN_RE.fullmatch(value):
        return None
    return value


def read_domains(cfg: AppConfig, logger: logging.Logger) -> List[str]:
    path = cfg.domain_file
    if not path.is_file() and cfg.typo_domain_file.is_file():
        path = cfg.typo_domain_file
        logger.warning("未找到 domain.txt，已兼容读取拼写文件：%s", path)
    if not path.is_file():
        raise FileNotFoundError(f"域名文件不存在：{cfg.domain_file}（兼容文件也不存在：{cfg.typo_domain_file}）")

    result: List[str] = []
    seen = set()
    for lineno, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        domain = normalize_domain(raw)
        if domain is None:
            stripped = raw.strip()
            if stripped and not stripped.startswith("#"):
                logger.warning("忽略无效域名，第 %d 行：%s", lineno, stripped)
            continue
        if domain not in seen:
            seen.add(domain)
            result.append(domain)
    if not result:
        raise RuntimeError(f"域名文件没有有效域名：{path}")
    return result


def build_host(base_domain: str, prefix: str) -> str:
    return base_domain if prefix == "@" else f"{prefix}.{base_domain}"


def ssl_context(verify_tls: bool) -> ssl.SSLContext:
    if verify_tls:
        return ssl.create_default_context()
    return ssl._create_unverified_context()  # noqa: SLF001


def request_once(
    url: str,
    *,
    method: str,
    timeout: float,
    user_agent: str,
    verify_tls: bool,
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    max_body: int = 4096,
) -> Tuple[int, Dict[str, str], bytes]:
    hdrs = {"User-Agent": user_agent, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = Request(url, data=data, headers=hdrs, method=method)
    opener = build_opener(NoRedirect, HTTPSHandler(context=ssl_context(verify_tls)))
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_body) if method != "HEAD" else b""
            return int(resp.status), dict(resp.headers.items()), body
    except HTTPError as exc:
        body = exc.read(max_body) if method != "HEAD" else b""
        return int(exc.code), dict(exc.headers.items()), body


def probe_url(
    url: str,
    cfg: AppConfig,
    *,
    expected_body: Optional[str] = None,
) -> Tuple[bool, int, str]:
    methods = ["GET"] if expected_body is not None else ["HEAD", "GET"]
    last_error = ""
    for method in methods:
        try:
            status, headers, body = request_once(
                url,
                method=method,
                timeout=cfg.timeout,
                user_agent=cfg.user_agent,
                verify_tls=cfg.verify_tls,
                max_body=4096,
            )
            allowed = 200 <= status < 300 or (cfg.allow_redirect_status and 300 <= status < 400)
            if method == "HEAD" and status in {400, 403, 405, 501}:
                continue
            if not allowed:
                return False, status, f"HTTP {status}"
            if expected_body is not None:
                text = body.decode("utf-8", errors="replace").strip()
                if text != expected_body:
                    return False, status, "响应内容与密钥不一致"
            if 300 <= status < 400:
                location = headers.get("Location", "")
                return True, status, f"跳转：{location}" if location else "跳转"
            return True, status, "OK"
        except (URLError, socket.timeout, TimeoutError, ssl.SSLError, OSError) as exc:
            last_error = str(exc)
            continue
    return False, 0, last_error or "请求失败"


def detect_scheme(host: str, cfg: AppConfig) -> Tuple[Optional[str], str]:
    schemes = [cfg.preferred_scheme]
    if cfg.allow_http_fallback:
        fallback = "http" if cfg.preferred_scheme == "https" else "https"
        if fallback not in schemes:
            schemes.append(fallback)
    for scheme in schemes:
        ok, status, detail = probe_url(f"{scheme}://{host}/", cfg)
        if ok:
            return scheme, f"HTTP {status} {detail}"
    return None, "HTTPS/HTTP 均不可访问"


def load_or_create_key(cfg: AppConfig, logger: logging.Logger, dry_run: bool) -> str:
    key_store = cfg.state_dir / "indexnow.key"
    if key_store.is_file():
        key = key_store.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[A-Za-z0-9-]{8,128}", key):
            return key
        raise RuntimeError(f"现有密钥格式无效，请检查：{key_store}")
    key = secrets.token_hex(16)
    if dry_run:
        logger.info("[dry-run] 将生成新的 IndexNow 密钥：%s", key)
        return key
    atomic_write_text(key_store, key + "\n", mode=0o600)
    logger.info("已生成服务器统一 IndexNow 密钥：%s", key_store)
    return key


def safe_chown_chmod(path: Path, cfg: AppConfig, logger: logging.Logger) -> None:
    try:
        os.chmod(path, cfg.file_mode)
    except OSError as exc:
        logger.warning("设置权限失败 %s：%s", path, exc)
    try:
        shutil.chown(path, user=cfg.file_owner, group=cfg.file_group)
    except (LookupError, PermissionError, OSError) as exc:
        logger.warning("设置属主失败 %s（不影响 Nginx 读取时可忽略）：%s", path, exc)


def atomic_write_text(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fp:
            fp.write(content)
            fp.flush()
            os.fsync(fp.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def deploy_key(site_dir: Path, key: str, cfg: AppConfig, logger: logging.Logger, dry_run: bool) -> Path:
    target = site_dir / f"{key}.txt"
    desired = key + "\n"
    if target.is_file() and target.read_text(encoding="utf-8", errors="replace") == desired:
        return target
    if dry_run:
        logger.info("[dry-run] 将写入密钥文件：%s", target)
        return target
    atomic_write_text(target, desired, cfg.file_mode)
    safe_chown_chmod(target, cfg, logger)
    return target


def php_is_excluded(name: str, cfg: AppConfig) -> bool:
    lower = name.lower()
    if lower in cfg.exclude_php:
        return True
    stem = lower[:-4] if lower.endswith(".php") else lower
    return any(token and token in stem for token in cfg.exclude_name_contains)


def scan_php_pages(site_dir: Path, cfg: AppConfig, logger: logging.Logger) -> List[Tuple[str, date]]:
    pages: List[Tuple[str, date]] = []
    entries: Iterable[Path]
    if cfg.scan_root_only:
        entries = site_dir.iterdir()
    else:
        entries = site_dir.rglob("*.php")

    for path in sorted(entries, key=lambda p: p.name.lower()):
        if not path.is_file() or path.suffix.lower() != ".php":
            continue
        name = path.name
        if not PHP_NAME_RE.fullmatch(name):
            logger.debug("跳过不规则 PHP 文件名：%s", path)
            continue
        if name.lower() == "index.php" or php_is_excluded(name, cfg):
            logger.debug("排除 PHP 文件：%s", path)
            continue
        if cfg.scan_root_only:
            html_path = f"/{path.stem}.html"
        else:
            rel = path.relative_to(site_dir).with_suffix(".html")
            html_path = "/" + "/".join(quote(part) for part in rel.parts)
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).date()
        pages.append((html_path, mtime))
        if cfg.max_inner_pages and len(pages) >= cfg.max_inner_pages:
            logger.warning("站点 %s 固定内页达到上限 %d，后续 PHP 文件已跳过", site_dir.name, cfg.max_inner_pages)
            break
    return pages


def sitemap_filename(prefix: str, cfg: AppConfig) -> str:
    if prefix == "@":
        return cfg.sitemap_base_filename
    if not re.fullmatch(r"[A-Za-z0-9_-]+", prefix):
        raise ValueError(f"非法 host 前缀：{prefix}")
    return cfg.sitemap_prefix_template.format(prefix=prefix)


def build_urls(target: HostTarget, pages: Sequence[Tuple[str, date]]) -> List[Tuple[str, date]]:
    today = date.today()
    result = [(target.origin + "/", today)]
    for path, lastmod in pages:
        result.append((target.origin + path, lastmod))
    return result


def make_sitemap_xml(urls: Sequence[Tuple[str, date]], include_lastmod: bool) -> str:
    ET.register_namespace("", "http://www.sitemaps.org/schemas/sitemap/0.9")
    root = ET.Element("{http://www.sitemaps.org/schemas/sitemap/0.9}urlset")
    for url, lastmod in urls:
        node = ET.SubElement(root, "{http://www.sitemaps.org/schemas/sitemap/0.9}url")
        loc = ET.SubElement(node, "{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
        loc.text = url
        if include_lastmod:
            lm = ET.SubElement(node, "{http://www.sitemaps.org/schemas/sitemap/0.9}lastmod")
            lm.text = lastmod.isoformat()
    ET.indent(root, space="  ")
    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    # 生成后立即解析，作为本地 XML 完整性检查。
    ET.fromstring(xml_bytes)
    return xml_bytes.decode("utf-8") + "\n"


def write_sitemap(
    site_dir: Path,
    prefix: str,
    urls: Sequence[Tuple[str, date]],
    cfg: AppConfig,
    logger: logging.Logger,
    dry_run: bool,
) -> Path:
    filename = sitemap_filename(prefix, cfg)
    target = site_dir / filename
    xml = make_sitemap_xml(urls, cfg.include_lastmod)
    if dry_run:
        logger.info("[dry-run] 将生成 %s（%d 个 URL）", target, len(urls))
        return target
    atomic_write_text(target, xml, cfg.file_mode)
    safe_chown_chmod(target, cfg, logger)
    return target


def chunks(items: Sequence[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield list(items[i : i + size])


def post_indexnow(
    target: HostTarget,
    urls: Sequence[str],
    key: str,
    cfg: AppConfig,
    logger: logging.Logger,
    dry_run: bool,
) -> Tuple[bool, int, str]:
    if dry_run:
        logger.info("[dry-run] IndexNow host=%s URLs=%d", target.host, len(urls))
        return True, 0, "dry-run"

    key_location = f"{target.origin}/{key}.txt"
    final_status = 0
    final_detail = ""
    all_ok = True

    for batch_num, batch in enumerate(chunks(list(urls), cfg.batch_size), start=1):
        payload = {
            "host": target.host,
            "key": key,
            "keyLocation": key_location,
            "urlList": batch,
        }
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json, text/plain, */*"}

        status = 0
        detail = ""
        for attempt in range(cfg.retries + 1):
            try:
                status, _headers, response_body = request_once(
                    cfg.endpoint,
                    method="POST",
                    timeout=cfg.timeout,
                    user_agent=cfg.user_agent,
                    verify_tls=cfg.verify_tls,
                    data=body,
                    headers=headers,
                    max_body=8192,
                )
                detail = response_body.decode("utf-8", errors="replace").strip()[:500]
            except (URLError, socket.timeout, TimeoutError, ssl.SSLError, OSError) as exc:
                status = 0
                detail = str(exc)

            if status in {200, 202}:
                break
            retryable = status == 0 or status == 429 or 500 <= status < 600
            if not retryable or attempt >= cfg.retries:
                break
            delay = cfg.retry_delay * (2**attempt)
            logger.warning("IndexNow 重试 host=%s batch=%d status=%s，%.1f 秒后重试", target.host, batch_num, status or "网络错误", delay)
            time.sleep(delay)

        final_status, final_detail = status, detail
        if status not in {200, 202}:
            all_ok = False
            logger.error("IndexNow 失败 host=%s batch=%d URLs=%d HTTP=%s detail=%s", target.host, batch_num, len(batch), status or "NETWORK", detail or "-")
        else:
            logger.info("IndexNow 成功 host=%s batch=%d URLs=%d HTTP=%d", target.host, batch_num, len(batch), status)
        if cfg.request_pause:
            time.sleep(cfg.request_pause)

    return all_ok, final_status, final_detail


def append_report(report_path: Path, rows: Sequence[Dict[str, str]]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["time", "base_domain", "host", "scheme", "site_dir", "php_pages", "url_count", "sitemap", "key_check", "push_status", "http_status", "detail"]
    fd, temp_name = tempfile.mkstemp(prefix=".latest.", suffix=".csv.tmp", dir=str(report_path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8-sig") as fp:
            writer = csv.DictWriter(fp, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temp_path, report_path)
    finally:
        temp_path.unlink(missing_ok=True)


def process_domain(
    base_domain: str,
    cfg: AppConfig,
    key: str,
    logger: logging.Logger,
    dry_run: bool,
    no_push: bool,
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    site_dir = cfg.site_root / base_domain
    if not site_dir.is_dir():
        logger.error("站点目录不存在，跳过：%s", site_dir)
        rows.append({
            "time": datetime.now().isoformat(timespec="seconds"), "base_domain": base_domain, "host": "", "scheme": "", "site_dir": str(site_dir),
            "php_pages": "0", "url_count": "0", "sitemap": "", "key_check": "SKIP", "push_status": "SKIP", "http_status": "", "detail": "站点目录不存在",
        })
        return rows

    logger.info("处理基础域名：%s | 目录：%s", base_domain, site_dir)
    key_path = deploy_key(site_dir, key, cfg, logger, dry_run)
    pages = scan_php_pages(site_dir, cfg, logger)
    logger.info("固定 PHP 内页：%s 共 %d 个", base_domain, len(pages))

    for prefix in cfg.prefixes:
        host = build_host(base_domain, prefix)
        scheme: Optional[str]
        probe_detail = "未检测"
        if cfg.verify_homepage and not dry_run:
            scheme, probe_detail = detect_scheme(host, cfg)
        else:
            scheme = cfg.preferred_scheme
            probe_detail = "dry-run/关闭首页检测"

        if scheme is None:
            logger.warning("host 不可访问，跳过 Sitemap 和推送：%s", host)
            rows.append({
                "time": datetime.now().isoformat(timespec="seconds"), "base_domain": base_domain, "host": host, "scheme": "", "site_dir": str(site_dir),
                "php_pages": str(len(pages)), "url_count": "0", "sitemap": "", "key_check": "SKIP", "push_status": "SKIP", "http_status": "", "detail": probe_detail,
            })
            continue

        target = HostTarget(base_domain, prefix, host, scheme, site_dir)
        urls_with_dates = build_urls(target, pages)

        if cfg.verify_inner_pages and not dry_run:
            verified: List[Tuple[str, date]] = [urls_with_dates[0]]
            for url, lm in urls_with_dates[1:]:
                ok, status, detail = probe_url(url, cfg)
                if ok:
                    verified.append((url, lm))
                else:
                    logger.warning("固定内页不可访问，已跳过：%s (%s %s)", url, status, detail)
            urls_with_dates = verified

        sitemap_path = write_sitemap(site_dir, prefix, urls_with_dates, cfg, logger, dry_run)
        key_check = "未检查"
        if cfg.verify_key_publicly and not dry_run:
            key_url = f"{target.origin}/{key_path.name}"
            key_ok, key_status, key_detail = probe_url(key_url, cfg, expected_body=key)
            key_check = f"HTTP {key_status} {key_detail}" if key_status else key_detail
            if not key_ok:
                logger.error("密钥公网验证失败，停止该 host 推送：%s | %s", key_url, key_check)
                rows.append({
                    "time": datetime.now().isoformat(timespec="seconds"), "base_domain": base_domain, "host": host, "scheme": scheme, "site_dir": str(site_dir),
                    "php_pages": str(len(pages)), "url_count": str(len(urls_with_dates)), "sitemap": str(sitemap_path), "key_check": key_check,
                    "push_status": "SKIP", "http_status": str(key_status or ""), "detail": "密钥公网验证失败",
                })
                continue
        elif dry_run:
            key_check = "dry-run"

        url_list = [url for url, _lastmod in urls_with_dates]
        if no_push:
            push_ok, status, detail = True, 0, "--no-push"
            push_status = "NO_PUSH"
        else:
            push_ok, status, detail = post_indexnow(target, url_list, key, cfg, logger, dry_run)
            push_status = "SUCCESS" if push_ok else "FAILED"

        rows.append({
            "time": datetime.now().isoformat(timespec="seconds"), "base_domain": base_domain, "host": host, "scheme": scheme, "site_dir": str(site_dir),
            "php_pages": str(len(pages)), "url_count": str(len(url_list)), "sitemap": str(sitemap_path), "key_check": key_check,
            "push_status": push_status, "http_status": str(status or ""), "detail": (detail or probe_detail)[:500],
        })
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="批量生成 Sitemap 并向 IndexNow 推送固定页面")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="配置文件路径")
    parser.add_argument("--domain", help="只处理一个基础域名")
    parser.add_argument("--dry-run", action="store_true", help="演练模式：不写站点文件、不发送请求")
    parser.add_argument("--no-push", action="store_true", help="只生成密钥和 Sitemap，不发送 IndexNow")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        cfg = load_config(Path(args.config).resolve())
        ensure_dirs(cfg)
        logger = setup_logging(cfg, args.verbose)
        logger.info("IndexNow Auto %s 启动 | dry_run=%s no_push=%s", VERSION, args.dry_run, args.no_push)

        lock_path = cfg.state_dir / "run.lock"
        with RunLock(lock_path):
            domains = read_domains(cfg, logger)
            if args.domain:
                requested = normalize_domain(args.domain)
                if not requested:
                    raise RuntimeError(f"--domain 参数无效：{args.domain}")
                domains = [requested]

            key = load_or_create_key(cfg, logger, args.dry_run)
            all_rows: List[Dict[str, str]] = []
            for domain in domains:
                try:
                    all_rows.extend(process_domain(domain, cfg, key, logger, args.dry_run, args.no_push))
                except Exception:
                    logger.exception("处理域名异常：%s", domain)
                    all_rows.append({
                        "time": datetime.now().isoformat(timespec="seconds"), "base_domain": domain, "host": "", "scheme": "", "site_dir": str(cfg.site_root / domain),
                        "php_pages": "0", "url_count": "0", "sitemap": "", "key_check": "ERROR", "push_status": "ERROR", "http_status": "", "detail": "处理异常，查看 run.log",
                    })

            report = cfg.report_dir / "latest.csv"
            append_report(report, all_rows)
            successes = sum(1 for row in all_rows if row["push_status"] in {"SUCCESS", "NO_PUSH"})
            failures = sum(1 for row in all_rows if row["push_status"] in {"FAILED", "ERROR"})
            skips = sum(1 for row in all_rows if row["push_status"] == "SKIP")
            logger.info("任务完成：记录=%d 成功=%d 失败=%d 跳过=%d 报告=%s", len(all_rows), successes, failures, skips, report)
            return 1 if failures else 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

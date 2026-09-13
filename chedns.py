# -*- coding: utf-8 -*-
"""
CheDNS — локальный DNS-сервер с веб-интерфейсом.
Версия 1.2b: авторизация, HTTPS, импорт блок-листов, wildcard, логи в файл.

Создано Che1lVK Чеилом · https://чеил.рф · https://vkvideo.ru/@che1lvk
"""
import json
import logging
import logging.handlers
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from functools import wraps

from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver
from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, send_file, Response,
)
from werkzeug.security import generate_password_hash, check_password_hash

APP_NAME = "CheDNS"
VERSION = "1.2b"
AUTHOR = "Che1lVK Чеил"
AUTHOR_URL = "https://чеил.рф"
AUTHOR_VK = "https://vkvideo.ru/@che1lvk"


# ============================================================
#  ANSI цвета
# ============================================================
def enable_ansi():
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"


# ============================================================
#  Пути
# ============================================================
def get_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_templates_dir():
    if getattr(sys, "frozen", False):
        external = os.path.join(os.path.dirname(sys.executable), "templates")
        if os.path.isdir(external):
            return external
        internal = os.path.join(getattr(sys, "_MEIPASS", ""), "templates")
        if os.path.isdir(internal):
            return internal
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


BASE_DIR = get_base_dir()
CONFIG_FILE = os.path.join(BASE_DIR, "chedns_config.json")
CERTS_DIR = os.path.join(BASE_DIR, "certs")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
BACKUPS_DIR = os.path.join(BASE_DIR, "backups")

for d in (CERTS_DIR, LOGS_DIR, BACKUPS_DIR):
    os.makedirs(d, exist_ok=True)

# ============================================================
#  Конфиг
# ============================================================
DEFAULT_CONFIG = {
    "records": {},
    "blocked": [],
    "internet_enabled": True,
    "upstream_dns": "8.8.8.8",
    "listen_ip": "0.0.0.0",
    "dns_port": 53,
    "web_port": 8080,
    "https_enabled": True,
    "auth_enabled": True,
    "username": "admin",
    "password_hash": generate_password_hash("admin"),
    "default_password": True,
    "session_lifetime_hours": 24,
    "secret_key": secrets.token_hex(32),
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"{C.YELLOW}[CONFIG]{C.RESET} Ошибка чтения: {e}")
        cfg = dict(DEFAULT_CONFIG)
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg


def save_config(cfg):
    # Бэкап старого конфига перед перезаписью
    if os.path.exists(CONFIG_FILE):
        try:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = os.path.join(BACKUPS_DIR, f"chedns_config_{stamp}.json")
            with open(CONFIG_FILE, "r", encoding="utf-8") as src:
                data = src.read()
            with open(backup, "w", encoding="utf-8") as dst:
                dst.write(data)
            # Оставляем только 5 последних бэкапов
            backups = sorted([
                os.path.join(BACKUPS_DIR, f)
                for f in os.listdir(BACKUPS_DIR)
                if f.startswith("chedns_config_") and f.endswith(".json")
            ])
            for old in backups[:-5]:
                try:
                    os.remove(old)
                except Exception:
                    pass
        except Exception as e:
            print(f"{C.YELLOW}[CONFIG]{C.RESET} Не удалось создать бэкап: {e}")

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


config = load_config()
config_lock = threading.Lock()
START_TIME = time.time()


# ============================================================
#  Логирование в файл с ротацией
# ============================================================
def setup_file_logger():
    logger = logging.getLogger("chedns")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger
    handler = logging.handlers.RotatingFileHandler(
        os.path.join(LOGS_DIR, "chedns.log"),
        maxBytes=5 * 1024 * 1024,  # 5 МБ
        backupCount=5,
        encoding="utf-8",
    )
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    return logger


file_logger = setup_file_logger()


# ============================================================
#  Статистика и логи в памяти
# ============================================================
stats = {
    "total": 0,
    "local": 0,
    "forward": 0,
    "blocked": 0,
    "denied": 0,
}
stats_lock = threading.Lock()
recent_logs = deque(maxlen=500)
logs_lock = threading.Lock()


def add_log(kind, qname, qtype, client="?", extra=""):
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "kind": kind,
        "name": qname,
        "type": qtype,
        "client": client,
        "extra": extra,
    }
    with logs_lock:
        recent_logs.append(entry)
    with stats_lock:
        stats["total"] += 1
        key = {"LOCAL": "local", "FORWARD": "forward",
               "BLOCK": "blocked", "DENY": "denied"}.get(kind)
        if key:
            stats[key] += 1

    file_logger.info(
        f"{kind:8s} | {client:20s} | {qname} ({qtype}) {extra}"
    )


# ============================================================
#  Красивый вывод в консоль
# ============================================================
def log_dns_query(client, qname, qtype, kind, extra=""):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    kind_colors = {
        "FORWARD": (C.CYAN, "[FORWARD]"),
        "LOCAL":   (C.GREEN, "[LOCAL]  "),
        "BLOCK":   (C.RED,   "[BLOCK]  "),
        "DENY":    (C.YELLOW, "[DENY]   "),
    }
    color, badge = kind_colors.get(kind, (C.WHITE, f"[{kind}]"))

    if ":" in client:
        client_ip, client_port = client.rsplit(":", 1)
    else:
        client_ip, client_port = client, "?"

    if kind == "LOCAL":
        answer = f"{C.GREEN}-> {extra}{C.RESET}"
    elif kind == "FORWARD":
        answer = f"{C.CYAN}-> upstream {extra}{C.RESET}"
    elif kind == "BLOCK":
        answer = f"{C.RED}заблокировано (NXDOMAIN){C.RESET}"
    elif kind == "DENY":
        answer = f"{C.YELLOW}интернет выключен (NXDOMAIN){C.RESET}"
    else:
        answer = extra

    print()
    print(f"{C.GRAY}─────────────────────────────────────────────────────{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}[DNS запрос]{C.RESET} {C.GRAY}[{now}]{C.RESET}")
    print(f"  {C.GRAY}Отправитель:{C.RESET}  {C.MAGENTA}{client_ip}{C.GRAY}:{client_port}{C.RESET}")
    print(f"  {C.GRAY}Домен:{C.RESET}        {C.WHITE}{qname}{C.RESET} {C.GRAY}({qtype}){C.RESET}")
    print(f"  {C.GRAY}Обработка:{C.RESET}    {color}{badge}{C.RESET} {answer}")
    print(f"{C.GRAY}─────────────────────────────────────────────────────{C.RESET}")


# ============================================================
#  Wildcard-проверка блокировки
# ============================================================
def is_blocked(qname, blocked_list):
    """Возвращает True, если домен заблокирован (с учётом поддоменов)."""
    qname = qname.lower()
    for b in blocked_list:
        b = b.lower().lstrip(".")
        if qname == b or qname.endswith("." + b):
            return True
    return False


def find_local_record(qname, records):
    """
    Ищет запись для домена с учётом wildcard.
    Возвращает (ip, matched_domain) или (None, None).
    Приоритет: точная запись > wildcard.
    """
    qname = qname.lower()
    # Точное совпадение
    if qname in records:
        return records[qname], qname
    # Wildcard: *.example.local
    for pattern, ip in records.items():
        p = pattern.lower()
        if p.startswith("*."):
            base = p[2:]  # example.local
            if qname.endswith("." + base) and qname != base:
                return ip, pattern
    return None, None


# ============================================================
#  DNS Resolver
# ============================================================
class CheDNSResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]

        try:
            client = f"{handler.client_address[0]}:{handler.client_address[1]}"
        except Exception:
            client = "unknown:0"

        if qtype == "PTR" or qname.endswith(".in-addr.arpa"):
            reply.header.rcode = 3
            return reply

        with config_lock:
            records = dict(config["records"])
            blocked = list(config["blocked"])
            internet_enabled = config["internet_enabled"]
            upstream = config["upstream_dns"]

        # 1) Блокировка
        if is_blocked(qname, blocked):
            reply.header.rcode = 3
            log_dns_query(client, qname, qtype, "BLOCK")
            add_log("BLOCK", qname, qtype, client)
            return reply

        # 2) Локальные записи (A + wildcard)
        if qtype == "A":
            ip, matched = find_local_record(qname, records)
            if ip:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))
                tag = ip if matched == qname else f"{ip} (wildcard {matched})"
                log_dns_query(client, qname, qtype, "LOCAL", tag)
                add_log("LOCAL", qname, qtype, client, ip)
                return reply

        # 3) Форвард
        if internet_enabled and qtype in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "HTTPS", "SVCB"):
            try:
                proxy = DNSRecord.question(qname, qtype)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(proxy.pack(), (upstream, 53))
                data, _ = sock.recvfrom(4096)
                sock.close()
                proxied = DNSRecord.parse(data)
                for rr in proxied.rr:
                    reply.add_answer(rr)
                for rr in proxied.auth:
                    reply.add_auth(rr)
                log_dns_query(client, qname, qtype, "FORWARD", upstream)
                add_log("FORWARD", qname, qtype, client, upstream)
                return reply
            except Exception as e:
                log_dns_query(client, qname, qtype, "FORWARD", f"ошибка: {e}")
                add_log("FORWARD", qname, qtype, client, f"error")
                reply.header.rcode = 2
                return reply

        # 4) DENY
        log_dns_query(client, qname, qtype, "DENY")
        add_log("DENY", qname, qtype, client)
        reply.header.rcode = 3
        return reply


# ============================================================
#  Проверка порта 53
# ============================================================
def check_port_53():
    """Проверяет, свободен ли порт 53. Возвращает (True, '') или (False, 'сообщение')."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 53))
        s.close()
        return True, ""
    except OSError as e:
        msg = f"Порт 53 занят: {e}"
        # Попытка понять, кто держит
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "UDP"],
                capture_output=True, text=True, timeout=5,
            )
            lines = [l for l in result.stdout.splitlines() if ":53 " in l]
            if lines:
                msg += "\n\nКто держит порт:\n"
                for l in lines[:5]:
                    msg += f"  {l.strip()}\n"
            msg += (
                '\n\nЧасто порт держит служба "Internet Connection Sharing (ICS)".\n'
                "Останови её в admin-cmd:\n"
                '  net stop "Internet Connection Sharing (ICS)"'
            )
        except Exception:
            pass
        return False, msg


# ============================================================
#  HTTPS: генерация самоподписанного сертификата
# ============================================================
def generate_self_signed_cert():
    """Генерирует самоподписанный сертификат в CERTS_DIR. Возвращает (cert_path, key_path)."""
    cert_path = os.path.join(CERTS_DIR, "chedns.crt")
    key_path = os.path.join(CERTS_DIR, "chedns.key")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print(f"{C.YELLOW}[HTTPS]{C.RESET} Модуль cryptography не установлен.")
        print(f"{C.YELLOW}       {C.RESET} Установи: python -m pip install cryptography")
        print(f"{C.YELLOW}       {C.RESET} HTTPS будет отключён.")
        return None, None

    try:
        print(f"{C.CYAN}[HTTPS]{C.RESET} Генерирую самоподписанный сертификат...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CheDNS"),
            x509.NameAttribute(NameOID.COMMON_NAME, get_local_ip()),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(__import__("ipaddress").ip_address(get_local_ip())),
                    x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"{C.GREEN}[HTTPS]{C.RESET} Сертификат создан: {cert_path}")
        return cert_path, key_path
    except Exception as e:
        print(f"{C.RED}[HTTPS]{C.RESET} Ошибка генерации сертификата: {e}")
        return None, None


# ============================================================
#  Flask
# ============================================================
app = Flask(__name__, template_folder=get_templates_dir())
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
app.secret_key = config["secret_key"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=config["session_lifetime_hours"])


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ============================================================
#  Авторизация
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not config.get("auth_enabled", True):
            return f(*args, **kwargs)
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Требуется авторизация", "auth": False}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if not config.get("auth_enabled", True):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        data = request.form if request.form else (request.json or {})
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        with config_lock:
            stored_user = config.get("username", "admin")
            stored_hash = config.get("password_hash", "")

        if username == stored_user and check_password_hash(stored_hash, password):
            session.permanent = True
            session["logged_in"] = True
            session["username"] = username
            session["login_time"] = time.time()
            file_logger.info(f"AUTH | Успешный вход: {username}")
            if config.get("default_password"):
                return redirect(url_for("index", force_password_change=1))
            return redirect(url_for("index"))
        else:
            file_logger.warning(f"AUTH | Неудачная попытка входа: {username}")
            error = "Неверный логин или пароль"

    return render_template("login.html", error=error, version=VERSION)


@app.route("/logout")
def logout_page():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/api/change_password", methods=["POST"])
@login_required
def api_change_password():
    data = request.json or {}
    old_pw = data.get("old_password") or ""
    new_pw = data.get("new_password") or ""
    new_pw2 = data.get("new_password2") or ""

    if len(new_pw) < 6:
        return jsonify({"ok": False, "error": "Пароль минимум 6 символов"}), 400
    if new_pw != new_pw2:
        return jsonify({"ok": False, "error": "Пароли не совпадают"}), 400

    with config_lock:
        if not check_password_hash(config["password_hash"], old_pw):
            return jsonify({"ok": False, "error": "Неверный текущий пароль"}), 400
        config["password_hash"] = generate_password_hash(new_pw)
        config["default_password"] = False
        save_config(config)

    file_logger.info("AUTH | Пароль изменён")
    return jsonify({"ok": True})


# ============================================================
#  Основные маршруты
# ============================================================
@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        local_ip=get_local_ip(),
        version=VERSION,
        default_password=config.get("default_password", True),
        auth_enabled=config.get("auth_enabled", True),
        username=session.get("username", "admin"),
    )


@app.route("/favicon.ico")
def favicon():
    from flask import send_from_directory
    return send_from_directory(
        app.template_folder, "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.route("/api/health")
def api_health():
    return jsonify({
        "ok": True,
        "version": VERSION,
        "uptime": int(time.time() - START_TIME),
        "local_ip": get_local_ip(),
        "auth_required": config.get("auth_enabled", True),
    })


@app.route("/api/config", methods=["GET"])
@login_required
def api_get_config():
    with config_lock:
        return jsonify({
            "records": config["records"],
            "blocked": config["blocked"],
            "internet_enabled": config["internet_enabled"],
            "upstream_dns": config["upstream_dns"],
            "dns_port": config["dns_port"],
            "web_port": config["web_port"],
            "https_enabled": config.get("https_enabled", True),
            "auth_enabled": config.get("auth_enabled", True),
            "username": config.get("username", "admin"),
            "default_password": config.get("default_password", True),
        })


# ---------- Записи ----------
@app.route("/api/record", methods=["POST"])
@login_required
def api_add_record():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower().rstrip(".")
    ip = (data.get("ip") or "").strip()
    if not domain or not ip:
        return jsonify({"ok": False, "error": "Заполните домен и IP"}), 400

    is_wildcard = domain.startswith("*.")
    check_domain = domain[2:] if is_wildcard else domain
    if not check_domain:
        return jsonify({"ok": False, "error": "Некорректный домен"}), 400

    try:
        socket.inet_aton(ip)
    except OSError:
        return jsonify({"ok": False, "error": "Некорректный IP"}), 400

    with config_lock:
        config["records"][domain] = ip
        save_config(config)
    file_logger.info(f"RECORD | Добавлено: {domain} -> {ip}")
    return jsonify({"ok": True})


@app.route("/api/record", methods=["DELETE"])
@login_required
def api_del_record():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower().rstrip(".")
    with config_lock:
        if domain in config["records"]:
            del config["records"][domain]
            save_config(config)
            file_logger.info(f"RECORD | Удалено: {domain}")
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Не найдено"}), 404


# ---------- Блокировки ----------
@app.route("/api/block", methods=["POST"])
@login_required
def api_add_block():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower().lstrip(".").rstrip(".")
    if not domain:
        return jsonify({"ok": False, "error": "Укажите домен"}), 400
    with config_lock:
        if domain not in config["blocked"]:
            config["blocked"].append(domain)
            save_config(config)
    file_logger.info(f"BLOCK | Добавлено: {domain}")
    return jsonify({"ok": True})


@app.route("/api/block", methods=["DELETE"])
@login_required
def api_del_block():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower().lstrip(".").rstrip(".")
    with config_lock:
        if domain in config["blocked"]:
            config["blocked"].remove(domain)
            save_config(config)
            file_logger.info(f"BLOCK | Удалено: {domain}")
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Не найдено"}), 404


@app.route("/api/import_blocks", methods=["POST"])
@login_required
def api_import_blocks():
    """Импорт блок-листов из текста (AdBlock / hosts)."""
    data = request.json or {}
    text = data.get("text") or ""
    if not text.strip():
        return jsonify({"ok": False, "error": "Пустой список"}), 400

    new_domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith("!") or line.startswith("["):
            continue

        # hosts-формат: "0.0.0.0 example.com" или "127.0.0.1 example.com"
        parts = line.split()
        if len(parts) >= 2 and (parts[0].startswith("0.") or parts[0].startswith("127.")):
            domain = parts[1].strip().lower().rstrip(".")
            if domain and domain != "localhost":
                new_domains.add(domain)
            continue

        # AdBlock-формат: "||example.com^" или "example.com"
        domain = line
        # Убираем || в начале
        if domain.startswith("||"):
            domain = domain[2:]
        # Убираем ^ и всё после
        for ch in ("^", "$", "/", "|"):
            if ch in domain:
                domain = domain.split(ch)[0]
        domain = domain.strip().lower().rstrip(".")

        # Валидация: только латиница, цифры, точки, дефис
        if domain and all(c.isalnum() or c in ".-" for c in domain):
            new_domains.add(domain)

    if not new_domains:
        return jsonify({"ok": False, "error": "Не найдено валидных доменов"}), 400

    added = 0
    with config_lock:
        current = set(config["blocked"])
        for d in new_domains:
            if d not in current:
                config["blocked"].append(d)
                added += 1
        save_config(config)

    file_logger.info(f"IMPORT | Добавлено {added} доменов из списка")
    return jsonify({"ok": True, "added": added, "total": len(new_domains)})


# ---------- Интернет ----------
@app.route("/api/toggle_internet", methods=["POST"])
@login_required
def api_toggle_internet():
    with config_lock:
        config["internet_enabled"] = not config["internet_enabled"]
        save_config(config)
        state = config["internet_enabled"]
    return jsonify({"ok": True, "internet_enabled": state})


# ---------- Upstream ----------
@app.route("/api/upstream", methods=["POST"])
@login_required
def api_set_upstream():
    data = request.json or {}
    ip = (data.get("ip") or "").strip()
    try:
        socket.inet_aton(ip)
    except OSError:
        return jsonify({"ok": False, "error": "Некорректный IP"}), 400
    with config_lock:
        config["upstream_dns"] = ip
        save_config(config)
    return jsonify({"ok": True})


# ---------- Статистика ----------
@app.route("/api/stats")
@login_required
def api_stats():
    with stats_lock:
        s = dict(stats)
    s["uptime"] = int(time.time() - START_TIME)
    return jsonify(s)


@app.route("/api/logs")
@login_required
def api_logs():
    with logs_lock:
        return jsonify(list(recent_logs))


# ---------- Экспорт/импорт конфига ----------
@app.route("/api/export_config")
@login_required
def api_export_config():
    try:
        with open(CONFIG_FILE, "rb") as f:
            data = f.read()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return Response(
            data,
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="chedns_config_{stamp}.json"'
            },
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/import_config", methods=["POST"])
@login_required
def api_import_config():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "Файл не передан"}), 400
    file = request.files["file"]
    try:
        content = file.read().decode("utf-8")
        new_cfg = json.loads(content)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Ошибка чтения: {e}"}), 400

    # Валидация
    required_keys = ["records", "blocked", "internet_enabled", "upstream_dns"]
    for k in required_keys:
        if k not in new_cfg:
            return jsonify({"ok": False, "error": f"Нет ключа: {k}"}), 400
    if not isinstance(new_cfg.get("records"), dict):
        return jsonify({"ok": False, "error": "records должен быть объектом"}), 400
    if not isinstance(new_cfg.get("blocked"), list):
        return jsonify({"ok": False, "error": "blocked должен быть массивом"}), 400

    with config_lock:
        # Сохраняем только безопасные поля из импорта
        config["records"] = new_cfg["records"]
        config["blocked"] = new_cfg["blocked"]
        config["internet_enabled"] = bool(new_cfg.get("internet_enabled", True))
        config["upstream_dns"] = new_cfg.get("upstream_dns", "8.8.8.8")
        # Логин/пароль НЕ импортируем
        save_config(config)

    file_logger.info("CONFIG | Импорт конфига выполнен")
    return jsonify({"ok": True})


# ---------- Настройки безопасности ----------
@app.route("/api/settings", methods=["POST"])
@login_required
def api_update_settings():
    data = request.json or {}
    with config_lock:
        if "username" in data:
            u = (data["username"] or "").strip()
            if len(u) < 3:
                return jsonify({"ok": False, "error": "Логин минимум 3 символа"}), 400
            config["username"] = u
        if "auth_enabled" in data:
            config["auth_enabled"] = bool(data["auth_enabled"])
        save_config(config)
    return jsonify({"ok": True})


# ============================================================
#  Запуск
# ============================================================
def start_dns_server():
    resolver = CheDNSResolver()
    try:
        server = DNSServer(resolver, port=config["dns_port"], address=config["listen_ip"])
        server.start_thread()
        return server
    except PermissionError:
        print(f"{C.RED}[ОШИБКА]{C.RESET} Нет прав для открытия порта 53.")
        print(f"{C.GRAY}         Запусти CheDNS.exe от имени администратора.{C.RESET}")
        return None
    except OSError as e:
        print(f"{C.RED}[ОШИБКА]{C.RESET} Не удалось занять порт 53 — {e}")
        return None


def log_startup_banner(local_ip):
    print()
    print(f"{C.CYAN}{'═' * 62}{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  {C.BOLD}{C.WHITE}{APP_NAME} v{VERSION}{C.RESET} — Свой интернет · DNS сервер")
    print(f"{C.CYAN}║{C.RESET}  {C.GRAY}Создано {AUTHOR} · {AUTHOR_URL}{C.RESET}")
    print(f"{C.CYAN}{'═' * 62}{C.RESET}")
    print()
    print(f"  {C.GREEN}▶{C.RESET} Запуск DNS сервера с веб интерфейсом...")
    print()
    print(f"  {C.GREEN}✓{C.RESET} {C.BOLD}{C.GREEN}Успешно! Сервер запущен.{C.RESET}")
    print()

    scheme = "https" if config.get("https_enabled") else "http"
    print(f"{C.CYAN}{'─' * 62}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}Данные для подключения:{C.RESET}")
    print()
    print(f"  {C.GRAY}DNS сервер:{C.RESET}")
    print(f"    {C.BOLD}{C.CYAN}{local_ip}{C.RESET}  {C.GRAY}(порт {config['dns_port']}){C.RESET}")
    print()
    print(f"  {C.GRAY}Веб-интерфейс:{C.RESET}")
    print(f"    {C.BOLD}{C.CYAN}{scheme}://{local_ip}:{config['web_port']}{C.RESET}")
    if config.get("https_enabled"):
        print(f"    {C.YELLOW}⚠ Сертификат самоподписанный — браузер предупредит{C.RESET}")
    print()
    if config.get("default_password"):
        print(f"  {C.RED}{C.BOLD}⚠ Стоит пароль по умолчанию admin/admin!{C.RESET}")
        print(f"  {C.RED}   Смени его при первом входе в панель!{C.RESET}")
        print()
    print(f"{C.CYAN}{'─' * 62}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}Логи сервера:{C.RESET}")
    print(f"  {C.GRAY}(Ctrl+C для остановки сервера){C.RESET}")


def main():
    enable_ansi()
    local_ip = get_local_ip()

    # Проверка порта 53
    ok, err = check_port_53()
    if not ok:
        print(f"{C.RED}{'═' * 62}{C.RESET}")
        print(f"{C.RED}  ОШИБКА: не удалось занять порт 53{C.RESET}")
        print(f"{C.RED}{'═' * 62}{C.RESET}")
        print(err)
        print()
        print(f"{C.YELLOW}  Сервер продолжит работу БЕЗ DNS (только веб-панель).{C.RESET}")
        print()

    log_startup_banner(local_ip)

    dns_server = start_dns_server()

    # HTTPS
    cert_path, key_path = None, None
    if config.get("https_enabled"):
        cert_path, key_path = generate_self_signed_cert()
        if not cert_path:
            print(f"{C.YELLOW}[HTTPS]{C.RESET} HTTPS недоступен, работаю по HTTP")

    try:
        import logging as _l
        _l.getLogger("werkzeug").setLevel(_l.ERROR)

        ssl_ctx = None
        if cert_path and key_path:
            ssl_ctx = (cert_path, key_path)

        app.run(
            host="0.0.0.0",
            port=config["web_port"],
            debug=False,
            use_reloader=False,
            ssl_context=ssl_ctx,
        )
    except KeyboardInterrupt:
        pass
    finally:
        if dns_server:
            dns_server.stop()
        print()
        print(f"{C.CYAN}{'═' * 62}{C.RESET}")
        print(f"  {C.YELLOW}CheDNS остановлен. До встречи!{C.RESET}")
        print(f"{C.CYAN}{'═' * 62}{C.RESET}")


if __name__ == "__main__":
    main()

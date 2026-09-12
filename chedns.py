# -*- coding: utf-8 -*-
"""
CheDNS — локальный DNS-сервер с веб-интерфейсом.
Создано Che1lVK Чеилом · https://чеил.рф · https://vkvideo.ru/@che1lvk
"""
import json
import os
import socket
import sys
import threading
import time
from collections import deque
from dnslib import DNSRecord, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver
from flask import Flask, render_template, request, jsonify

APP_NAME = "CheDNS"
VERSION = "1.1"
AUTHOR = "Che1lVK Чеил"
AUTHOR_URL = "https://чеил.рф"
AUTHOR_VK = "https://vkvideo.ru/@che1lvk"


# ---------- ANSI цвета (Windows 10+) ----------
def enable_ansi():
    """Включает поддержку ANSI-цветов в cmd Windows."""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


class C:
    """ANSI-коды для цветного вывода."""
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


# ---------- Пути ----------
def get_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_templates_dir():
    """Ищем templates рядом с exe, потом внутри, потом рядом со скриптом."""
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

DEFAULT_CONFIG = {
    "records": {},
    "blocked": [],
    "internet_enabled": True,
    "upstream_dns": "8.8.8.8",
    "listen_ip": "0.0.0.0",
    "dns_port": 53,
    "web_port": 8080,
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
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


config = load_config()
config_lock = threading.Lock()
START_TIME = time.time()

# Статистика и логи
stats = {
    "total": 0,
    "local": 0,
    "forward": 0,
    "blocked": 0,
    "denied": 0,
}
stats_lock = threading.Lock()
recent_logs = deque(maxlen=200)
logs_lock = threading.Lock()


def add_log(kind, qname, qtype, extra=""):
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "kind": kind,
        "name": qname,
        "type": qtype,
        "extra": extra,
    }
    with logs_lock:
        recent_logs.append(entry)
    with stats_lock:
        stats["total"] += 1
        if kind == "LOCAL":
            stats["local"] += 1
        elif kind == "FORWARD":
            stats["forward"] += 1
        elif kind == "BLOCK":
            stats["blocked"] += 1
        elif kind == "DENY":
            stats["denied"] += 1


# ---------- Красивый вывод DNS-запроса в консоль ----------
def log_dns_query(client, qname, qtype, kind, extra=""):
    """
    Печатает красивый блок о DNS-запросе.
    kind: FORWARD / LOCAL / BLOCK / DENY
    """
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    time_short = time.strftime("%H:%M:%S")

    # Цвет бейджа по типу
    kind_colors = {
        "FORWARD": (C.CYAN, "[FORWARD]"),
        "LOCAL":   (C.GREEN, "[LOCAL]  "),
        "BLOCK":   (C.RED,   "[BLOCK]  "),
        "DENY":    (C.YELLOW, "[DENY]   "),
    }
    color, badge = kind_colors.get(kind, (C.WHITE, f"[{kind}]"))

    # Разбор адреса клиента
    if ":" in client:
        client_ip, client_port = client.rsplit(":", 1)
    else:
        client_ip, client_port = client, "?"

    # Строка "Ответ"
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
    print()
    print(f"  {C.GRAY}Отправитель:{C.RESET}  {C.MAGENTA}{client_ip}{C.GRAY}:{client_port}{C.RESET}")
    print(f"  {C.GRAY}Тип:{C.RESET}          {C.WHITE}udp{C.RESET}")
    print(f"  {C.GRAY}Домен:{C.RESET}        {C.WHITE}{qname}{C.RESET} {C.GRAY}({qtype}){C.RESET}")
    print(f"  {C.GRAY}Обработка:{C.RESET}    {color}{badge}{C.RESET} {answer}")
    print(f"{C.GRAY}─────────────────────────────────────────────────────{C.RESET}")


def log_startup_banner():
    """Печатает стартовый баннер сервера."""
    local_ip = get_local_ip()
    print()
    print(f"{C.CYAN}{'═' * 62}{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  {C.BOLD}{C.WHITE}{APP_NAME} v{VERSION}{C.RESET} — Свой интернет · DNS сервер")
    print(f"{C.CYAN}║{C.RESET}  {C.GRAY}Создано {AUTHOR} · {AUTHOR_URL}{C.RESET}")
    print(f"{C.CYAN}{'═' * 62}{C.RESET}")
    print()
    print(f"  {C.GREEN}▶{C.RESET} {C.WHITE}Запуск DNS сервера с веб интерфейсом...{C.RESET}")
    print()
    print(f"  {C.GREEN}✓{C.RESET} {C.BOLD}{C.GREEN}Успешно! Сервер запущен.{C.RESET}")
    print()
    print(f"{C.CYAN}{'─' * 62}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}Данные для подключения:{C.RESET}")
    print()
    print(f"  {C.GRAY}DNS сервер (в настройках устройств):{C.RESET}")
    print(f"    {C.BOLD}{C.CYAN}{local_ip}{C.RESET}  {C.GRAY}(порт {config['dns_port']}){C.RESET}")
    print()
    print(f"  {C.GRAY}Веб-интерфейс:{C.RESET}")
    print(f"    {C.BOLD}{C.CYAN}http://{local_ip}:{config['web_port']}{C.RESET}")
    print()
    print(f"  {C.GRAY}Конфиг:{C.RESET}")
    print(f"    {C.DIM}{CONFIG_FILE}{C.RESET}")
    print()
    print(f"{C.CYAN}{'─' * 62}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}Логи сервера:{C.RESET}")
    print(f"{C.GRAY}  (Ctrl+C для остановки сервера){C.RESET}")


# ---------- DNS Resolver ----------
class CheDNSResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]

        # Клиент (адрес:порт)
        try:
            client = request.get_client() if hasattr(request, "get_client") else None
        except Exception:
            client = None
        if not client and handler is not None and hasattr(handler, "client_address"):
            client = f"{handler.client_address[0]}:{handler.client_address[1]}"
        client = client or "unknown:0"

        # PTR / служебные — молча NXDOMAIN (без логов, чтобы не засорять)
        if qtype == "PTR" or qname.endswith(".in-addr.arpa"):
            reply.header.rcode = 3
            return reply

        with config_lock:
            records = dict(config["records"])
            blocked = list(config["blocked"])
            internet_enabled = config["internet_enabled"]
            upstream = config["upstream_dns"]

        # 1) Блокировка
        for b in blocked:
            b = b.lower().lstrip(".")
            if qname == b or qname.endswith("." + b):
                reply.header.rcode = 3
                log_dns_query(client, qname, qtype, "BLOCK")
                add_log("BLOCK", qname, qtype)
                return reply

        # 2) Локальные A-записи
        if qtype == "A":
            ip = records.get(qname)
            if ip:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))
                log_dns_query(client, qname, qtype, "LOCAL", ip)
                add_log("LOCAL", qname, qtype, ip)
                return reply

        # 3) Форвард наружу
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
                add_log("FORWARD", qname, qtype, upstream)
                return reply
            except Exception as e:
                log_dns_query(client, qname, qtype, "FORWARD", f"ошибка: {e}")
                add_log("FORWARD", qname, qtype, f"error: {e}")
                reply.header.rcode = 2
                return reply

        # 4) Интернет выключен
        log_dns_query(client, qname, qtype, "DENY")
        add_log("DENY", qname, qtype)
        reply.header.rcode = 3
        return reply


# ---------- Flask ----------
app = Flask(__name__, template_folder=get_templates_dir())
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


@app.route("/")
def index():
    return render_template("index.html", local_ip=get_local_ip(), version=VERSION)


@app.route("/favicon.ico")
def favicon():
    from flask import send_from_directory
    return send_from_directory(
        app.template_folder,
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.route("/api/health")
def api_health():
    return jsonify({
        "ok": True,
        "version": VERSION,
        "uptime": int(time.time() - START_TIME),
        "local_ip": get_local_ip(),
    })


@app.route("/api/config", methods=["GET"])
def api_get_config():
    with config_lock:
        return jsonify({
            "records": config["records"],
            "blocked": config["blocked"],
            "internet_enabled": config["internet_enabled"],
            "upstream_dns": config["upstream_dns"],
            "dns_port": config["dns_port"],
            "web_port": config["web_port"],
        })


@app.route("/api/record", methods=["POST"])
def api_add_record():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower().rstrip(".")
    ip = (data.get("ip") or "").strip()
    if not domain or not ip:
        return jsonify({"ok": False, "error": "Заполните домен и IP"}), 400
    try:
        socket.inet_aton(ip)
    except OSError:
        return jsonify({"ok": False, "error": "Некорректный IP"}), 400
    with config_lock:
        config["records"][domain] = ip
        save_config(config)
    return jsonify({"ok": True})


@app.route("/api/record", methods=["DELETE"])
def api_del_record():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower().rstrip(".")
    with config_lock:
        if domain in config["records"]:
            del config["records"][domain]
            save_config(config)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Не найдено"}), 404


@app.route("/api/block", methods=["POST"])
def api_add_block():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower().lstrip(".").rstrip(".")
    if not domain:
        return jsonify({"ok": False, "error": "Укажите домен"}), 400
    with config_lock:
        if domain not in config["blocked"]:
            config["blocked"].append(domain)
            save_config(config)
    return jsonify({"ok": True})


@app.route("/api/block", methods=["DELETE"])
def api_del_block():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower().lstrip(".").rstrip(".")
    with config_lock:
        if domain in config["blocked"]:
            config["blocked"].remove(domain)
            save_config(config)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Не найдено"}), 404


@app.route("/api/toggle_internet", methods=["POST"])
def api_toggle_internet():
    with config_lock:
        config["internet_enabled"] = not config["internet_enabled"]
        save_config(config)
        state = config["internet_enabled"]
    return jsonify({"ok": True, "internet_enabled": state})


@app.route("/api/upstream", methods=["POST"])
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


@app.route("/api/stats")
def api_stats():
    with stats_lock:
        s = dict(stats)
    s["uptime"] = int(time.time() - START_TIME)
    return jsonify(s)


@app.route("/api/logs")
def api_logs():
    with logs_lock:
        return jsonify(list(recent_logs))


# ---------- Запуск ----------
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
        print(f"{C.GRAY}         Возможно, порт занят другой службой (ICS, DNS Client).{C.RESET}")
        print(f"{C.GRAY}         Попробуй: net stop \"Internet Connection Sharing (ICS)\"{C.RESET}")
        return None


def main():
    enable_ansi()
    log_startup_banner()

    dns_server = start_dns_server()
    if not dns_server:
        # DNS не запустился — но веб-панель всё равно поднимем
        print()
        print(f"{C.YELLOW}  ▶{C.RESET} Запускаю только веб-интерфейс (без DNS)...")

    try:
        # Отключаем стандартные логи Flask, чтобы не мешали нашим
        import logging
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)

        app.run(host="0.0.0.0", port=config["web_port"], debug=False, use_reloader=False)
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
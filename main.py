import json
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import parse_qs, unquote
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import os
import threading
import glob
import sys
import tempfile
import zipfile
import shutil
import hashlib
import queue
import uuid as uuid_module
import ipaddress
import socket

xray_process = None
log_thread = None
stop_log_thread = False
current_profile_info = {}
runtime_config_file = None
log_queue = queue.Queue()
current_tun_enabled = False
current_tun_routes = []

profiles = {}

CONFIGS_DIR = "configs"
XRAY_RELEASES_API = "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=20"
XRAY_ASSET_NAME = "Xray-windows-64.zip"
DOWNLOADABLE_FILES = {"xray.exe", "geoip.dat", "geosite.dat"}
MAX_CORE_ZIP_BYTES = 120 * 1024 * 1024
MAX_EXTRACTED_FILE_BYTES = 120 * 1024 * 1024
MAX_RELEASES_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_VLESS_URL_LENGTH = 4096
MAX_JSON_CONFIG_LENGTH = 512 * 1024
MAX_PROFILE_NAME_LENGTH = 80
TUN_INTERFACE_NAME = "xstart0"
TUN_BLOCK_TAG = "tun-block"
TUN_ROUTES = ["0.0.0.0/0", "::/0"]
WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_ZIP_MAX_BYTES = 8 * 1024 * 1024
COLORS = {
    "bg": "#f4f7fb",
    "panel": "#ffffff",
    "panel_alt": "#eef3f8",
    "border": "#d7e0ea",
    "text": "#162033",
    "muted": "#64748b",
    "accent": "#2563eb",
    "accent_hover": "#1d4ed8",
    "danger": "#dc2626",
    "success": "#15803d",
    "log_bg": "#0b1120",
    "log_fg": "#8ff0a4",
}
if not os.path.exists(CONFIGS_DIR):
    os.makedirs(CONFIGS_DIR)


def get_app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_xray_path():
    local_xray = os.path.join(get_app_dir(), "xray.exe")
    if not os.path.exists(local_xray):
        raise FileNotFoundError("xray.exe не найден рядом с приложением. Нажмите 'Загрузить ядро'.")
    return local_xray


def get_wintun_path():
    return os.path.join(get_app_dir(), "wintun.dll")


def cleanup_runtime_config():
    global runtime_config_file
    if runtime_config_file and os.path.exists(runtime_config_file):
        try:
            os.remove(runtime_config_file)
        except OSError:
            pass
    runtime_config_file = None


def create_runtime_config(config_file, tun_enabled):
    global runtime_config_file
    cleanup_runtime_config()

    if not tun_enabled:
        return config_file

    with open(config_file, "r", encoding="utf-8") as f:
        config = json.load(f)

    config.setdefault("inbounds", []).append(
        {
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": TUN_INTERFACE_NAME,
                "mtu": 1500,
                "gateway": ["10.19.0.1/30", "fc00::1/126"],
                "dns": ["1.1.1.1", "8.8.8.8"],
                "autoSystemRoutingTable": TUN_ROUTES,
                "autoOutboundsInterface": "auto",
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
            },
        }
    )

    routing = config.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    outbounds = config.setdefault("outbounds", [])
    if not any(outbound.get("tag") == TUN_BLOCK_TAG for outbound in outbounds):
        outbounds.append({"tag": TUN_BLOCK_TAG, "protocol": "blackhole"})

    local_tun_ips = [
        "10.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    has_tun_block_rule = any(
        rule.get("outboundTag") == TUN_BLOCK_TAG and "tun-in" in rule.get("inboundTag", [])
        for rule in rules
        if isinstance(rule.get("inboundTag"), list)
    )
    if not has_tun_block_rule:
        rules.insert(0, {"type": "field", "inboundTag": ["tun-in"], "ip": local_tun_ips, "outboundTag": TUN_BLOCK_TAG})
        has_tun_block_rule = True

    has_tun_rule = any(
        rule.get("outboundTag") == "vless-reality" and "tun-in" in rule.get("inboundTag", [])
        for rule in rules
        if isinstance(rule.get("inboundTag"), list)
    )
    if not has_tun_rule:
        rules.insert(1 if has_tun_block_rule else 0, {"type": "field", "inboundTag": ["tun-in"], "outboundTag": "vless-reality"})

    fd, runtime_path = tempfile.mkstemp(prefix="xstart-runtime-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
    runtime_config_file = runtime_path
    return runtime_path


def fetch_xray_releases():
    request = Request(
        XRAY_RELEASES_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "XStart",
        },
    )
    with urlopen(request, timeout=20) as response:
        body = response.read(MAX_RELEASES_RESPONSE_BYTES + 1)
        if len(body) > MAX_RELEASES_RESPONSE_BYTES:
            raise RuntimeError("Ответ GitHub API слишком большой")
        releases = json.loads(body.decode("utf-8"))

    result = []
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        asset = next((item for item in release.get("assets", []) if item.get("name") == XRAY_ASSET_NAME), None)
        if not asset:
            continue
        try:
            validate_sha256_digest(asset.get("digest", ""))
        except RuntimeError:
            continue
        result.append(
            {
                "tag": release.get("tag_name", "unknown"),
                "name": release.get("name") or release.get("tag_name", "unknown"),
                "published_at": release.get("published_at", ""),
                "download_url": asset.get("browser_download_url", ""),
                "size": asset.get("size", 0),
                "digest": asset.get("digest", ""),
            }
        )
        if len(result) == 4:
            break

    if not result:
        raise RuntimeError("Не найдены подходящие релизы с Xray-windows-64.zip")
    return result


def validate_download_url(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise RuntimeError("Некорректный URL загрузки релиза")
    if not parsed.path.startswith("/XTLS/Xray-core/releases/download/"):
        raise RuntimeError("URL загрузки не относится к официальному XTLS/Xray-core")


def validate_final_download_url(url):
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if parsed.scheme != "https" or not (host == "github.com" or host.endswith(".githubusercontent.com")):
        raise RuntimeError("Загрузка была перенаправлена на недоверенный URL")


def validate_wintun_url(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc.lower() != "www.wintun.net":
        raise RuntimeError("Некорректный URL загрузки Wintun")
    if parsed.path != "/builds/wintun-0.14.1.zip":
        raise RuntimeError("URL загрузки Wintun не относится к ожидаемому официальному архиву")


def validate_sha256_digest(digest):
    if not digest:
        return ""
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise RuntimeError("Некорректный digest релиза")
    value = digest.split(":", 1)[1].lower()
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise RuntimeError("Некорректный SHA256 digest релиза")
    return value


def download_file(url, target_file, expected_digest=""):
    validate_download_url(url)
    expected_sha256 = validate_sha256_digest(expected_digest)
    request = Request(url, headers={"User-Agent": "XStart"})
    downloaded = 0
    digest = hashlib.sha256()
    with urlopen(request, timeout=60) as response, open(target_file, "wb") as f:
        validate_final_download_url(response.geturl())
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_CORE_ZIP_BYTES:
            raise RuntimeError("Архив ядра слишком большой")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            downloaded += len(chunk)
            if downloaded > MAX_CORE_ZIP_BYTES:
                raise RuntimeError("Архив ядра слишком большой")
            digest.update(chunk)
            f.write(chunk)

    if expected_sha256 and digest.hexdigest().lower() != expected_sha256:
        raise RuntimeError("SHA256 архива Xray не совпал с digest релиза GitHub")


def download_wintun_zip(target_file):
    validate_wintun_url(WINTUN_URL)
    request = Request(WINTUN_URL, headers={"User-Agent": "XStart"})
    downloaded = 0
    digest = hashlib.sha256()
    with urlopen(request, timeout=60) as response, open(target_file, "wb") as f:
        validate_wintun_url(response.geturl())
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > WINTUN_ZIP_MAX_BYTES:
            raise RuntimeError("Архив Wintun слишком большой")
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            downloaded += len(chunk)
            if downloaded > WINTUN_ZIP_MAX_BYTES:
                raise RuntimeError("Архив Wintun слишком большой")
            digest.update(chunk)
            f.write(chunk)

    if digest.hexdigest().lower() != WINTUN_SHA256:
        raise RuntimeError("SHA256 архива Wintun не совпал с официальным значением")


def extract_xray_core(zip_path, target_dir):
    extracted = set()
    with zipfile.ZipFile(zip_path, "r") as archive:
        for member in archive.infolist():
            filename = os.path.basename(member.filename).lower()
            if filename not in DOWNLOADABLE_FILES or member.is_dir():
                continue
            if filename in extracted:
                raise RuntimeError(f"В архиве найден дубликат файла {filename}")
            if member.file_size > MAX_EXTRACTED_FILE_BYTES:
                raise RuntimeError("Файл в архиве слишком большой")
            target_path = os.path.join(target_dir, filename)
            try:
                with archive.open(member, "r") as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                if os.path.getsize(target_path) != member.file_size:
                    raise RuntimeError(f"Размер извлеченного файла не совпал: {filename}")
            finally:
                if os.path.exists(target_path) and os.path.getsize(target_path) != member.file_size:
                    try:
                        os.remove(target_path)
                    except OSError:
                        pass
            extracted.add(filename)

    if "xray.exe" not in extracted:
        raise RuntimeError("В архиве не найден xray.exe")
    return extracted


def extract_wintun_dll(zip_path, target_dir):
    target_path = os.path.join(target_dir, "wintun.dll")
    with zipfile.ZipFile(zip_path, "r") as archive:
        member = next(
            (
                item
                for item in archive.infolist()
                if item.filename.replace("\\", "/").lower() == "wintun/bin/amd64/wintun.dll"
                and not item.is_dir()
            ),
            None,
        )
        if not member:
            raise RuntimeError("В архиве Wintun не найден bin/amd64/wintun.dll")
        if member.file_size > WINTUN_ZIP_MAX_BYTES:
            raise RuntimeError("wintun.dll в архиве слишком большой")
        try:
            with archive.open(member, "r") as source, open(target_path, "wb") as target:
                shutil.copyfileobj(source, target)
            if os.path.getsize(target_path) != member.file_size:
                raise RuntimeError("Размер извлеченного wintun.dll не совпал")
        finally:
            if os.path.exists(target_path) and os.path.getsize(target_path) != member.file_size:
                try:
                    os.remove(target_path)
                except OSError:
                    pass
    return {"wintun.dll"}


def install_downloaded_files(stage_dir, filenames):
    app_dir = get_app_dir()
    installed = set()
    for filename in sorted(filenames):
        if filename not in DOWNLOADABLE_FILES and filename != "wintun.dll":
            raise RuntimeError(f"Недопустимый файл для установки: {filename}")
        source_path = os.path.join(stage_dir, filename)
        if not os.path.isfile(source_path):
            raise RuntimeError(f"Подготовленный файл не найден: {filename}")
        os.replace(source_path, os.path.join(app_dir, filename))
        installed.add(filename)
    return installed


def download_wintun_dll():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "wintun-0.14.1.zip")
        stage_dir = os.path.join(temp_dir, "stage")
        os.makedirs(stage_dir)
        download_wintun_zip(zip_path)
        extracted = extract_wintun_dll(zip_path, stage_dir)
        return install_downloaded_files(stage_dir, extracted)


def download_core_release(release):
    if xray_process is not None:
        raise RuntimeError("Остановите Xray перед обновлением ядра")

    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, XRAY_ASSET_NAME)
        wintun_zip_path = os.path.join(temp_dir, "wintun-0.14.1.zip")
        stage_dir = os.path.join(temp_dir, "stage")
        os.makedirs(stage_dir)
        download_file(release["download_url"], zip_path, release.get("digest", ""))
        extracted = extract_xray_core(zip_path, stage_dir)
        download_wintun_zip(wintun_zip_path)
        extracted.update(extract_wintun_dll(wintun_zip_path, stage_dir))
        return install_downloaded_files(stage_dir, extracted)


def load_existing_profiles():
    """Загружает все существующие профили из папки configs при запуске приложения"""
    profile_files = glob.glob(os.path.join(CONFIGS_DIR, "*.json"))
    for file_path in profile_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                
            info = extract_profile_info_from_config(config)
            
            # Имя профиля - это имя файла без расширения
            profile_name = os.path.splitext(os.path.basename(file_path))[0]
            
            profiles[profile_name] = {
                "config_file": file_path,
                "info": info
            }
            
        except Exception as e:
            print(f"Ошибка загрузки профиля из {file_path}: {e}")
            continue


def parse_vless_url(vless_url):
    if len(vless_url) > MAX_VLESS_URL_LENGTH:
        raise ValueError("VLESS-ссылка слишком длинная.")

    if not vless_url.startswith("vless://"):
        raise ValueError("Это не VLESS-ссылка.")

    full_url = vless_url[8:]
    base, _, comment = full_url.partition('#')
    uuid, _, server_part = base.partition('@')
    if not uuid or not server_part:
        raise ValueError("Неверный формат VLESS-ссылки.")
    try:
        str(uuid_module.UUID(uuid))
    except Exception:
        raise ValueError("Неверный UUID в VLESS-ссылке.")

    if '?' in server_part:
        host_port, query_string = server_part.split('?', 1)
    else:
        host_port = server_part
        query_string = ""

    if ':' not in host_port:
        raise ValueError("Неверный формат: отсутствует порт.")
    host, port = host_port.split(':', 1)
    port = int(port)
    if port < 1 or port > 65535:
        raise ValueError("Порт должен быть в диапазоне 1-65535.")
    params = parse_qs(query_string)

    def get_param(name, default=""):
        return params.get(name, [default])[0]

    profile_name = unquote(comment) if comment else "Без имени"

    config = {
        "log": {"loglevel": "info"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth"},
            }
        ],
        "outbounds": [
            {
                "tag": "vless-reality",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": host,
                            "port": port,
                            "users": [
                                {
                                    "id": uuid,
                                    "encryption": "none",
                                    "flow": get_param("flow"),
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": get_param("type", "tcp"),
                    "security": "reality",
                    "realitySettings": {
                        "serverName": get_param("sni"),
                        "publicKey": get_param("pbk"),
                        "shortId": get_param("sid"),
                        "fingerprint": get_param("fp", "chrome"),
                        "spiderX": "/",
                    },
                },
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
                {"type": "field", "outboundTag": "block", "network": "udp", "port": "135,137,138,139"},
                {
                    "type": "field",
                    "outboundTag": "block",
                    "domain": [
                        "geosite:category-ads-all",
                        "google-analytics",
                        "analytics.yandex",
                        "appcenter.ms",
                        "app-measurement.com",
                        "firebase.io",
                        "crashlytics.com",
                    ],
                },
                {"type": "field", "outboundTag": "block", "network": "udp", "port": "443", "ip": ["geoip:!ru"]},
                {"type": "field", "inboundTag": ["socks-in"], "outboundTag": "vless-reality"},
            ],
        },
    }

    return profile_name, config, {
        "server": host,
        "port": port,
        "protocol": "VLESS",
        "security": "REALITY",
        "network": get_param("type", "tcp"),
        "sni": get_param("sni"),
        "fingerprint": get_param("fp", "chrome")
    }


def find_vless_outbound(config):
    for outbound in config.get("outbounds", []):
        if outbound.get("protocol") == "vless":
            return outbound
    raise ValueError("JSON-конфиг должен содержать VLESS outbound.")


def extract_profile_info_from_config(config):
    if not isinstance(config, dict):
        raise ValueError("JSON-конфиг должен быть объектом.")
    if not isinstance(config.get("outbounds"), list):
        raise ValueError("JSON-конфиг должен содержать список outbounds.")

    outbound = find_vless_outbound(config)
    settings = outbound.get("settings", {})
    vnext = settings.get("vnext", [])
    if not vnext or not isinstance(vnext, list):
        raise ValueError("VLESS outbound должен содержать settings.vnext.")
    endpoint = vnext[0]
    server = endpoint.get("address")
    port = endpoint.get("port")
    if not server or not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("VLESS outbound должен содержать корректные сервер и порт.")

    stream_settings = outbound.get("streamSettings", {})
    reality = stream_settings.get("realitySettings", {})
    return {
        "server": server,
        "port": port,
        "protocol": "VLESS",
        "security": stream_settings.get("security", ""),
        "network": stream_settings.get("network", ""),
        "sni": reality.get("serverName", ""),
        "fingerprint": reality.get("fingerprint", ""),
    }


def ensure_local_socks_inbound(config):
    inbounds = config.setdefault("inbounds", [])
    has_socks = any(inbound.get("tag") == "socks-in" for inbound in inbounds)
    if not has_socks:
        inbounds.insert(
            0,
            {
                "tag": "socks-in",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth"},
            },
        )


def ensure_basic_socks_route(config):
    routing = config.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    has_route = any(
        rule.get("outboundTag") == "vless-reality" and "socks-in" in rule.get("inboundTag", [])
        for rule in rules
        if isinstance(rule.get("inboundTag"), list)
    )
    if not has_route:
        rules.append({"type": "field", "inboundTag": ["socks-in"], "outboundTag": "vless-reality"})


def normalize_imported_json_config(config):
    info = extract_profile_info_from_config(config)
    find_vless_outbound(config)["tag"] = "vless-reality"
    ensure_local_socks_inbound(config)
    ensure_basic_socks_route(config)
    return config, info


def parse_profile_text(raw_text):
    text = raw_text.strip()
    if not text:
        raise ValueError("Вставлен пустой текст.")
    if text.startswith("vless://"):
        return parse_vless_url(text)
    if len(text) > MAX_JSON_CONFIG_LENGTH:
        raise ValueError("JSON-конфиг слишком большой.")
    try:
        config = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Это не VLESS-ссылка и не корректный JSON: {e}") from e
    config, info = normalize_imported_json_config(config)
    profile_name = info["server"]
    return profile_name, config, info


def unique_profile_name(profile_name):
    base_name = profile_name.strip() or "profile"
    if base_name not in profiles:
        return base_name
    index = 2
    while f"{base_name} ({index})" in profiles:
        index += 1
    return f"{base_name} ({index})"


def save_profile_config(profile_name, config):
    safe_name = "".join(c for c in profile_name if c.isalnum() or c in " _-()[]").strip()
    safe_name = safe_name[:MAX_PROFILE_NAME_LENGTH].strip()
    if not safe_name:
        raise ValueError("Имя профиля не содержит символов, подходящих для имени файла.")

    filename = os.path.join(CONFIGS_DIR, f"{safe_name}.json")
    if os.path.exists(filename):
        index = 2
        while True:
            candidate = os.path.join(CONFIGS_DIR, f"{safe_name} ({index}).json")
            if not os.path.exists(candidate):
                filename = candidate
                break
            index += 1

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
    return filename


def update_profile_list():
    profile_listbox.delete(0, tk.END)
    for name in profiles.keys():
        profile_listbox.insert(tk.END, name)


def add_profile_from_text(raw_text, dialog=None):
    try:
        profile_name, config, info = parse_profile_text(raw_text)
        profile_name = unique_profile_name(profile_name)
        config_file = save_profile_config(profile_name, config)
    except Exception as e:
        messagebox.showerror("Ошибка импорта", f"Не удалось импортировать профиль:\n{e}")
        return

    profiles[profile_name] = {"config_file": config_file, "info": info}
    update_profile_list()
    messagebox.showinfo("Готово", f"Профиль «{profile_name}» добавлен")
    if dialog is not None:
        dialog.destroy()


def add_profile_from_clipboard():
    try:
        clipboard_text = root.clipboard_get().strip()
    except Exception:
        messagebox.showerror("Буфер обмена", "Не удалось прочитать буфер обмена")
        return
    add_profile_from_text(clipboard_text)


def open_profile_import_dialog():
    dialog = tk.Toplevel(root)
    dialog.title("Импорт профиля")
    dialog.geometry("720x500")
    dialog.minsize(620, 420)
    dialog.transient(root)
    dialog.grab_set()
    dialog.configure(bg=COLORS["bg"])

    container = ttk.Frame(dialog, style="App.TFrame", padding=18)
    container.pack(fill="both", expand=True)

    ttk.Label(container, text="Импорт профиля", style="Title.TLabel").pack(anchor="w")
    ttk.Label(
        container,
        text="Вставьте vless:// ссылку или полный JSON-конфиг Xray с VLESS outbound.",
        style="Subtitle.TLabel",
    ).pack(anchor="w", pady=(4, 12))

    text_frame = ttk.Frame(container, style="Card.TFrame", padding=1)
    text_frame.pack(fill="both", expand=True)
    input_text = tk.Text(
        text_frame,
        height=14,
        wrap="word",
        bg=COLORS["panel"],
        fg=COLORS["text"],
        insertbackground=COLORS["text"],
        relief="flat",
        padx=12,
        pady=12,
        font=("Consolas", 10),
    )
    input_text.pack(fill="both", expand=True)

    try:
        input_text.insert("1.0", root.clipboard_get().strip())
    except Exception:
        pass

    button_frame = ttk.Frame(container, style="App.TFrame")
    button_frame.pack(fill="x", pady=(14, 0))

    def paste_clipboard():
        try:
            input_text.delete("1.0", tk.END)
            input_text.insert("1.0", root.clipboard_get().strip())
        except Exception:
            messagebox.showerror("Буфер обмена", "Не удалось прочитать буфер обмена")

    ttk.Button(button_frame, text="Вставить из буфера", command=paste_clipboard, style="Secondary.TButton").pack(side="left")
    ttk.Button(button_frame, text="Отмена", command=dialog.destroy, style="Secondary.TButton").pack(side="right")
    ttk.Button(
        button_frame,
        text="Импортировать",
        command=lambda: add_profile_from_text(input_text.get("1.0", tk.END), dialog),
        style="Accent.TButton",
    ).pack(side="right", padx=(0, 8))


def delete_selected_profile():
    selected = profile_listbox.curselection()
    if not selected:
        messagebox.showwarning("Внимание", "Выберите профиль для удаления")
        return
    profile_name = profile_listbox.get(selected[0])
    answer = messagebox.askyesno("Подтверждение", f"Удалить профиль '{profile_name}'?")
    if not answer:
        return
    config_file = profiles[profile_name]["config_file"]
    try:
        if os.path.exists(config_file):
            os.remove(config_file)
    except Exception as e:
        messagebox.showwarning("Внимание", f"Не удалось удалить файл конфига:\n{e}")
    del profiles[profile_name]
    update_profile_list()


def show_core_download_dialog():
    if xray_process is not None:
        messagebox.showwarning("Предупреждение", "Остановите Xray перед загрузкой ядра")
        return

    core_btn.config(state="disabled", text="Загрузка...")

    def finish_error(error_text):
        core_btn.config(state="normal", text="Загрузить ядро")
        messagebox.showerror("Ошибка", f"Не удалось получить список релизов:\n{error_text}")

    def finish_success(releases):
        core_btn.config(state="normal", text="Загрузить ядро")
        open_core_release_dialog(releases)

    def worker():
        try:
            releases = fetch_xray_releases()
        except Exception as e:
            root.after(0, lambda: finish_error(str(e)))
            return
        root.after(0, lambda: finish_success(releases))

    threading.Thread(target=worker, daemon=True).start()


def open_core_release_dialog(releases):
    dialog = tk.Toplevel(root)
    dialog.title("Загрузка ядра Xray")
    dialog.geometry("460x260")
    dialog.resizable(False, False)
    dialog.transient(root)
    dialog.grab_set()

    ttk.Label(dialog, text="Выберите версию Xray-core:").pack(anchor="w", padx=10, pady=(10, 5))

    release_list = tk.Listbox(dialog, height=6)
    release_list.pack(fill="both", expand=True, padx=10)
    for release in releases:
        published = release["published_at"][:10] if release.get("published_at") else "дата неизвестна"
        size_mb = release.get("size", 0) / 1024 / 1024
        release_list.insert(tk.END, f"{release['tag']}  |  {published}  |  {size_mb:.1f} MB")
    release_list.selection_set(0)

    status = ttk.Label(dialog, text="")
    status.pack(anchor="w", padx=10, pady=(6, 0))

    button_frame = ttk.Frame(dialog)
    button_frame.pack(fill="x", padx=10, pady=10)

    def close_dialog():
        dialog.destroy()

    def start_download():
        selected = release_list.curselection()
        if not selected:
            messagebox.showwarning("Внимание", "Выберите версию для загрузки", parent=dialog)
            return
        release = releases[selected[0]]
        download_btn.config(state="disabled")
        cancel_btn.config(state="disabled")
        release_list.config(state="disabled")
        status.config(text=f"Скачивание {release['tag']}...")

        def finish_download(error_text=None, extracted=None):
            if error_text:
                download_btn.config(state="normal")
                cancel_btn.config(state="normal")
                release_list.config(state="normal")
                status.config(text="")
                messagebox.showerror("Ошибка", f"Не удалось загрузить ядро:\n{error_text}", parent=dialog)
                return
            dialog.destroy()
            files = ", ".join(sorted(extracted))
            messagebox.showinfo("Готово", f"Ядро Xray загружено.\nФайлы: {files}", parent=root)

        def worker():
            try:
                extracted = download_core_release(release)
            except Exception as e:
                root.after(0, lambda: finish_download(error_text=str(e)))
                return
            root.after(0, lambda: finish_download(extracted=extracted))

        threading.Thread(target=worker, daemon=True).start()

    download_btn = ttk.Button(button_frame, text="Скачать", command=start_download)
    download_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))
    cancel_btn = ttk.Button(button_frame, text="Отмена", command=close_dialog)
    cancel_btn.pack(side="left", fill="x", expand=True, padx=(5, 0))


def ensure_wintun_for_tun():
    if os.path.exists(get_wintun_path()):
        return True

    answer = messagebox.askyesno(
        "Нужен Wintun",
        "Для TUN режима на Windows нужен wintun.dll рядом с xray.exe.\n"
        "Скачать официальный Wintun 0.14.1 с проверкой SHA256 сейчас?",
    )
    if not answer:
        return False

    root.config(cursor="watch")
    root.update_idletasks()
    try:
        download_wintun_dll()
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось скачать wintun.dll:\n{e}")
        return False
    finally:
        root.config(cursor="")
        root.update_idletasks()

    messagebox.showinfo("Готово", "wintun.dll загружен рядом с приложением")
    return True


def run_powershell_script(script, timeout=15):
    utf8_script = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n$OutputEncoding = [System.Text.Encoding]::UTF8\n" + script
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", utf8_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=0x08000000,
    )
    output = completed.stdout.strip()
    if completed.returncode != 0:
        raise RuntimeError(output or f"PowerShell завершился с кодом {completed.returncode}")
    return output


def resolve_endpoint_ips(host):
    ips = []
    try:
        ip = ipaddress.ip_address(host)
        return [str(ip)]
    except ValueError:
        pass

    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            results = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        for result in results:
            ip = result[4][0]
            if ip not in ips:
                ips.append(ip)
            if len(ips) >= 4:
                return ips
    return ips


def prepare_tun_endpoint_routes(host):
    ips = resolve_endpoint_ips(host)
    if not ips:
        raise RuntimeError(f"Не удалось определить IP прокси для TUN-маршрута: {host}")

    ps_ips = "@(" + ",".join(json.dumps(ip) for ip in ips) + ")"
    script = f"""
$ErrorActionPreference = 'Stop'
$ips = {ps_ips}
$added = @()

try {{
    foreach ($ip in $ips) {{
        $best = Find-NetRoute -RemoteIPAddress $ip -ErrorAction Stop |
            Where-Object {{ $_.InterfaceAlias -ne '{TUN_INTERFACE_NAME}' }} |
            Sort-Object -Property RouteMetric, InterfaceMetric |
            Select-Object -First 1
        if (-not $best) {{ throw "No physical route to endpoint $ip" }}

        if ($ip.Contains(':')) {{
            $prefix = "$ip/128"
        }} else {{
            $prefix = "$ip/32"
        }}
        $existing = Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object {{ $_.InterfaceIndex -eq $best.InterfaceIndex }}
        if (-not $existing) {{
            New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $best.InterfaceIndex -NextHop $best.NextHop -RouteMetric 4242 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
            $added += $prefix
        }}
    }}
}} catch {{
    foreach ($prefix in $added) {{
        Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }}
    throw
}}

[pscustomobject]@{{
    AddedPrefixes = $added
    EndpointIPs = $ips
}} | ConvertTo-Json -Compress
"""
    data = json.loads(run_powershell_script(script, timeout=20))
    prefixes = data.get("AddedPrefixes", [])
    endpoint_ips = data.get("EndpointIPs", ips)
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    if isinstance(endpoint_ips, str):
        endpoint_ips = [endpoint_ips]
    return prefixes, endpoint_ips


def configure_tun_adapter_routes():
    script = f"""
$ErrorActionPreference = 'Stop'
$adapter = $null
$deadline = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $deadline) {{
    $adapter = Get-NetAdapter -Name '{TUN_INTERFACE_NAME}' -ErrorAction SilentlyContinue
    if ($adapter) {{ break }}
    Start-Sleep -Milliseconds 250
}}
if (-not $adapter) {{ throw "TUN adapter '{TUN_INTERFACE_NAME}' was not created" }}
$ifIndex = $adapter.ifIndex

function Invoke-WithRetry([scriptblock]$Action, [string]$Name) {{
    $lastError = $null
    for ($i = 0; $i -lt 30; $i++) {{
        try {{
            & $Action
            return
        }} catch {{
            $lastError = $_
            Start-Sleep -Milliseconds 300
        }}
    }}
    throw "Не удалось настроить TUN $Name после нескольких попыток: $lastError"
}}

function Invoke-Netsh([string[]]$NetshArgs, [string]$Name) {{
    Invoke-WithRetry {{
        $output = & netsh @NetshArgs 2>&1
        if ($LASTEXITCODE -ne 0) {{
            throw "$Name failed with code $LASTEXITCODE`: $output"
        }}
    }} $Name
}}

Invoke-Netsh @('interface', 'ip', 'set', 'address', 'name="{TUN_INTERFACE_NAME}"', 'static', '10.19.0.1', '255.255.255.252') 'IPv4 address'
Invoke-Netsh @('interface', 'ip', 'set', 'dns', 'name="{TUN_INTERFACE_NAME}"', 'static', '1.1.1.1', 'validate=no') 'primary DNS'
Invoke-Netsh @('interface', 'ip', 'add', 'dns', 'name="{TUN_INTERFACE_NAME}"', '8.8.8.8', 'index=2', 'validate=no') 'secondary DNS'
Invoke-WithRetry {{
    $dns = Get-DnsClientServerAddress -InterfaceAlias '{TUN_INTERFACE_NAME}' -AddressFamily IPv4 -ErrorAction Stop
    if ($dns.ServerAddresses -notcontains '1.1.1.1' -or $dns.ServerAddresses -notcontains '8.8.8.8') {{
        throw "DNS was not applied"
    }}
}} 'DNS verification'
Invoke-Netsh @('interface', 'ipv4', 'set', 'interface', '{TUN_INTERFACE_NAME}', 'metric=1') 'IPv4 metric'
Invoke-Netsh @('interface', 'ipv6', 'set', 'interface', '{TUN_INTERFACE_NAME}', 'metric=1') 'IPv6 metric'

$routes = @('0.0.0.0/0', '::/0')
foreach ($prefix in $routes) {{
    Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    if ($prefix.Contains(':')) {{
        Invoke-WithRetry {{ New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -NextHop '::' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null }} "route $prefix"
    }} else {{
        Invoke-WithRetry {{ New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $ifIndex -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null }} "route $prefix"
    }}
}}

[pscustomobject]@{{ InterfaceIndex = $ifIndex; AddedPrefixes = $routes }} | ConvertTo-Json -Compress
"""
    data = json.loads(run_powershell_script(script, timeout=25))
    prefixes = data.get("AddedPrefixes", [])
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    return prefixes


def cleanup_tun_routes(prefixes):
    if not prefixes:
        return
    ps_prefixes = "@(" + ",".join(json.dumps(prefix) for prefix in prefixes) + ")"
    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$prefixes = {ps_prefixes}
foreach ($prefix in $prefixes) {{
    if ($prefix -eq '0.0.0.0/0' -or $prefix -eq '::/0') {{
        Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object {{ $_.InterfaceAlias -eq '{TUN_INTERFACE_NAME}' }} |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }} else {{
        Get-NetRoute -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object {{ $_.RouteMetric -eq 4242 }} |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }}
}}
"""
    try:
        run_powershell_script(script, timeout=10)
    except Exception:
        pass


def update_proxy_info(profile_name):
    global current_profile_info

    if profile_name not in profiles:
        return
    info = profiles[profile_name]["info"]
    current_profile_info = info

    for widget in proxy_info_frame.winfo_children():
        widget.destroy()

    proxy_info_frame.columnconfigure(0, weight=0)
    proxy_info_frame.columnconfigure(1, weight=1)

    ttk.Label(proxy_info_frame, text="Удаленный прокси", style="Muted.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
    details = [
        ("Сервер", info["server"]),
        ("Порт", info["port"]),
        ("Протокол", info["protocol"]),
        ("Защита", info["security"]),
        ("Транспорт", info["network"]),
        ("SNI", info["sni"]),
        ("Fingerprint", info["fingerprint"]),
    ]
    for row, (label, value) in enumerate(details, start=1):
        ttk.Label(proxy_info_frame, text=label, style="Muted.TLabel").grid(row=row, column=0, sticky="nw", pady=3, padx=(0, 16))
        value_label = ttk.Label(proxy_info_frame, text=str(value or "-"), style="Body.TLabel", wraplength=560)
        value_label.grid(row=row, column=1, sticky="ew", pady=3)

    row = len(details) + 2
    ttk.Label(proxy_info_frame, text="Локальный SOCKS", style="Muted.TLabel").grid(row=row, column=0, sticky="nw", pady=(14, 0), padx=(0, 16))
    ttk.Label(proxy_info_frame, text="127.0.0.1:10808, без авторизации", style="Body.TLabel").grid(row=row, column=1, sticky="ew", pady=(14, 0))


def render_inactive_proxy_info():
    for widget in proxy_info_frame.winfo_children():
        widget.destroy()
    proxy_info_frame.columnconfigure(0, weight=1)
    ttk.Label(proxy_info_frame, text="Прокси не запущен", style="Body.TLabel").grid(row=0, column=0, sticky="w")


def update_ui_state(is_running):
    if is_running:
        status_label.config(text="Запущен", foreground=COLORS["success"])
        toggle_btn.config(text="Остановить Xray", command=stop_xray)
        add_btn.config(state="disabled")
        del_btn.config(state="disabled")
        core_btn.config(state="disabled")
        tun_check.config(state="disabled")
        profile_listbox.config(state="disabled")
    else:
        status_label.config(text="Остановлен", foreground=COLORS["danger"])
        toggle_btn.config(text="Запустить Xray", command=start_xray)
        add_btn.config(state="normal")
        del_btn.config(state="normal")
        core_btn.config(state="normal")
        tun_check.config(state="normal")
        profile_listbox.config(state="normal")


def append_log_line(line):
    log_text.config(state="normal")
    log_text.insert(tk.END, line)
    log_text.see(tk.END)
    log_text.config(state="disabled")


def handle_xray_exit(process, return_code):
    global xray_process, stop_log_thread, current_tun_enabled, current_tun_routes
    if xray_process is not process:
        return

    if current_tun_enabled:
        cleanup_tun_routes(current_tun_routes)
        current_tun_routes = []
    current_tun_enabled = False
    xray_process = None
    stop_log_thread = True
    cleanup_runtime_config()
    update_ui_state(False)
    append_log_line(f"\nXray завершился с кодом {return_code}\n")


def poll_log_queue():
    while True:
        try:
            item = log_queue.get_nowait()
        except queue.Empty:
            break

        kind = item[0]
        if kind == "line":
            append_log_line(item[1])
        elif kind == "exit":
            handle_xray_exit(item[1], item[2])

    if xray_process is not None or not log_queue.empty():
        root.after(100, poll_log_queue)


def clear_log_queue():
    while True:
        try:
            log_queue.get_nowait()
        except queue.Empty:
            break


def start_xray():
    global xray_process, stop_log_thread, log_thread, current_tun_enabled, current_tun_routes

    if xray_process is not None:
        messagebox.showwarning("Внимание", "Xray уже запущен")
        return

    selected = profile_listbox.curselection()
    if not selected:
        messagebox.showerror("Ошибка", "Выберите профиль для запуска")
        return

    profile_name = profile_listbox.get(selected[0])
    config_file = profiles[profile_name]["config_file"]

    if not os.path.exists(config_file):
        messagebox.showerror("Ошибка", f"Файл конфига не найден: {config_file}")
        return

    try:
        xray_path = get_xray_path()
    except FileNotFoundError:
        answer = messagebox.askyesno(
            "Ядро не загружено",
            "Ядро Xray не найдено рядом с приложением.\n"
            "Сначала загрузите ядро, затем запустите профиль.\n\n"
            "Открыть загрузку ядра сейчас?",
        )
        if answer:
            show_core_download_dialog()
        return

    tun_enabled = tun_var.get()
    pending_tun_routes = []
    endpoint_ips = []
    if tun_enabled:
        confirmed = messagebox.askyesno(
            "TUN-режим",
            "TUN-режим меняет маршруты Windows и обычно требует запуск от администратора.\nПродолжить?",
        )
        if not confirmed:
            return
        if not ensure_wintun_for_tun():
            return
        try:
            endpoint_routes, endpoint_ips = prepare_tun_endpoint_routes(profiles[profile_name]["info"]["server"])
            pending_tun_routes.extend(endpoint_routes)
        except Exception as e:
            cleanup_tun_routes(pending_tun_routes)
            messagebox.showerror("Ошибка", f"Не удалось подготовить маршрут до прокси:\n{e}")
            return

    try:
        config_file = create_runtime_config(config_file, tun_enabled)
        xray_process = subprocess.Popen(
            [xray_path, "-config", os.path.abspath(config_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            creationflags=0x08000000,
            cwd=get_app_dir(),
        )
        if tun_enabled:
            pending_tun_routes.extend(configure_tun_adapter_routes())
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось запустить Xray:\n{e}")
        if xray_process is not None:
            try:
                xray_process.terminate()
                xray_process.wait(timeout=5)
            except Exception:
                try:
                    xray_process.kill()
                except Exception:
                    pass
        cleanup_tun_routes(pending_tun_routes)
        cleanup_runtime_config()
        xray_process = None
        return

    current_tun_enabled = tun_enabled
    current_tun_routes = pending_tun_routes
    update_ui_state(True)
    update_proxy_info(profile_name)

    log_text.config(state="normal")
    log_text.delete("1.0", tk.END)
    log_text.config(state="disabled")

    clear_log_queue()
    stop_log_thread = False

    def read_log(process):
        global stop_log_thread
        while not stop_log_thread:
            line = process.stdout.readline()
            if line:
                log_queue.put(("line", line))
            else:
                break
        return_code = process.wait()
        log_queue.put(("exit", process, return_code))

    log_thread = threading.Thread(target=read_log, args=(xray_process,), daemon=True)
    log_thread.start()
    poll_log_queue()
    if tun_enabled:
        log_queue.put(
            (
                "line",
                "\n[ TUN ] Маршруты Windows активны: прокси="
                f"{', '.join(endpoint_ips)}; маршруты={', '.join(current_tun_routes)}\n",
            )
        )


def stop_xray():
    global xray_process, stop_log_thread, current_tun_enabled, current_tun_routes
    if xray_process:
        if current_tun_enabled:
            cleanup_tun_routes(current_tun_routes)
            current_tun_routes = []
        stop_log_thread = True
        xray_process.terminate()
        try:
            xray_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            xray_process.kill()
            xray_process.wait(timeout=5)
        xray_process = None
        current_tun_enabled = False
        cleanup_runtime_config()
        update_ui_state(False)
        
        render_inactive_proxy_info()
    else:
        messagebox.showinfo("Информация", "Xray не запущен")


def on_close():
    if xray_process:
        stop_xray()
    cleanup_runtime_config()
    root.destroy()


def configure_styles():
    style.configure("App.TFrame", background=COLORS["bg"])
    style.configure("Card.TFrame", background=COLORS["panel"], relief="flat")
    style.configure("Panel.TLabelframe", background=COLORS["panel"], bordercolor=COLORS["border"], relief="solid")
    style.configure("Panel.TLabelframe.Label", background=COLORS["panel"], foreground=COLORS["muted"], font=("Segoe UI", 9, "bold"))
    style.configure("Title.TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 18, "bold"))
    style.configure("Subtitle.TLabel", background=COLORS["bg"], foreground=COLORS["muted"], font=("Segoe UI", 10))
    style.configure("Body.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=("Segoe UI", 10))
    style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"], font=("Segoe UI", 9))
    style.configure("Status.TLabel", background=COLORS["panel"], foreground=COLORS["danger"], font=("Segoe UI", 10, "bold"))
    style.configure("TCheckbutton", background=COLORS["panel"], foreground=COLORS["text"], font=("Segoe UI", 10))
    style.configure("Accent.TButton", background=COLORS["accent"], foreground="white", borderwidth=0, focusthickness=0, font=("Segoe UI", 10, "bold"), padding=(14, 8))
    style.map("Accent.TButton", background=[("active", COLORS["accent_hover"]), ("disabled", COLORS["border"])])
    style.configure("Secondary.TButton", background=COLORS["panel_alt"], foreground=COLORS["text"], borderwidth=0, focusthickness=0, font=("Segoe UI", 10), padding=(12, 8))
    style.map("Secondary.TButton", background=[("active", COLORS["border"]), ("disabled", COLORS["panel_alt"])])


root = tk.Tk()
root.title("XStart")
root.geometry("1080x760")
root.minsize(960, 680)
root.protocol("WM_DELETE_WINDOW", on_close)
root.configure(bg=COLORS["bg"])

style = ttk.Style(root)
style.theme_use("clam")
configure_styles()

main_frame = ttk.Frame(root, style="App.TFrame", padding=20)
main_frame.pack(fill="both", expand=True)
main_frame.columnconfigure(0, weight=0, minsize=310)
main_frame.columnconfigure(1, weight=1, minsize=610)
main_frame.rowconfigure(1, weight=1)

header_frame = ttk.Frame(main_frame, style="App.TFrame")
header_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 18))
header_frame.columnconfigure(0, weight=1)
ttk.Label(header_frame, text="XStart", style="Title.TLabel").grid(row=0, column=0, sticky="w")
ttk.Label(header_frame, text="Лаунчер Xray для VLESS-профилей и TUN-режима Windows", style="Subtitle.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 0))

profiles_frame = ttk.LabelFrame(main_frame, text="Профили", style="Panel.TLabelframe", padding=14)
profiles_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 16))
profiles_frame.rowconfigure(0, weight=1)
profiles_frame.columnconfigure(0, weight=1)
profile_listbox = tk.Listbox(
    profiles_frame,
    height=12,
    relief="flat",
    activestyle="none",
    borderwidth=0,
    highlightthickness=1,
    highlightbackground=COLORS["border"],
    selectbackground=COLORS["accent"],
    selectforeground="white",
    bg=COLORS["panel"],
    fg=COLORS["text"],
    font=("Segoe UI", 10),
)
profile_listbox.grid(row=0, column=0, sticky="nsew")

profile_buttons = ttk.Frame(profiles_frame, style="Card.TFrame")
profile_buttons.grid(row=1, column=0, sticky="ew", pady=(12, 0))
profile_buttons.columnconfigure(0, weight=1)
profile_buttons.columnconfigure(1, weight=1)
add_btn = ttk.Button(profile_buttons, text="Импорт", command=open_profile_import_dialog, style="Accent.TButton")
add_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))
del_btn = ttk.Button(profile_buttons, text="Удалить", command=delete_selected_profile, style="Secondary.TButton")
del_btn.grid(row=0, column=1, sticky="ew", padx=(6, 0))

workspace_frame = ttk.Frame(main_frame, style="App.TFrame")
workspace_frame.grid(row=1, column=1, sticky="nsew")
workspace_frame.columnconfigure(0, weight=1)
workspace_frame.rowconfigure(2, weight=1)

control_frame = ttk.LabelFrame(workspace_frame, text="Управление", style="Panel.TLabelframe", padding=14)
control_frame.grid(row=0, column=0, sticky="ew")
control_frame.columnconfigure(0, weight=1)
control_frame.columnconfigure(1, weight=0)
control_frame.columnconfigure(2, weight=0)
control_frame.columnconfigure(3, weight=0)
toggle_btn = ttk.Button(control_frame, text="Запустить Xray", command=start_xray, style="Accent.TButton")
toggle_btn.grid(row=0, column=0, sticky="ew", padx=(0, 12))
status_label = ttk.Label(control_frame, text="Остановлен", style="Status.TLabel")
status_label.grid(row=0, column=1, sticky="w", padx=(0, 18))
tun_var = tk.BooleanVar(value=False)
tun_check = ttk.Checkbutton(control_frame, text="TUN-режим", variable=tun_var)
tun_check.grid(row=0, column=2, sticky="w", padx=(0, 12))
core_btn = ttk.Button(control_frame, text="Загрузить ядро", command=show_core_download_dialog, style="Secondary.TButton")
core_btn.grid(row=0, column=3, sticky="ew")

proxy_info_frame = ttk.LabelFrame(workspace_frame, text="Подключение", style="Panel.TLabelframe", padding=14)
proxy_info_frame.grid(row=1, column=0, sticky="ew", pady=(16, 0))
render_inactive_proxy_info()

log_frame = ttk.LabelFrame(workspace_frame, text="Лог Xray", style="Panel.TLabelframe", padding=10)
log_frame.grid(row=2, column=0, sticky="nsew", pady=(16, 0))
log_frame.rowconfigure(0, weight=1)
log_frame.columnconfigure(0, weight=1)
log_text = tk.Text(
    log_frame,
    state="disabled",
    wrap="none",
    bg=COLORS["log_bg"],
    fg=COLORS["log_fg"],
    insertbackground=COLORS["log_fg"],
    relief="flat",
    padx=12,
    pady=10,
    font=("Consolas", 10),
)
log_text.grid(row=0, column=0, sticky="nsew")

load_existing_profiles()
update_profile_list()

root.mainloop()

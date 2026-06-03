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

xray_process = None
log_thread = None
stop_log_thread = False
current_profile_info = {}
runtime_config_file = None

profiles = {}

CONFIGS_DIR = "configs"
XRAY_RELEASES_API = "https://api.github.com/repos/XTLS/Xray-core/releases"
XRAY_ASSET_NAME = "Xray-windows-64.zip"
DOWNLOADABLE_FILES = {"xray.exe", "geoip.dat", "geosite.dat"}
MAX_CORE_ZIP_BYTES = 120 * 1024 * 1024
WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_ZIP_MAX_BYTES = 8 * 1024 * 1024
if not os.path.exists(CONFIGS_DIR):
    os.makedirs(CONFIGS_DIR)


def get_app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_xray_path():
    local_xray = os.path.join(get_app_dir(), "xray.exe")
    if os.path.exists(local_xray):
        return local_xray
    return "xray.exe"


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
                "name": "xstart0",
                "mtu": 1500,
                "gateway": ["10.19.0.1/30", "fc00::1/126"],
                "dns": ["1.1.1.1", "8.8.8.8"],
                "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
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
    has_tun_rule = any("tun-in" in rule.get("inboundTag", []) for rule in rules if isinstance(rule.get("inboundTag"), list))
    if not has_tun_rule:
        rules.insert(0, {"type": "field", "inboundTag": ["tun-in"], "outboundTag": "vless-reality"})

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
        releases = json.loads(response.read().decode("utf-8"))

    result = []
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        asset = next((item for item in release.get("assets", []) if item.get("name") == XRAY_ASSET_NAME), None)
        if not asset:
            continue
        result.append(
            {
                "tag": release.get("tag_name", "unknown"),
                "name": release.get("name") or release.get("tag_name", "unknown"),
                "published_at": release.get("published_at", ""),
                "download_url": asset.get("browser_download_url", ""),
                "size": asset.get("size", 0),
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


def download_file(url, target_file):
    validate_download_url(url)
    request = Request(url, headers={"User-Agent": "XStart"})
    downloaded = 0
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
            f.write(chunk)


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


def extract_xray_core(zip_path):
    app_dir = get_app_dir()
    extracted = set()
    with zipfile.ZipFile(zip_path, "r") as archive:
        for member in archive.infolist():
            filename = os.path.basename(member.filename).lower()
            if filename not in DOWNLOADABLE_FILES or member.is_dir():
                continue
            if member.file_size > MAX_CORE_ZIP_BYTES:
                raise RuntimeError("Файл в архиве слишком большой")
            target_path = os.path.join(app_dir, filename)
            temp_target = target_path + ".download"
            try:
                with archive.open(member, "r") as source, open(temp_target, "wb") as target:
                    shutil.copyfileobj(source, target)
                os.replace(temp_target, target_path)
            finally:
                if os.path.exists(temp_target):
                    try:
                        os.remove(temp_target)
                    except OSError:
                        pass
            extracted.add(filename)

    if "xray.exe" not in extracted:
        raise RuntimeError("В архиве не найден xray.exe")
    return extracted


def extract_wintun_dll(zip_path):
    target_path = get_wintun_path()
    temp_target = target_path + ".download"
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
            with archive.open(member, "r") as source, open(temp_target, "wb") as target:
                shutil.copyfileobj(source, target)
            os.replace(temp_target, target_path)
        finally:
            if os.path.exists(temp_target):
                try:
                    os.remove(temp_target)
                except OSError:
                    pass
    return {"wintun.dll"}


def download_wintun_dll():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "wintun-0.14.1.zip")
        download_wintun_zip(zip_path)
        return extract_wintun_dll(zip_path)


def download_core_release(release):
    if xray_process is not None:
        raise RuntimeError("Остановите Xray перед обновлением ядра")

    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, XRAY_ASSET_NAME)
        download_file(release["download_url"], zip_path)
        extracted = extract_xray_core(zip_path)
    extracted.update(download_wintun_dll())
    return extracted


def load_existing_profiles():
    """Загружает все существующие профили из папки configs при запуске приложения"""
    profile_files = glob.glob(os.path.join(CONFIGS_DIR, "*.json"))
    for file_path in profile_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                config = json.load(f)
                
            # Извлекаем информацию о профиле из конфига
            outbound = config["outbounds"][0]  # Первый outbound - наш vless
            vnext = outbound["settings"]["vnext"][0]
            stream_settings = outbound["streamSettings"]
            
            # Создаем информацию о профиле
            info = {
                "server": vnext["address"],
                "port": vnext["port"],
                "protocol": "VLESS",
                "security": stream_settings["security"],
                "network": stream_settings["network"],
                "sni": stream_settings.get("realitySettings", {}).get("serverName", ""),
                "fingerprint": stream_settings.get("realitySettings", {}).get("fingerprint", "chrome")
            }
            
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
    if not vless_url.startswith("vless://"):
        raise ValueError("Это не VLESS-ссылка.")

    full_url = vless_url[8:]
    base, _, comment = full_url.partition('#')
    uuid, _, server_part = base.partition('@')

    if '?' in server_part:
        host_port, query_string = server_part.split('?', 1)
    else:
        host_port = server_part
        query_string = ""

    if ':' not in host_port:
        raise ValueError("Неверный формат: отсутствует порт.")
    host, port = host_port.split(':', 1)
    port = int(port)
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


def save_profile_config(profile_name, config):
    safe_name = "".join(c for c in profile_name if c.isalnum() or c in " _-()[]").strip()
    filename = os.path.join(CONFIGS_DIR, f"{safe_name}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
    return filename


def update_profile_list():
    profile_listbox.delete(0, tk.END)
    for name in profiles.keys():
        profile_listbox.insert(tk.END, name)


def add_profile_from_clipboard():
    try:
        vless_url = root.clipboard_get().strip()
    except Exception:
        messagebox.showerror("Ошибка", "Не удалось получить данные из буфера обмена")
        return

    try:
        profile_name, config, info = parse_vless_url(vless_url)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка парсинга VLESS ссылки:\n{e}")
        return

    if profile_name in profiles:
        messagebox.showinfo("Инфо", f"Профиль с именем '{profile_name}' уже существует")
        return

    config_file = save_profile_config(profile_name, config)
    profiles[profile_name] = {"config_file": config_file, "info": info}
    update_profile_list()
    messagebox.showinfo("Успех", f"Профиль '{profile_name}' добавлен")


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

    core_btn.config(state="disabled", text="Загрузка списка...")

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
        published = release["published_at"][:10] if release.get("published_at") else "date unknown"
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


def update_proxy_info(profile_name):
    global current_profile_info
    
    if profile_name in profiles:
        info = profiles[profile_name]["info"]
        current_profile_info = info
        
        # Очищаем предыдущую информацию
        for widget in proxy_info_frame.winfo_children():
            widget.destroy()
        
        # Создаем заголовок
        ttk.Label(proxy_info_frame, text="Информация о подключении", font=('Helvetica', 10, 'bold')).pack(anchor='w', pady=(0, 5))
        
        # Добавляем информацию о прокси
        ttk.Label(proxy_info_frame, text=f"Сервер: {info['server']}").pack(anchor='w')
        ttk.Label(proxy_info_frame, text=f"Порт: {info['port']}").pack(anchor='w')
        ttk.Label(proxy_info_frame, text=f"Протокол: {info['protocol']}").pack(anchor='w')
        ttk.Label(proxy_info_frame, text=f"Безопасность: {info['security']}").pack(anchor='w')
        ttk.Label(proxy_info_frame, text=f"Тип сети: {info['network']}").pack(anchor='w')
        ttk.Label(proxy_info_frame, text=f"SNI: {info['sni']}").pack(anchor='w')
        ttk.Label(proxy_info_frame, text=f"Fingerprint: {info['fingerprint']}").pack(anchor='w')
        
        # Добавляем информацию о локальном SOCKS прокси
        ttk.Label(proxy_info_frame, text="\nЛокальный прокси:", font=('Helvetica', 9, 'bold')).pack(anchor='w', pady=(5, 0))
        ttk.Label(proxy_info_frame, text="Тип: SOCKS5").pack(anchor='w')
        ttk.Label(proxy_info_frame, text="Адрес: 127.0.0.1").pack(anchor='w')
        ttk.Label(proxy_info_frame, text="Порт: 10808").pack(anchor='w')
        ttk.Label(proxy_info_frame, text="Аутентификация: нет").pack(anchor='w')


def update_ui_state(is_running):
    if is_running:
        status_label.config(text="🟢 Xray запущен", foreground="green")
        toggle_btn.config(text="Stop Xray", command=stop_xray)
        add_btn.config(state="disabled")
        del_btn.config(state="disabled")
        core_btn.config(state="disabled")
        tun_check.config(state="disabled")
        profile_listbox.config(state="disabled")
    else:
        status_label.config(text="🔴 Xray не запущен", foreground="red")
        toggle_btn.config(text="Start Xray", command=start_xray)
        add_btn.config(state="normal")
        del_btn.config(state="normal")
        core_btn.config(state="normal")
        tun_check.config(state="normal")
        profile_listbox.config(state="normal")


def start_xray():
    global xray_process, stop_log_thread, log_thread

    if xray_process is not None:
        messagebox.showwarning("Предупреждение", "Xray уже запущен")
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

    tun_enabled = tun_var.get()
    if tun_enabled:
        confirmed = messagebox.askyesno(
            "TUN режим",
            "TUN режим изменяет системную маршрутизацию и обычно требует запуск от администратора.\nПродолжить?",
        )
        if not confirmed:
            return
        if not ensure_wintun_for_tun():
            return

    try:
        config_file = create_runtime_config(config_file, tun_enabled)
        xray_process = subprocess.Popen(
            [get_xray_path(), "-config", os.path.abspath(config_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            creationflags=0x08000000,
            cwd=get_app_dir(),
        )
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось запустить Xray:\n{e}")
        cleanup_runtime_config()
        xray_process = None
        return

    update_ui_state(True)
    update_proxy_info(profile_name)

    log_text.config(state="normal")
    log_text.delete("1.0", tk.END)
    log_text.config(state="disabled")

    stop_log_thread = False

    def read_log():
        global stop_log_thread, xray_process
        while not stop_log_thread:
            line = xray_process.stdout.readline()
            if line:
                log_text.config(state="normal")
                log_text.insert(tk.END, line)
                log_text.see(tk.END)
                log_text.config(state="disabled")
            else:
                break

    log_thread = threading.Thread(target=read_log, daemon=True)
    log_thread.start()


def stop_xray():
    global xray_process, stop_log_thread
    if xray_process:
        stop_log_thread = True
        xray_process.terminate()
        xray_process.wait()
        xray_process = None
        cleanup_runtime_config()
        update_ui_state(False)
        
        # Очищаем информацию о прокси при остановке
        for widget in proxy_info_frame.winfo_children():
            widget.destroy()
        ttk.Label(proxy_info_frame, text="Информация о подключении", font=('Helvetica', 10, 'bold')).pack(anchor='w', pady=(0, 5))
        ttk.Label(proxy_info_frame, text="Прокси не активен").pack(anchor='w')
    else:
        messagebox.showinfo("Инфо", "Xray не запущен")


def on_close():
    if xray_process:
        stop_xray()
    cleanup_runtime_config()
    root.destroy()


# Создаем основное окно
root = tk.Tk()
root.title("VLESS → Xray Launcher")
root.geometry("900x650")
root.resizable(False, False)
root.protocol("WM_DELETE_WINDOW", on_close)

style = ttk.Style(root)
style.theme_use("clam")

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill="both", expand=True)

# Верхняя часть с профилями слева и информацией справа
top_frame = ttk.Frame(main_frame)
top_frame.pack(side="top", fill="x")

# Левая часть верхнего фрейма (профили + кнопки)
left_top_frame = ttk.Frame(top_frame)
left_top_frame.pack(side="left", fill="y")

profile_listbox = tk.Listbox(left_top_frame, width=40, height=10)
profile_listbox.pack()

btn_frame = ttk.Frame(left_top_frame)
btn_frame.pack(fill="x", pady=5)

add_btn = ttk.Button(btn_frame, text="Добавить профиль из буфера", command=add_profile_from_clipboard)
add_btn.pack(side="left", fill="x", expand=True, padx=5)

del_btn = ttk.Button(btn_frame, text="Удалить профиль", command=delete_selected_profile)
del_btn.pack(side="left", fill="x", expand=True, padx=5)

core_btn = ttk.Button(left_top_frame, text="Загрузить ядро", command=show_core_download_dialog)
core_btn.pack(fill="x", padx=5, pady=(0, 5))

# Центральная часть верхнего фрейма (кнопка старт/стоп и статус)
center_top_frame = ttk.Frame(top_frame, width=150)
center_top_frame.pack(side="left", fill="y", padx=10)

toggle_btn = ttk.Button(center_top_frame, text="Start Xray", command=start_xray, width=15)
toggle_btn.pack(pady=(40, 5))

status_label = ttk.Label(center_top_frame, text="🔴 Xray не запущен", foreground="red")
status_label.pack()

tun_var = tk.BooleanVar(value=False)
tun_check = ttk.Checkbutton(center_top_frame, text="TUN режим", variable=tun_var)
tun_check.pack(pady=(10, 0))

# Правая часть верхнего фрейма (информация о прокси)
proxy_info_frame = ttk.LabelFrame(top_frame, text="Информация о прокси", padding=10, width=250)
proxy_info_frame.pack(side="right", fill="both", expand=True, padx=10)

# Заполняем начальную информацию
ttk.Label(proxy_info_frame, text="Информация о подключении", font=('Helvetica', 10, 'bold')).pack(anchor='w', pady=(0, 5))
ttk.Label(proxy_info_frame, text="Прокси не активен").pack(anchor='w')

# Нижняя часть — окно логов
log_frame = ttk.LabelFrame(main_frame, text="Логи Xray", padding=5)
log_frame.pack(side="bottom", fill="both", expand=True, pady=(10, 0))

log_text = tk.Text(log_frame, state="disabled", wrap="none", bg="black", fg="#00FF00", insertbackground="#00FF00")
log_text.pack(fill="both", expand=True)

# Загружаем существующие профили при запуске
load_existing_profiles()
update_profile_list()

root.mainloop()

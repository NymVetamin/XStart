import json
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import parse_qs, unquote
import os
import threading
import glob

xray_process = None
log_thread = None
stop_log_thread = False
current_profile_info = {}

profiles = {}

CONFIGS_DIR = "configs"
if not os.path.exists(CONFIGS_DIR):
    os.makedirs(CONFIGS_DIR)


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
        profile_listbox.config(state="disabled")
    else:
        status_label.config(text="🔴 Xray не запущен", foreground="red")
        toggle_btn.config(text="Start Xray", command=start_xray)
        add_btn.config(state="normal")
        del_btn.config(state="normal")
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

    try:
        xray_process = subprocess.Popen(
            ["xray.exe", "-config", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            creationflags=0x08000000
        )
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось запустить Xray:\n{e}")
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
        update_ui_state(False)
        
        # Очищаем информацию о прокси при остановке
        for widget in proxy_info_frame.winfo_children():
            widget.destroy()
        ttk.Label(proxy_info_frame, text="Информация о подключении", font=('Helvetica', 10, 'bold')).pack(anchor='w', pady=(0, 5))
        ttk.Label(proxy_info_frame, text="Прокси не активен").pack(anchor='w')
    else:
        messagebox.showinfo("Инфо", "Xray не запущен")


# Создаем основное окно
root = tk.Tk()
root.title("VLESS → Xray Launcher")
root.geometry("900x650")
root.resizable(False, False)

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

# Центральная часть верхнего фрейма (кнопка старт/стоп и статус)
center_top_frame = ttk.Frame(top_frame, width=150)
center_top_frame.pack(side="left", fill="y", padx=10)

toggle_btn = ttk.Button(center_top_frame, text="Start Xray", command=start_xray, width=15)
toggle_btn.pack(pady=(40, 5))

status_label = ttk.Label(center_top_frame, text="🔴 Xray не запущен", foreground="red")
status_label.pack()

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
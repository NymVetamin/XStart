# XStart Agent Guide

Документ для агентов, которые продолжают работу над проектом. Цель - быстро понять устройство приложения, локальный запуск, формат данных и зоны риска без повторного ресерча.

## Кратко о проекте

XStart - Windows GUI-лаунчер для Xray-core. Приложение принимает VLESS-ссылки из буфера обмена, преобразует их в JSON-конфиги Xray, сохраняет профили в `configs/`, запускает `xray.exe` с выбранным конфигом и показывает stdout/stderr Xray в окне Tkinter.

Основной пользовательский сценарий:

1. Пользователь кладет рядом с приложением `xray.exe`, `geoip.dat`, `geosite.dat`.
2. Копирует VLESS URL в буфер обмена.
3. Нажимает кнопку добавления профиля.
4. Выбирает профиль в списке.
5. Нажимает `Start Xray`.
6. Настраивает клиентское приложение на локальный SOCKS5 `127.0.0.1:10808`.

## Структура репозитория

```text
.
├── .gitignore
├── AGENTS.md
├── README.md
├── requirements.txt
├── main.py
└── XStart.exe
```

Ожидаемые runtime-файлы, которые могут появляться рядом:

```text
configs/       # JSON-конфиги профилей, создается main.py автоматически
xray.exe       # внешний бинарник Xray-core, не должен храниться в git
geoip.dat      # база Xray для routing rules, не должна храниться в git
geosite.dat    # база Xray для routing rules, не должна храниться в git
wintun.dll     # Wintun DLL для Xray TUN на Windows, не должна храниться в git
```

`.gitignore` уже игнорирует `venv`, `output`, `__pycache__`, `configs`, `geoip.dat`, `geosite.dat`, `xray.exe`, `wintun.dll`, `test.py`.

## Технологии

Фактический runtime:

- Python 3 на Windows.
- `tkinter` / `ttk` для GUI.
- Стандартная библиотека: `json`, `subprocess`, `urllib.parse`, `os`, `threading`, `glob`.
- Внешний процесс: `xray.exe`.

`requirements.txt` содержит зависимости для Eel/gevent/requests/PyInstaller-окружения, но текущий `main.py` их не импортирует. Не добавляйте новые зависимости только потому, что они есть в requirements; сначала проверьте фактическую необходимость.

## Запуск из исходников

Минимальный запуск из корня проекта:

```powershell
python main.py
```

Для полноценной проверки запуска Xray рядом с `main.py` должен быть доступен `xray.exe`, либо `xray.exe` должен находиться в `PATH`. Для правил маршрутизации в генерируемом конфиге нужны `geoip.dat` и `geosite.dat` из релиза Xray-core. Для TUN на Windows рядом с `xray.exe` также нужен `wintun.dll`.

Приложение создает папку `configs/` при импорте/старте, если она отсутствует.

## Сборка exe

В репозитории нет `.spec` файла или скрипта сборки. По составу `requirements.txt` и наличию `XStart.exe` вероятная сборка выполнялась через PyInstaller.

Базовая команда, которую стоит использовать как отправную точку:

```powershell
pyinstaller --onefile --windowed --name XStart main.py
```

После сборки проверить, что рядом с итоговым `XStart.exe` лежат внешние файлы Xray (`xray.exe`, `geoip.dat`, `geosite.dat`) и, для TUN, `wintun.dll`. Они не встраиваются текущей логикой.

## Архитектура main.py

Вся логика находится в `main.py`.

Глобальное состояние:

- `xray_process` - текущий `subprocess.Popen` для Xray или `None`.
- `log_thread` - daemon-поток чтения логов Xray.
- `stop_log_thread` - флаг остановки чтения логов.
- `current_profile_info` - информация о текущем выбранном/запущенном профиле.
- `profiles` - словарь профилей в памяти.
- `CONFIGS_DIR = "configs"` - папка с JSON-конфигами.

Ключевые функции:

- `load_existing_profiles()` - при старте читает `configs/*.json`, извлекает данные первого outbound и заполняет `profiles`.
- `parse_vless_url(vless_url)` - парсит `vless://...`, строит Xray config dict и краткую информацию для GUI.
- `save_profile_config(profile_name, config)` - очищает имя профиля, пишет JSON в `configs/<name>.json`.
- `update_profile_list()` - синхронизирует `profiles` с `Listbox`.
- `add_profile_from_clipboard()` - читает VLESS URL из буфера обмена, парсит, сохраняет профиль.
- `delete_selected_profile()` - удаляет выбранный профиль из `profiles` и файл конфига с диска.
- `update_proxy_info(profile_name)` - перерисовывает правую панель информации о прокси.
- `update_ui_state(is_running)` - переключает состояние кнопок и статус при старте/остановке Xray.
- `start_xray()` - проверяет выбранный профиль, запускает `xray.exe -config <config_file>`, стартует поток чтения логов.
- `stop_xray()` - завершает процесс Xray, сбрасывает UI и информацию о прокси.

GUI создается внизу файла на верхнем уровне, затем вызываются `load_existing_profiles()`, `update_profile_list()` и `root.mainloop()`.

## Формат профилей

Профиль в памяти:

```python
profiles[profile_name] = {
    "config_file": "configs/<profile_name>.json",
    "info": {
        "server": "...",
        "port": 443,
        "protocol": "VLESS",
        "security": "REALITY",
        "network": "tcp",
        "sni": "...",
        "fingerprint": "chrome",
    },
}
```

Имя профиля берется из fragment VLESS-ссылки после `#`. Если fragment отсутствует, используется `"Без имени"`. Перед записью в файл имя фильтруется: разрешены alnum-символы, пробел, `_`, `-`, `(`, `)`, `[`, `]`.

Важная особенность: если после фильтрации имя стало пустым, текущая логика создаст файл `configs/.json`. Это стоит исправлять при работах с валидацией профилей.

## Генерируемый Xray config

`parse_vless_url()` создает конфиг:

- `log.loglevel = "info"`;
- inbound SOCKS:
  - tag `socks-in`;
  - listen `127.0.0.1`;
  - port `10808`;
  - protocol `socks`;
  - auth `noauth`;
- основной outbound:
  - tag `vless-reality`;
  - protocol `vless`;
  - address/port/user id из VLESS URL;
  - `streamSettings.security = "reality"`;
  - `network` из query param `type`, default `tcp`;
  - `realitySettings.serverName` из `sni`;
  - `publicKey` из `pbk`;
  - `shortId` из `sid`;
  - `fingerprint` из `fp`, default `chrome`;
  - `spiderX = "/"`;
- дополнительные outbounds:
  - `direct` через `freedom`;
  - `block` через `blackhole`;
- routing:
  - private IP/domain напрямую;
  - некоторые UDP-порты и рекламно-аналитические домены в block;
  - UDP 443 вне RU в block;
  - все из `socks-in` в `vless-reality`.

## Парсинг VLESS URL

Ожидаемый формат:

```text
vless://<uuid>@<host>:<port>?type=<network>&security=reality&sni=<sni>&pbk=<public_key>&sid=<short_id>&fp=<fingerprint>&flow=<flow>#<profile_name>
```

Текущие ограничения:

- Проверяется только префикс `vless://`.
- IPv6 host с двоеточиями корректно не поддерживается, потому что host/port делятся через `split(':', 1)`.
- Query param `security` фактически игнорируется: в конфиг всегда пишется `reality`.
- Не валидируется UUID.
- Не валидируются обязательные для REALITY параметры `pbk`, `sni`, `sid`.
- Повторные query params берутся по первому значению.

Если расширяете поддержку VLESS, лучше сначала покрыть `parse_vless_url()` тестами, потому что это самая важная чистая функция в проекте.

## Работа с процессом Xray

Запуск:

```python
subprocess.Popen(
    ["xray.exe", "-config", config_file],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
    universal_newlines=True,
    creationflags=0x08000000,
)
```

`creationflags=0x08000000` скрывает консольное окно на Windows (`CREATE_NO_WINDOW`).

Логи читаются в daemon-потоке через `xray_process.stdout.readline()` и вставляются напрямую в `tk.Text`.

Важный риск: Tkinter не является thread-safe. Сейчас фоновый поток напрямую меняет `log_text`. При активной доработке логов лучше передавать строки в основной поток через `queue.Queue` + `root.after(...)`.

## UI

Окно фиксированное:

- title: `VLESS -> Xray Launcher`;
- размер: `900x650`;
- `resizable(False, False)`;
- тема ttk: `clam`.

Основные зоны:

- слева сверху `Listbox` профилей;
- под ним кнопки добавления из буфера и удаления;
- по центру кнопка `Start Xray` / `Stop Xray` и статус;
- справа панель информации о текущем прокси;
- снизу `Text` с логами Xray.

Во время работы Xray добавление, удаление и список профилей блокируются.

## Проверка изменений

Быстрые проверки без запуска GUI:

```powershell
python -m py_compile main.py
```

Для проверки парсинга можно временно импортировать `parse_vless_url`, но сейчас `main.py` создает GUI на верхнем уровне при импорте. Это мешает unit-тестам. Если планируются тесты, сначала отделите чистую логику от создания окна:

- оставить `parse_vless_url()` и генерацию конфигов импортируемыми без GUI;
- перенести создание `root` и `mainloop()` в `main()` под `if __name__ == "__main__":`.

Ручная проверка GUI:

1. Запустить `python main.py`.
2. Скопировать валидную VLESS REALITY ссылку.
3. Нажать добавление профиля.
4. Убедиться, что появился `configs/<profile>.json`.
5. Выбрать профиль и нажать `Start Xray`.
6. Проверить статус, логи и порт `127.0.0.1:10808`.
7. Нажать `Stop Xray` и убедиться, что процесс завершен.

## Известные проблемы и технический долг

- Код смешивает бизнес-логику, работу с файлами, процесс Xray и GUI в одном файле.
- Нет тестов.
- Нет воспроизводимого сценария сборки exe.
- `requirements.txt` не соответствует фактическим импортам.
- `main.py` нельзя безопасно импортировать в тестах из-за создания GUI на верхнем уровне.
- Tkinter обновляется из фонового потока логов.
- `xray.exe` ищется только как `"xray.exe"` относительно текущей рабочей директории или `PATH`; рядом с exe при запуске из другого cwd может не найтись.
- Нет обработки аварийного завершения Xray с обновлением UI после падения процесса.
- Нет защиты от перезаписи файла, если разные имена профилей после фильтрации дают одинаковый safe filename.
- Нет поддержки редактирования профиля.
- Нет проверки занятости локального порта `10808`.
- README в текущем терминале может отображаться с mojibake; при правках сохраняйте UTF-8.

## Рекомендации агентам

- Перед изменениями всегда читайте актуальный `main.py`, потому что проект маленький и вся логика централизована.
- Не коммитьте runtime-файлы `xray.exe`, `wintun.dll`, `geoip.dat`, `geosite.dat`, `configs/*.json`, если пользователь явно не просит.
- Если меняете формат JSON-конфига, проверьте совместимость с `load_existing_profiles()`.
- Если меняете имя/путь `CONFIGS_DIR`, обновите загрузку, сохранение и README.
- Если меняете порт SOCKS, обновите одновременно:
  - generated inbound в `parse_vless_url()`;
  - текст в `update_proxy_info()`;
  - README;
  - этот документ.
- Если добавляете тесты, начните с извлечения чистой логики из GUI-инициализации.
- Для серьезной доработки логов или мониторинга процесса сначала исправьте thread-safety Tkinter.
- Для UX-изменений учитывайте, что приложение Windows-only из-за `xray.exe`, `creationflags` и модели распространения через `.exe`.

## Быстрая карта файлов

- `main.py` - единственный исходный файл приложения.
- `README.md` - пользовательская инструкция на русском.
- `requirements.txt` - зафиксированное окружение, частично избыточное для текущего кода.
- `XStart.exe` - собранный бинарник, вероятно PyInstaller onefile/windowed.
- `.gitignore` - исключает локальное окружение и внешние бинарные/runtime-файлы Xray.

## Добавлено: TUN и загрузка ядра

В `main.py` добавлены два пользовательских сценария:

- чекбокс `TUN режим` рядом со статусом запуска;
- кнопка `Загрузить ядро` под кнопками управления профилями.

### TUN режим

TUN не меняет сохраненный профиль в `configs/`. При старте `create_runtime_config(config_file, tun_enabled)` читает выбранный JSON, добавляет inbound `tun` и пишет временный runtime-конфиг в системную temp-папку. После остановки Xray или закрытия окна `cleanup_runtime_config()` удаляет этот временный файл.

Добавляемый inbound:

```json
{
  "tag": "tun-in",
  "protocol": "tun",
  "settings": {
    "name": "xstart0",
    "mtu": 1500,
    "gateway": ["10.19.0.1/30", "fc00::1/126"],
    "dns": ["1.1.1.1", "8.8.8.8"],
    "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
    "autoOutboundsInterface": "auto"
  },
  "sniffing": {
    "enabled": true,
    "destOverride": ["http", "tls", "quic"]
  }
}
```

Маршрутизация вставляет первым правило `tun-in -> vless-reality`, чтобы TUN-трафик не перехватывался более ранними direct/block правилами базового профиля. `autoOutboundsInterface = "auto"` нужен, чтобы снизить риск петли, когда трафик самого Xray попадает обратно в TUN.

Практические ограничения:

- TUN с `autoSystemRoutingTable` рассчитан на Windows и обычно требует запуск от администратора.
- Перед стартом с включенным TUN приложение показывает предупреждение.
- Если Xray не сможет создать интерфейс или изменить маршруты, причина будет в логах Xray.

### Загрузка ядра

Загрузчик использует официальный GitHub API:

```text
https://api.github.com/repos/XTLS/Xray-core/releases
```

Логика:

1. `fetch_xray_releases()` получает релизы.
2. Draft и prerelease пропускаются.
3. Пользователю показываются первые 4 релиза, где есть asset `Xray-windows-64.zip`.
4. `download_core_release()` скачивает выбранный zip и распаковывает файлы рядом с `XStart.exe` или, при запуске из исходников, рядом с `main.py`.

Безопасность загрузки:

- исходный URL должен быть `https://github.com/XTLS/Xray-core/releases/download/...`;
- после редиректа финальный URL должен остаться на `github.com` или `*.githubusercontent.com`;
- лимит zip - `120 MB`;
- из архива Xray извлекаются только `xray.exe`, `geoip.dat`, `geosite.dat`;
- для TUN дополнительно скачивается официальный `https://www.wintun.net/builds/wintun-0.14.1.zip`, проверяется SHA256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`, затем извлекается только `wintun/bin/amd64/wintun.dll`;
- пути внутри zip отбрасываются через `os.path.basename`, path traversal не используется;
- временный файл `<name>.download` удаляется при ошибке;
- обновление запрещено, пока текущий `xray_process` запущен.

Оставшийся риск: checksum/signature скачанного Xray asset сейчас не проверяется. Wintun zip проверяется по опубликованному SHA256. Если добавляете checksum для Xray, используйте официальный источник Xray-core и не ослабляйте allowlist файлов.

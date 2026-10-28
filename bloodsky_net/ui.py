"""Russian-language desktop UI for BLOODSKY NET (Tk 8.6, Windows 10/11)."""
from __future__ import annotations

from collections import deque
from dataclasses import asdict
import ipaddress
import math
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from . import network as net
from . import wifi
from . import topology
from . import fdb
from .storage import Storage

BG = "#0B1220"
SIDEBAR = "#101B2D"
PANEL = "#142238"
PANEL_ALT = "#1B2D45"
TEXT = "#EAF2FC"
MUTED = "#91A7BE"
BLUE = "#4ABEF1"
GREEN = "#4CD4A5"
YELLOW = "#FFBD60"
RED = "#FF6D7D"
BORDER = "#2C4058"


class NetApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"BLOODSKY NET  ·  Диагностика сети  ·  v{__version__}")
        self.geometry("1380x860")
        self.minsize(980, 640)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self.shutdown)
        self.store = Storage()
        self.devices: dict[str, net.Device] = self.store.load_devices()
        self.topology_snapshots: dict[str, topology.TopologySnapshot] = {}
        self.snmp_busy = False
        self.snmp_profiles: dict[str, topology.SNMPCredentials] = {}  # RAM only
        self.snmp_due: dict[str, float] = {}
        self.topology_received: dict[str, float] = {}
        self.topology_failed: set[str] = set()
        self.snmp_auto_enabled = False
        self.snmp_interval = 60
        self.state_lock = threading.Lock()
        self.messages: queue.Queue = queue.Queue()
        self.scan_stop = threading.Event()
        self.monitor_stop = threading.Event()
        self.scanning = False
        self.monitoring = False
        self.gateway, route_ip = net.default_gateway()
        self.local_route_ip = route_ip
        self.adapters = net.get_adapters()
        self.network_value = tk.StringVar(value=net.suggested_network(self.adapters, route_ip))
        self.monitor_enabled = tk.BooleanVar(value=True)
        self.interval_value = tk.StringVar(value="5")
        self.current_page = "Обзор"
        self.monitor_interval = 5
        self.pages: dict[str, tk.Frame] = {}
        self.nav_buttons: dict[str, tk.Button] = {}
        self.wifi_report = wifi.WifiReport(wifi.WifiStatus(), [], [])
        self.wifi_warning_previous = ""
        self.wifi_previously_observed = False
        self.traffic_last_rate = (0.0, 0.0)
        self.mac_history = net.MacHistory()
        self.ip_alerts: dict[str, net.MacChange] = {}
        self.ip_alert_expiry: dict[str, float] = {}
        self.alerts_enabled = tk.BooleanVar(value=True)
        self.alert_last: dict[tuple[str, str, str], float] = {}
        self.alert_token = 0
        self.wifi_last_saved = float('-inf')
        self.latency_history: deque[float | None] = deque(maxlen=100)
        self.signal_history: deque[float | None] = deque(self.store.wifi_signal_history(100), maxlen=100)
        self.traffic_samples: deque[tuple[float, dict]] = deque(maxlen=2)
        self.selected_ip = ""
        self._dirty = False
        self._last_paint = 0.0
        self._closed = False
        self._style()
        self._layout()
        self._refresh_ui()
        self.after(150, self._drain)
        self.after(1100, self._traffic_tick)
        self.after(1000, self._snmp_tick)
        self._read_wifi_background()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Night.Treeview", background=PANEL, foreground=TEXT,
                        fieldbackground=PANEL, rowheight=29, borderwidth=0,
                        font=("Segoe UI", 10))
        style.map("Night.Treeview", background=[("selected", "#235577")], foreground=[("selected", "#FFFFFF")])
        style.configure("Night.Treeview.Heading", background=PANEL_ALT, foreground=TEXT,
                        font=("Segoe UI Semibold", 10), relief="flat", padding=9)
        style.map("Night.Treeview.Heading", background=[("active", "#29415E")])
        style.configure("Night.Vertical.TScrollbar", background=PANEL_ALT, troughcolor=BG, arrowsize=13)
        style.configure("Night.TCombobox", fieldbackground=PANEL_ALT, background=PANEL_ALT,
                        foreground=TEXT, arrowcolor=BLUE)
        style.configure("Night.TSpinbox", fieldbackground=PANEL_ALT, background=PANEL_ALT,
                        foreground=TEXT, arrowcolor=BLUE)
        style.configure("Night.Horizontal.TProgressbar", troughcolor=PANEL_ALT, background=BLUE)

    def _label(self, parent, text, size=10, bold=False, color=TEXT, **kw):
        return tk.Label(parent, text=text, font=("Segoe UI Semibold" if bold else "Segoe UI", size),
                        fg=color, bg=parent.cget("bg"), **kw)

    def _button(self, parent, text, command, primary=False, **kw):
        base = dict(font=("Segoe UI Semibold", 10), relief="flat", bd=0, cursor="hand2",
                    padx=17, pady=9, activeforeground=TEXT,
                    bg=BLUE if primary else PANEL_ALT, fg=BG if primary else TEXT,
                    activebackground="#7FD8FF" if primary else "#294562")
        base.update(kw)
        return tk.Button(parent, text=text, command=command, **base)

    def _panel(self, parent, **kw):
        return tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1, **kw)

    def _tree(self, parent, cols, widths, stretch=None):
        container = tk.Frame(parent, bg=PANEL)
        table = ttk.Treeview(container, columns=cols, show="headings", style="Night.Treeview")
        for name, width in zip(cols, widths):
            table.heading(name, text=name)
            table.column(name, width=width, anchor="w", stretch=(stretch is None or name in stretch))
        sb = ttk.Scrollbar(container, orient="vertical", command=table.yview,
                           style="Night.Vertical.TScrollbar")
        table.configure(yscrollcommand=sb.set)
        table.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return container, table

    def _layout(self):
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)
        sidebar = tk.Frame(outer, bg=SIDEBAR, width=215)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        brand = tk.Frame(sidebar, bg=SIDEBAR)
        brand.pack(fill="x", padx=20, pady=(30, 5))
        self._label(brand, "◉  BLOODSKY", 18, True, BLUE).pack(anchor="w")
        self._label(brand, "N E T W O R K  M O N I T O R", 8, color=MUTED).pack(anchor="w", pady=(2, 0))
        self._label(sidebar, "РАЗДЕЛЫ", 9, True, MUTED).pack(anchor="w", padx=22, pady=(35, 12))
        navigation = [("◫", "Обзор"), ("▤", "Устройства"), ("◇", "Карта сети"),
                      ("◉", "Wi-Fi"), ("⌁", "Диагностика"), ("▣", "События")]
        for glyph, name in navigation:
            btn = tk.Button(sidebar, text=f"  {glyph}   {name}", relief="flat", borderwidth=0,
                            anchor="w", padx=19, pady=13, font=("Segoe UI", 11),
                            bg=SIDEBAR, fg=TEXT, activebackground=PANEL_ALT,
                            activeforeground=BLUE, cursor="hand2",
                            command=lambda n=name: self.show_page(n))
            btn.pack(fill="x", padx=9, pady=2)
            self.nav_buttons[name] = btn
        tk.Frame(sidebar, bg=SIDEBAR).pack(fill="both", expand=True)
        self._label(sidebar, f"BLOODSKY NET  v{__version__}", 9, color=MUTED).pack(anchor="w", padx=22)
        self._label(sidebar, "Локально • без облака", 9, color=MUTED).pack(anchor="w", padx=22, pady=(4, 25))

        right = tk.Frame(outer, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        heading = tk.Frame(right, bg=BG)
        heading.pack(fill="x", padx=25, pady=(23, 15))
        self.title_label = self._label(heading, "Обзор сети", 22, True)
        self.title_label.pack(side="left")
        self.state_label = self._label(heading, "●  ГОТОВО", 10, True, GREEN)
        self.state_label.pack(side="right", padx=7)

        controls = self._panel(right)
        controls.pack(fill="x", padx=25, pady=(0, 17))
        self._label(controls, "Подсеть", 10, color=MUTED).pack(side="left", padx=(15, 9), pady=13)
        self.cidr_entry = tk.Entry(controls, textvariable=self.network_value,
                                   width=20, bg=PANEL_ALT, fg=TEXT,
                                   insertbackground=TEXT, relief="flat", bd=0,
                                   font=("Consolas", 11))
        self.cidr_entry.pack(side="left", ipady=9)
        self.scan_button = self._button(controls, "Сканировать", self.start_scan, primary=True)
        self.scan_button.pack(side="left", padx=12)
        self.stop_button = self._button(controls, "Стоп", self.stop_scan)
        self.stop_button.pack(side="left")
        self.monitor_check = tk.Checkbutton(controls, text="Мониторинг", variable=self.monitor_enabled,
                                           command=self.toggle_monitor, bg=PANEL, fg=TEXT,
                                           selectcolor=BG, activebackground=PANEL,
                                           activeforeground=TEXT, font=("Segoe UI", 10))
        self.monitor_check.pack(side="left", padx=(22, 5))
        interval = ttk.Combobox(controls, values=("3", "5", "10", "15", "30", "60"),
                                width=4, textvariable=self.interval_value, state="readonly", style="Night.TCombobox")
        interval.pack(side="left", padx=(0, 5))
        interval.bind("<<ComboboxSelected>>", lambda e: setattr(self, "monitor_interval", int(self.interval_value.get())))
        self._label(controls, "сек", 9, color=MUTED).pack(side="left")
        self.progress = ttk.Progressbar(right, mode="determinate", maximum=100,
                                         style="Night.Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=26, pady=(0, 7))
        self.page_holder = tk.Frame(right, bg=BG)
        self.page_holder.pack(fill="both", expand=True, padx=25, pady=(2, 14))
        self._page_overview()
        self._page_devices()
        self._page_map()
        self._page_wifi()
        self._page_tools()
        self._page_events()
        self.alert_banner = self._label(right, "", 10, True, YELLOW)
        self.alert_banner.pack(fill="x", anchor="w", padx=26, pady=(0, 4))
        self.status_line = self._label(right, "Ожидание сканирования локальной сети", 9, color=MUTED)
        self.status_line.pack(fill="x", anchor="w", padx=26, pady=(0, 15))
        self.show_page("Обзор")

    def _new_page(self, name):
        frame = tk.Frame(self.page_holder, bg=BG)
        self.pages[name] = frame
        return frame

    def show_page(self, page):
        for fr in self.pages.values():
            fr.pack_forget()
        self.pages[page].pack(fill="both", expand=True)
        self.current_page = page
        self.title_label.configure(text={"Обзор": "Обзор сети", "Устройства": "Обнаруженные устройства",
                                         "Карта сети": "Карта локальной сети", "Wi-Fi": "Мониторинг Wi-Fi",
                                         "Диагностика": "Инструменты диагностики", "События": "Журнал событий"}[page])
        for name, btn in self.nav_buttons.items():
            btn.configure(bg=PANEL_ALT if name == page else SIDEBAR,
                          fg=BLUE if name == page else TEXT)
        self._refresh_ui()

    def _page_overview(self):
        parent = self._new_page("Обзор")
        metrics = tk.Frame(parent, bg=BG)
        metrics.pack(fill="x", pady=(0, 18))
        self.metrics: dict[str, tk.Label] = {}
        for key, title, color in [("online", "В СЕТИ", GREEN), ("offline", "НЕДОСТУПНЫ", RED),
                                   ("ip", "ВОЗМОЖНЫЕ IP-КОНФЛИКТЫ", YELLOW), ("wifi", "СИГНАЛ WI-FI", BLUE)]:
            pane = self._panel(metrics)
            pane.pack(side="left", fill="both", expand=True, padx=(0, 10))
            self._label(pane, title, 9, True, MUTED).pack(anchor="w", padx=16, pady=(15, 5))
            value = self._label(pane, "—", 24, True, color)
            value.pack(anchor="w", padx=16, pady=(0, 16))
            self.metrics[key] = value
        detail = self._panel(parent)
        detail.pack(fill="x", pady=(0, 17))
        self.adapter_label = self._label(detail, "Адаптер: —", 10, color=TEXT)
        self.adapter_label.pack(anchor="w", padx=15, pady=(15, 5))
        self.gw_label = self._label(detail, "Шлюз: —", 10, color=MUTED)
        self.gw_label.pack(anchor="w", padx=15, pady=(0, 5))
        self.traffic_label = self._label(detail, "Трафик адаптера: измерение…", 10, color=MUTED)
        self.traffic_label.pack(anchor="w", padx=15, pady=(0, 13))
        charts = tk.Frame(parent, bg=BG)
        charts.pack(fill="both", expand=True)
        a = self._panel(charts)
        a.pack(side="left", fill="both", expand=True, padx=(0, 9))
        self._label(a, "ЗАДЕРЖКА ДО ШЛЮЗА  ·  ms", 10, True, TEXT).pack(anchor="w", padx=16, pady=(14, 8))
        self.latency_canvas = tk.Canvas(a, bg=PANEL, highlightthickness=0, height=220)
        self.latency_canvas.pack(fill="both", expand=True, padx=11, pady=(0, 10))
        self.latency_canvas.bind("<Configure>", lambda e: self._draw_charts())
        b = self._panel(charts)
        b.pack(side="left", fill="both", expand=True, padx=(9, 0))
        self._label(b, "УРОВЕНЬ WI-FI  ·  %", 10, True, TEXT).pack(anchor="w", padx=16, pady=(14, 8))
        self.signal_canvas = tk.Canvas(b, bg=PANEL, highlightthickness=0, height=220)
        self.signal_canvas.pack(fill="both", expand=True, padx=11, pady=(0, 10))
        self.signal_canvas.bind("<Configure>", lambda e: self._draw_charts())
        self._label(parent, "Карта отображает логические связи обнаруженных устройств. Физические порты и кабели без SNMP/LLDP неизвестны.",
                    9, color=MUTED).pack(anchor="w", pady=(12, 0))

    def _page_devices(self):
        parent = self._new_page("Устройства")
        toolbar = tk.Frame(parent, bg=BG)
        toolbar.pack(fill="x", pady=(0, 10))
        self.devices_count = self._label(toolbar, "Список ещё пуст", 10, color=MUTED)
        self.devices_count.pack(side="left")
        self._button(toolbar, "Экспорт CSV", self.export_csv).pack(side="right", padx=(6, 0))
        self._button(toolbar, "Отчёт JSON", self.export_json).pack(side="right", padx=(6, 0))
        frame, self.device_table = self._tree(parent,
            ("IP-адрес", "Имя устройства", "Тип", "MAC", "Производитель", "Состояние", "Ping, мс"),
            (122, 160, 225, 141, 151, 109, 92))
        frame.pack(fill="both", expand=True)
        self.device_table.tag_configure("up", foreground=GREEN)
        self.device_table.tag_configure("down", foreground=RED)
        self.device_table.bind("<<TreeviewSelect>>", self._device_selected)
        self.device_table.bind("<Double-1>", self._device_double_click)
        detail = self._panel(parent)
        detail.pack(fill="x", pady=(11, 0))
        self.device_detail = self._label(detail, "Выберите устройство для просмотра сведений.", 10, color=MUTED)
        self.device_detail.pack(anchor="w", padx=13, pady=13)

    def _page_map(self):
        parent = self._new_page("Карта сети")
        top = tk.Frame(parent, bg=BG)
        top.pack(fill="x", pady=(0, 10))
        self._label(top, "Зелёный — доступен     Красный — недоступен     Жёлтый — конфликт под вопросом", 10,
                    color=MUTED).pack(side="left")
        self._button(top, "Сохранить карту SVG", self.export_map).pack(side="right", padx=(8, 0))
        self._button(top, "Опрос SNMP/LLDP", self._snmp_dialog, primary=True).pack(side="right")
        self._button(top, "Стоп автоопрос", self._stop_snmp_auto).pack(side="right", padx=(0, 8))
        shell = self._panel(parent)
        shell.pack(fill="both", expand=True)
        self.map_canvas = tk.Canvas(shell, bg=PANEL, highlightthickness=0, scrollregion=(0, 0, 1300, 850))
        vert = tk.Scrollbar(shell, orient="vertical", command=self.map_canvas.yview)
        hori = tk.Scrollbar(shell, orient="horizontal", command=self.map_canvas.xview)
        self.map_canvas.configure(yscrollcommand=vert.set, xscrollcommand=hori.set)
        vert.pack(side="right", fill="y")
        hori.pack(side="bottom", fill="x")
        self.map_canvas.pack(side="left", fill="both", expand=True)
        self.map_canvas.bind("<Configure>", lambda e: self._draw_map())
        self.map_canvas.bind("<MouseWheel>", lambda e: self.map_canvas.yview_scroll(-int(e.delta / 120), "units"))
        self.topology_note = self._label(parent, "LLDP: ещё не опрашивались управляемые устройства. Сплошная линия — подтверждённый LLDP-сосед.",
                                         9, color=MUTED)
        self.topology_note.pack(anchor="w", pady=(8, 5))
        frame, self.neighbor_table = self._tree(parent,
            ("SNMP IP", "Порт устройства", "Сосед LLDP", "Порт соседа", "Совпадение IP"),
            (125, 145, 200, 150, 135))
        frame.configure(height=155)
        self.neighbor_table.configure(height=4)
        frame.pack(fill="x")
        self.fdb_note = self._label(parent, "FDB: ещё нет данных. Изученные MAC/порты — не подтверждение физического кабеля.",
                                    9, color=MUTED)
        self.fdb_note.pack(anchor="w", pady=(7, 3))
        fdb_frame, self.fdb_table = self._tree(parent,
            ("Коммутатор", "MAC (изучен)", "Порт", "VLAN", "IP (по MAC)"),
            (125, 165, 155, 80, 155))
        self.fdb_table.configure(height=4)
        fdb_frame.pack(fill="x")

    def _page_wifi(self):
        parent = self._new_page("Wi-Fi")
        bar = tk.Frame(parent, bg=BG)
        bar.pack(fill="x", pady=(0, 13))
        self.wifi_current_label = self._label(bar, "Проверка Wi-Fi адаптера…", 11, True)
        self.wifi_current_label.pack(side="left")
        self._button(bar, "Обновить эфир", self._read_wifi_background, primary=True).pack(side="right")
        self.wifi_status_label = self._label(parent, "Текущий SSID, BSSID, канал, уровень сигнала и стандарт подключения", 10, color=MUTED)
        self.wifi_status_label.pack(anchor="w", pady=(0, 8))
        self.wifi_warning_label = self._label(parent, "", 10, color=YELLOW, wraplength=850, justify="left")
        self.wifi_warning_label.pack(anchor="w", pady=(0, 14))
        self._label(parent, "ИСТОРИЯ СИГНАЛА WI-FI (локально, до 7 дней)", 10, True, MUTED).pack(anchor="w", pady=(0, 6))
        self.wifi_signal_canvas = tk.Canvas(parent, bg=PANEL, highlightthickness=0, height=110)
        self.wifi_signal_canvas.pack(fill="x", pady=(0, 14))
        self.wifi_signal_canvas.bind("<Configure>", lambda _e: self._draw_curve(self.wifi_signal_canvas, list(self.signal_history), BLUE, 100))
        self._label(parent, "ТОЧКИ ДОСТУПА В ЗОНЕ ВИДИМОСТИ", 10, True, MUTED).pack(anchor="w", pady=(0, 9))
        frame, self.wifi_table = self._tree(parent,
            ("SSID", "BSSID", "Сигнал", "Канал", "Диапазон*", "Защита", "Стандарт"),
            (190, 156, 85, 75, 122, 175, 125))
        frame.pack(fill="both", expand=True)
        self._label(parent, "* Диапазон по номеру канала определяется ориентировочно; часть номеров пересекается между 5 и 6 ГГц.",
                    9, color=MUTED).pack(anchor="w", pady=(9, 0))

    def _page_tools(self):
        parent = self._new_page("Диагностика")
        control = self._panel(parent)
        control.pack(fill="x", pady=(0, 15))
        line = tk.Frame(control, bg=PANEL)
        line.pack(fill="x", padx=15, pady=15)
        self.tool_kind = tk.StringVar(value="Ping × 4")
        self.tool_select = ttk.Combobox(line, values=("Ping × 4", "Traceroute", "DNS", "TCP-порт", "ARP-таблица", "Маршруты IPv4"),
                                        textvariable=self.tool_kind, width=19,
                                        state="readonly", style="Night.TCombobox")
        self.tool_select.pack(side="left", padx=(0, 12), ipady=5)
        self.tool_target = tk.StringVar(value=self.gateway or "192.168.1.1")
        self._label(line, "Хост:", 10, color=MUTED).pack(side="left", padx=(0, 7))
        entry = tk.Entry(line, textvariable=self.tool_target, bg=PANEL_ALT, fg=TEXT,
                         insertbackground=TEXT, relief="flat", font=("Consolas", 11), width=28)
        entry.pack(side="left", ipady=9, padx=(0, 13))
        self.tool_port = tk.StringVar(value="443")
        self._label(line, "Порт:", 10, color=MUTED).pack(side="left", padx=(0, 5))
        port_entry = tk.Entry(line, textvariable=self.tool_port, bg=PANEL_ALT, fg=TEXT,
                              insertbackground=TEXT, relief="flat", font=("Consolas", 11), width=6)
        port_entry.pack(side="left", ipady=9, padx=(0, 13))
        self.tool_button = self._button(line, "Выполнить", self.run_tool, primary=True)
        self.tool_button.pack(side="left")
        console_frame = self._panel(parent)
        console_frame.pack(fill="both", expand=True)
        self.console = tk.Text(console_frame, wrap="word", bg=PANEL, fg="#C8EEFF",
                               font=("Consolas", 11), insertbackground=TEXT,
                               selectbackground="#325878", relief="flat", borderwidth=0, padx=18, pady=18)
        self.console.pack(fill="both", expand=True)
        self.console.insert("end", "BLOODSKY NET  ·  Инструменты диагностики\n\nВыберите инструмент, IP или имя хоста и нажмите «Выполнить».\nКоманды выполняются в отдельном потоке, интерфейс не зависает.\n")
        self.console.configure(state="disabled")

    def _page_events(self):
        parent = self._new_page("События")
        self._label(parent, "Все изменения состояний и предупреждения сохраняются в локальной базе SQLite.",
                    10, color=MUTED).pack(anchor="w", pady=(0, 12))
        tk.Checkbutton(parent, text="Показывать предупреждения внутри окна", variable=self.alerts_enabled,
                       bg=BG, fg=TEXT, selectcolor=PANEL, activebackground=BG,
                       activeforeground=TEXT, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))
        frame, self.events_table = self._tree(parent,
            ("Дата/время", "Уровень", "Событие", "Подробности"),
            (195, 125, 225, 630))
        frame.pack(fill="both", expand=True)
        self.events_table.tag_configure("error", foreground=RED)
        self.events_table.tag_configure("warning", foreground=YELLOW)
        self.events_table.tag_configure("info", foreground=TEXT)

    def _set_state(self, text, color=GREEN):
        self.state_label.configure(text=f"●  {text}", fg=color)

    def _set_status(self, text):
        self.status_line.configure(text=text)

    def start_scan(self):
        if self.scanning:
            return
        try:
            cidr = str(net.validate_scan_cidr(self.network_value.get(), self.adapters))
        except ValueError as exc:
            messagebox.showwarning("Неверная подсеть", str(exc), parent=self)
            return
        self.scanning = True
        self.scan_stop.clear()
        self.progress["value"] = 0
        self.scan_button.configure(state="disabled")
        self._set_state("СКАНИРОВАНИЕ", YELLOW)
        self._set_status(f"Поиск устройств в подсети {cidr}...")
        t = threading.Thread(target=self._scan_worker, args=(cidr,), daemon=True)
        t.start()

    def stop_scan(self):
        if self.scanning:
            self.scan_stop.set()
            self._set_status("Остановка сканирования — завершаются уже начатые запросы")

    def _scan_worker(self, cidr):
        try:
            result = net.scan_network(cidr, self.gateway, self.scan_stop,
                                      lambda device: self.messages.put(("found", device)),
                                      lambda n, total: self.messages.put(("progress", n, total)))
            self.messages.put(("scan_complete", cidr, result, self.scan_stop.is_set()))
        except Exception as exc:
            self.messages.put(("scan_error", str(exc)))

    def toggle_monitor(self):
        if self.monitor_enabled.get():
            self._start_monitor()
        else:
            self.monitor_stop.set()
            self.monitoring = False
            self._set_state("ПАУЗА", YELLOW)

    def _start_monitor(self):
        if self.monitoring or self._closed:
            return
        self.monitor_stop = threading.Event()
        self.monitoring = True
        threading.Thread(target=self._monitor_worker, args=(self.monitor_stop,), daemon=True).start()
        self._set_state("МОНИТОРИНГ", GREEN)

    def _monitor_worker(self, stop):
        tick = 0
        while not stop.is_set():
            if not self.scanning:
                with self.state_lock:
                    ips = list(self.devices.keys())
                    open_ports = {ip: list(d.ports) for ip, d in self.devices.items() if d.ports}
                if self.gateway and self.gateway not in ips:
                    ips.append(self.gateway)  # always measure gateway for latency graph
                if ips:
                    samples = net.poll_devices(ips, stop, open_ports)
                    neighbors = net.arp_table()
                    self.messages.put(("monitor", samples, neighbors))
                if tick % 3 == 0:
                    self._read_wifi_background()
            tick += 1
            stop.wait(max(3, self.monitor_interval))
        self.messages.put(("monitor_stopped", stop))

    def _read_wifi_background(self):
        if self._closed:
            return
        threading.Thread(target=lambda: self.messages.put(("wifi", wifi.read_wifi())), daemon=True).start()

    def _drain(self):
        if self._closed:
            return
        count = 0
        try:
            while count < 175:
                item = self.messages.get_nowait()
                count += 1
                kind = item[0]
                if kind == "found":
                    d = item[1]
                    with self.state_lock:
                        old = self.devices.get(d.ip)
                        if old and not d.mac:
                            d.mac, d.vendor = old.mac, old.vendor
                        self.devices[d.ip] = d
                    if not old:
                        self._event("info", "Новое устройство", f"{d.ip}  {d.hostname}  {d.kind}")
                    self._dirty = True
                elif kind == "progress":
                    self.progress["value"] = int(100 * item[1] / max(1, item[2]))
                    self._set_status(f"Сканирование: проверено {item[1]} из {item[2]} IP")
                elif kind == "scan_complete":
                    self._scan_complete(*item[1:])
                elif kind == "scan_error":
                    self._scan_finished()
                    self._set_status("Ошибка сканирования: " + item[1])
                    self._event("error", "Ошибка сканирования", item[1])
                elif kind == "monitor":
                    self._update_monitor(item[1], item[2])
                elif kind == "wifi":
                    self._update_wifi(item[1])
                elif kind == "topology":
                    self.snmp_busy = False
                    snapshot = item[1]
                    self.topology_snapshots[snapshot.source_ip] = snapshot
                    self.topology_received[snapshot.source_ip] = time.monotonic()
                    self.topology_failed.discard(snapshot.source_ip)
                    self.snmp_due[snapshot.source_ip] = time.monotonic() + self.snmp_interval
                    self._event("info", "SNMP опрос", f"{snapshot.source_ip}: LLDP {len(snapshot.neighbors)}, FDB {len(snapshot.fdb_entries)}")
                    self._set_status(f"SNMP {snapshot.source_ip}: найдено {len(snapshot.neighbors)} LLDP соседей")
                    self._dirty = True
                elif kind == "topology_error":
                    self.snmp_busy = False
                    self.topology_failed.add(item[1])
                    self.snmp_due[item[1]] = time.monotonic() + self.snmp_interval
                    self._set_status(f"SNMP {item[1]}: ошибка чтения, снимок помечен устаревшим")
                    self._event("warning", "SNMP/LLDP", f"{item[1]}: опрос не удался (проверьте SNMP/ACL)")
                    self._dirty = True
                elif kind == "tool":
                    self._console_text(item[1])
                    self.tool_button.configure(state="normal")
                elif kind == "monitor_stopped":
                    pass
        except queue.Empty:
            pass
        if self._dirty and time.monotonic() - self._last_paint > 0.45:
            self._refresh_ui()
            self._dirty = False
            self._last_paint = time.monotonic()
        self.after(140, self._drain)

    def _fresh_topology(self):
        """Never display stale observations as verified current LLDP links."""
        now = time.monotonic()
        maximum_age = max(120, self.snmp_interval * 2 + 30)
        return {ip: snap for ip, snap in self.topology_snapshots.items()
                if ip not in self.topology_failed
                and now - self.topology_received.get(ip, float('-inf')) <= maximum_age}

    def _snmp_tick(self):
        if self._closed:
            return
        if self.snmp_auto_enabled and not self.snmp_busy:
            due = [(t, ip) for ip, t in self.snmp_due.items()
                   if ip in self.snmp_profiles and t <= time.monotonic()]
            if due:
                _t, ip = min(due)
                self.snmp_busy = True
                self.snmp_due[ip] = time.monotonic() + self.snmp_interval
                threading.Thread(target=self._snmp_worker,
                                 args=(ip, self.snmp_profiles[ip]), daemon=True).start()
        if self.current_page == 'Карта сети' and self.topology_snapshots:
            self._dirty = True  # TTL and stale labels continue updating without new packets.
        self.after(1000, self._snmp_tick)

    def _stop_snmp_auto(self):
        self.snmp_auto_enabled = False
        self.snmp_profiles.clear()  # forget all secrets immediately
        self.snmp_due.clear()
        self._set_status('SNMP автоопрос отключён. Учётные данные удалены из памяти профилей.')

    def _scan_finished(self):
        self.scanning = False
        self.scan_button.configure(state="normal")
        self.progress["value"] = 100 if not self.scan_stop.is_set() else 0
        self._set_state("МОНИТОРИНГ" if self.monitoring else "ГОТОВО", GREEN)

    def _scan_complete(self, cidr, result, was_cancelled):
        devices, neighbors, total = result
        for device in devices:
            # The final snapshot contains the newest MAC information.
            with self.state_lock:
                self.devices[device.ip] = device
            self.store.save_device(device)
        if not was_cancelled:
            self._observe_neighbors(neighbors)
        self._scan_finished()
        self._dirty = True
        action = "Остановлено" if was_cancelled else "Завершено"
        self._set_status(f"{action}: {cidr} · проверено {total} адресов · найдено {len(devices)} записей (включая ARP)")
        self._event("info", "Сканирование", f"{cidr}; проверено {total}; записей {len(devices)}; остановлено {was_cancelled}")
        if self.monitor_enabled.get() and not self.monitoring:
            self._start_monitor()

    def _observe_neighbors(self, neighbors):
        now = time.monotonic()
        for ip, deadline in list(self.ip_alert_expiry.items()):
            if now >= deadline:
                self.ip_alert_expiry.pop(ip, None)
                self.ip_alerts.pop(ip, None)
        for change in self.mac_history.ingest(neighbors):
            if change.severity == "warning":
                self.ip_alerts[change.ip] = change
                self.ip_alert_expiry[change.ip] = now + 900
            self._event(change.severity,
                        "Подозрение на IP-конфликт" if change.severity == "warning" else "ARP: смена MAC",
                        f"{change.ip}: {change.previous} → {change.current}, переходов за 3 мин: {change.switches}. DHCP, VRRP и кеш ARP могут давать такие изменения; подтверждение требует анализа DHCP/пакетов.")
        with self.state_lock:
            for ip, mac in neighbors.items():
                if ip in self.devices and mac:
                    device = self.devices[ip]
                    device.mac = mac
                    device.vendor = net.mac_vendor(mac)
        self._dirty = True

    def _update_monitor(self, samples, neighbors):
        with self.state_lock:
            for ip, ping in samples.items():
                dev = self.devices.get(ip)
                if not dev:
                    continue
                previous = dev.online
                if ping.alive:
                    dev.failures = 0
                    dev.online = True
                    dev.latency_ms = ping.rtt_ms
                    dev.seen = net.now_iso()
                else:
                    dev.failures += 1
                    if dev.failures >= 2:
                        dev.online = False
                        dev.latency_ms = None
                if dev.online != previous:
                    self._event("info" if dev.online else "error",
                                "Устройство снова доступно" if dev.online else "Устройство не отвечает",
                                f"{ip}  {dev.hostname}")
                    self.store.save_device(dev)
        self._observe_neighbors(neighbors)
        if self.gateway:
            ping = samples.get(self.gateway)
            self.latency_history.append(ping.rtt_ms if ping and ping.alive else None)
        self._dirty = True

    def _update_wifi(self, report):
        previous = self.wifi_report.status
        state = report.status
        if self.wifi_previously_observed:
            if previous.connected and not state.connected:
                self._event("warning", "Wi-Fi отключился", f"Пропало подключение к {previous.ssid}")
            elif state.connected and not previous.connected:
                self._event("info", "Wi-Fi подключён", f"SSID: {state.ssid} | BSSID: {state.bssid}")
            elif state.connected and previous.connected and state.bssid and previous.bssid and state.bssid != previous.bssid:
                self._event("info", "Wi-Fi переключился на другую точку", f"{state.ssid}: {previous.bssid} → {state.bssid}")
        self.wifi_previously_observed = True
        self.wifi_report = report
        self.signal_history.append(float(state.signal) if state.connected else None)
        now = time.monotonic()
        if now - self.wifi_last_saved >= 30:
            self.store.save_wifi_sample(state.connected, state.ssid, state.bssid, state.signal, state.channel)
            self.wifi_last_saved = now
        warning = " | ".join(report.warnings)
        if warning and warning != self.wifi_warning_previous:
            self._event("warning", "Диагностика Wi-Fi", warning)
        self.wifi_warning_previous = warning
        self._dirty = True

    def _event(self, severity, title, detail):
        self.store.event(severity, title, detail)
        if severity not in ("warning", "error") or not self.alerts_enabled.get() or self._closed:
            return
        now = time.monotonic()
        key = (severity, title, detail)
        if now - self.alert_last.get(key, float('-inf')) < 120:
            return
        self.alert_last[key] = now
        if len(self.alert_last) > 300:
            self.alert_last = {k: t for k, t in self.alert_last.items() if now - t < 300}
        self.alert_token += 1
        token = self.alert_token
        self.alert_banner.configure(text=f"{'СБОЙ' if severity == 'error' else 'ВНИМАНИЕ'} · {title}: {detail[:110]}",
                                    fg=RED if severity == 'error' else YELLOW)
        self.after(12000, lambda: self.alert_banner.configure(text="") if token == self.alert_token and not self._closed else None)

    def _refresh_ui(self):
        if not hasattr(self, "metrics"):
            return
        with self.state_lock:
            all_devices = list(self.devices.values())
        online = sum(d.online for d in all_devices)
        self.metrics["online"].configure(text=str(online))
        self.metrics["offline"].configure(text=str(len(all_devices) - online))
        self.metrics["ip"].configure(text=str(len(self.ip_alerts)))
        state = self.wifi_report.status
        self.metrics["wifi"].configure(text=f"{state.signal}%" if state.connected else "—")
        self.adapter_label.configure(text=(f"Активные IPv4 интерфейсы: {', '.join(a.name + ' (' + a.address + ')' for a in self.adapters[:3])}"
                                           if self.adapters else "Активных IPv4 интерфейсов нет"))
        self.gw_label.configure(text=f"Шлюз: {self.gateway or 'не найден'}    ·    выбранная подсеть: {self.network_value.get()}")
        if self.current_page == "Устройства":
            self._paint_devices(all_devices)
        elif self.current_page == "Карта сети":
            self._draw_map(all_devices)
            self._paint_neighbors(all_devices)
            self._paint_fdb(all_devices)
        elif self.current_page == "Wi-Fi":
            self._paint_wifi()
        elif self.current_page == "События":
            self._paint_events()
        elif self.current_page == "Обзор":
            self._draw_charts()

    def _paint_devices(self, devices):
        previous = self.device_table.selection()
        old_ip = self.device_table.item(previous[0], "values")[0] if previous else None
        self.device_table.delete(*self.device_table.get_children())
        for d in sorted(devices, key=lambda item: ipaddress.ip_address(item.ip)):
            self.device_table.insert("", "end", iid=d.ip,
                values=(d.ip, d.hostname or "—", d.kind, d.mac or "—", d.vendor or "—",
                        "Доступен" if d.online else "Нет ответа",
                        f"{d.latency_ms:.1f}" if d.latency_ms is not None else "—"),
                tags=("up" if d.online else "down",))
        if old_ip and self.device_table.exists(old_ip):
            self.device_table.selection_set(old_ip)
        self.devices_count.configure(text=f"Обнаружено: {len(devices)} · доступно: {sum(d.online for d in devices)}")

    def _device_selected(self, _event=None):
        selection = self.device_table.selection()
        if not selection:
            return
        ip = selection[0]
        d = self.devices.get(ip)
        if d:
            self.selected_ip = ip
            self.device_detail.configure(text=f"{ip}  ·  {d.hostname or 'имя неизвестно'}  ·  порты: {', '.join(map(str, d.ports)) or 'нет подтверждённых'}  ·  последний ответ: {d.seen or '—'}")

    def _device_double_click(self, _event=None):
        if self.selected_ip:
            self.tool_target.set(self.selected_ip)
            self.show_page("Диагностика")

    def _paint_wifi(self):
        report = self.wifi_report
        state = report.status
        self.wifi_current_label.configure(text=f"{state.ssid or 'Wi-Fi не подключён'}  ·  {state.signal if state.connected else 0}%")
        self.wifi_status_label.configure(text=f"Адаптер: {state.adapter or '—'}  |  BSSID: {state.bssid or '—'}  |  Канал: {state.channel or '—'}  |  Радио: {state.radio or '—'}")
        self.wifi_warning_label.configure(text="\n".join(report.warnings[:3]) or "Предупреждений не найдено")
        self._draw_curve(self.wifi_signal_canvas, list(self.signal_history), BLUE, 100)
        self.wifi_table.delete(*self.wifi_table.get_children())
        for ap in sorted(report.aps, key=lambda item: item.signal, reverse=True):
            self.wifi_table.insert("", "end", values=(ap.ssid, ap.bssid,
                   f"{ap.signal}%", ap.channel or "—", ap.band or "—", ap.auth or "—", ap.radio or "—"))

    def _paint_events(self):
        self.events_table.delete(*self.events_table.get_children())
        for ts, severity, title, detail in self.store.events(250):
            self.events_table.insert("", "end", values=(ts, severity.upper(), title, detail), tags=(severity,))

    def _draw_curve(self, canvas, data, color, max_fixed=None):
        canvas.delete("all")
        w, h = max(canvas.winfo_width(), 80), max(canvas.winfo_height(), 80)
        pad = 15
        for i in range(4):
            y = pad + (h - pad * 2) * i / 3
            canvas.create_line(pad, y, w - pad, y, fill=BORDER, dash=(3, 6))
        if len(data) < 2:
            canvas.create_text(w / 2, h / 2, text="Данные появятся после начала мониторинга", fill=MUTED, font=("Segoe UI", 10))
            return
        maximum = max_fixed or max((x for x in data if x is not None), default=10) * 1.15 or 10
        maximum = max(1, maximum)
        points = []
        for i, value in enumerate(data):
            if value is None:
                if len(points) >= 4:
                    canvas.create_line(*points, fill=color, width=2, smooth=True)
                points = []
                continue
            x = pad + (w - pad * 2) * i / max(1, len(data) - 1)
            y = h - pad - (h - pad * 2) * (min(maximum, value) / maximum)
            points.extend((x, y))
        if len(points) >= 4:
            canvas.create_line(*points, fill=color, width=2, smooth=True)
        latest = next((v for v in reversed(data) if v is not None), None)
        if latest is not None:
            canvas.create_text(w - 13, 13, anchor="ne", text=f"{latest:.1f}", fill=color,
                               font=("Segoe UI Semibold", 13))

    def _draw_charts(self):
        self._draw_curve(self.latency_canvas, list(self.latency_history), GREEN)
        self._draw_curve(self.signal_canvas, list(self.signal_history), BLUE, 100)

    def _draw_map(self, devices=None):
        if not hasattr(self, "map_canvas"):
            return
        with self.state_lock:
            devices = list(self.devices.values()) if devices is None else devices
        canvas = self.map_canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 880)
        height = max(canvas.winfo_height(), 590)
        center_x, center_y = width // 2, max(280, height // 2)
        canvas.create_text(24, 22, text=f"КАРТА · {len(devices)} устройств · LLDP подтверждённые связи: {len(topology.physical_links(self._fresh_topology(), devices))}", fill=MUTED,
                           anchor="w", font=("Segoe UI Semibold", 10))
        canvas.create_oval(center_x - 68, center_y - 46, center_x + 68, center_y + 46,
                           fill="#1B4566", outline=BLUE, width=2)
        canvas.create_text(center_x, center_y - 10, text="ЛОКАЛЬНАЯ", fill=TEXT, font=("Segoe UI Semibold", 10))
        canvas.create_text(center_x, center_y + 9, text="СЕТЬ", fill=TEXT, font=("Segoe UI Semibold", 10))
        canvas.create_text(center_x, center_y + 57, text=f"Шлюз: {self.gateway or '—'}", fill=BLUE,
                           font=("Segoe UI", 10))
        positions = []
        ordered = sorted(devices, key=lambda d: ipaddress.ip_address(d.ip))[:120]
        remaining = len(devices) - len(ordered)
        cursor = 0
        ring = 0
        while cursor < len(ordered):
            capacity = 18 + ring * 12
            this_ring = ordered[cursor:cursor + capacity]
            radius = 185 + ring * 145
            for idx, dev in enumerate(this_ring):
                angle = (2 * math.pi * idx / max(1, len(this_ring))) - math.pi / 2
                x = center_x + radius * math.cos(angle)
                y = center_y + radius * math.sin(angle)
                positions.append((dev, x, y))
            cursor += len(this_ring)
            ring += 1
        max_r = 185 + max(0, ring - 1) * 145
        max_x = max(width, center_x + max_r + 150)
        max_y = max(height, center_y + max_r + 100)
        canvas.configure(scrollregion=(min(0, center_x - max_r - 150), min(0, center_y - max_r - 100),
                                       max_x, max_y))
        for dev, x, y in positions:
            canvas.create_line(center_x, center_y, x, y, fill="#2D4761", width=1, dash=(4, 4))
        physical = topology.physical_links(self._fresh_topology(), devices)
        point_by_ip = {dev.ip: (x, y) for dev, x, y in positions}
        for source, target, neighbor in physical:
            if source not in point_by_ip or target not in point_by_ip:
                continue
            x1, y1 = point_by_ip[source]
            x2, y2 = point_by_ip[target]
            canvas.create_line(x1, y1, x2, y2, fill=BLUE, width=3)
            canvas.create_text((x1 + x2) / 2, (y1 + y2) / 2 - 9,
                               text=f"{neighbor.local_port} ↔ {neighbor.remote_port}"[:34],
                               fill=BLUE, font=("Segoe UI", 9))
        for dev, x, y in positions:
            key = f"host:{dev.ip}"
            color = YELLOW if dev.ip in self.ip_alerts else (GREEN if dev.online else RED)
            canvas.create_oval(x - 12, y - 12, x + 12, y + 12,
                               fill=color, outline=BG, width=2, tags=(key, "node"))
            canvas.create_text(x, y + 23, text=dev.ip, fill=TEXT,
                               font=("Consolas", 10), tags=(key, "node"))
            canvas.create_text(x, y + 38, text=(dev.hostname or dev.kind)[:24], fill=MUTED,
                               font=("Segoe UI", 9), tags=(key, "node"))
            canvas.tag_bind(key, "<Button-1>", lambda e, ip=dev.ip: self._map_pick(ip))
        if remaining > 0:
            canvas.create_text(24, 46, text=f"Для читаемости показаны первые 120 узлов; ещё {remaining} — во вкладке «Устройства»",
                               fill=YELLOW, anchor="w", font=("Segoe UI", 9))
        if not devices:
            canvas.create_text(center_x, center_y + 85, text="Начните сканирование подсети для построения карты",
                               fill=MUTED, font=("Segoe UI", 12))

    def _paint_neighbors(self, devices):
        self.neighbor_table.delete(*self.neighbor_table.get_children())
        total = 0
        matched = 0
        fresh = self._fresh_topology()
        for source, snapshot in sorted(self.topology_snapshots.items()):
            if source not in fresh:
                continue  # stale snapshot must not masquerade as a live LLDP link
            for neighbor in snapshot.neighbors:
                total += 1
                target = topology.resolve_neighbor_ip(neighbor, devices)
                matched += bool(target)
                self.neighbor_table.insert("", "end", values=(
                    source, neighbor.local_port, neighbor.remote_name or neighbor.remote_chassis or "неизвестно",
                    neighbor.remote_port or "—", target or "не определён"))
        stale = len(self.topology_snapshots) - len(fresh)
        self.topology_note.configure(text=f"LLDP: {total} актуальных, {matched} сопоставлено, {stale} устаревших устройств. "
                                          "Синий — LLDP; пунктир — логическая схема, не кабель.")

    def _paint_fdb(self, devices):
        self.fdb_table.delete(*self.fdb_table.get_children())
        count = 0
        fresh = self._fresh_topology()
        for ip, snapshot in sorted(fresh.items()):
            for row in snapshot.fdb_entries:
                count += 1
                if count > 250:
                    continue
                self.fdb_table.insert('', 'end', values=(
                    ip, row.mac, row.interface,
                    str(row.vlan) if row.vlan is not None else 'не определён',
                    fdb.resolve_fdb_ip(row, devices) or '—'))
        self.fdb_note.configure(text=f"FDB: {count} записей (первые 250). MAC ↔ порт — таблица обучения, "
                                     "не физический кабель. VLAN указан только при однозначном соответствии FDB ID.")

    def _snmp_dialog(self):
        if self.snmp_busy:
            messagebox.showinfo("SNMP", "Опрос уже выполняется", parent=self)
            return
        popup = tk.Toplevel(self)
        popup.title("SNMP/LLDP · только чтение")
        popup.geometry("485x510")
        popup.resizable(False, False)
        popup.configure(bg=PANEL)
        popup.transient(self)
        popup.grab_set()
        host = tk.StringVar(value=self.selected_ip or self.gateway or "")
        version = tk.StringVar(value="v3")
        username = tk.StringVar()
        community = tk.StringVar()
        auth_key = tk.StringVar()
        priv_key = tk.StringVar()
        port = tk.StringVar(value="161")
        auto = tk.BooleanVar(value=False)
        interval = tk.StringVar(value="60")
        lines = [("IPv4 коммутатора/маршрутизатора", host, False),
                 ("Версия: v3 по умолчанию (SHA-256 + AES128)", version, False),
                 ("Пользователь SNMPv3", username, False),
                 ("Пароль аутентификации SNMPv3", auth_key, True),
                 ("Пароль шифрования SNMPv3", priv_key, True),
                 ("Community SNMPv2c (только чтение)", community, True),
                 ("UDP порт", port, False)]
        for caption, variable, secret in lines:
            row = tk.Frame(popup, bg=PANEL)
            row.pack(fill="x", padx=15, pady=3)
            self._label(row, caption, 9, color=TEXT).pack(side="left", anchor="w")
            if variable is version:
                ttk.Combobox(row, textvariable=version, values=("v3", "v2c"),
                             state="readonly", width=7).pack(side="right")
            else:
                tk.Entry(row, textvariable=variable, width=19, show="*" if secret else "",
                         bg=PANEL_ALT, fg=TEXT, insertbackground=TEXT, relief="flat").pack(side="right", ipady=3)

        auto_row = tk.Frame(popup, bg=PANEL)
        auto_row.pack(fill='x', padx=15, pady=(9, 0))
        tk.Checkbutton(auto_row, text='Автоопрос (пароли только в памяти)', variable=auto,
                       bg=PANEL, fg=TEXT, selectcolor=BG, activebackground=PANEL,
                       activeforeground=TEXT).pack(side='left')
        ttk.Combobox(auto_row, textvariable=interval, state='readonly',
                     values=('30', '60', '120', '300'), width=5).pack(side='right')
        self._label(popup, 'Интервал автоопроса, секунд (30–300)', 9, color=MUTED).pack(anchor='e', padx=16)
        self._label(popup, "Данные не сохраняются. SNMP запросы только GET/WALK; "
                    "используйте доступ к своему оборудованию.", 9, color=MUTED,
                    wraplength=435, justify="left").pack(anchor="w", padx=16, pady=10)

        def submit():
            try:
                credentials = topology.SNMPCredentials(version=version.get(), username=username.get(),
                    auth_key=auth_key.get(), priv_key=priv_key.get(), community=community.get(),
                    port=int(port.get()))
                credentials.validate()
                ip = str(ipaddress.IPv4Address(host.get().strip()))
                if not ipaddress.IPv4Address(ip).is_private:
                    raise ValueError("Укажите локальный частный IPv4-адрес")
            except (ValueError, ipaddress.AddressValueError) as exc:
                messagebox.showwarning("Параметры SNMP", str(exc), parent=popup)
                return
            popup.destroy()
            if auto.get():
                self.snmp_interval = int(interval.get())
                self.snmp_profiles[ip] = credentials
                self.snmp_due[ip] = time.monotonic() + self.snmp_interval
                self.snmp_auto_enabled = True
            else:
                self.snmp_profiles.pop(ip, None)
                self.snmp_due.pop(ip, None)
            self.snmp_busy = True
            self._set_status(f"Опрос LLDP {ip}: выполняется...")
            threading.Thread(target=self._snmp_worker, args=(ip, credentials), daemon=True).start()

        self._button(popup, "Получить LLDP-соседей", submit, primary=True).pack(pady=5)

    def _snmp_worker(self, ip, credentials):
        try:
            snapshot = topology.read_lldp(ip, credentials)
            self.messages.put(("topology", snapshot))
        except Exception as exc:
            # Exceptions can contain transport hostnames; never log any credentials.
            self.messages.put(("topology_error", ip))

    def _map_pick(self, ip):
        self.selected_ip = ip
        self.show_page("Устройства")
        if self.device_table.exists(ip):
            self.device_table.selection_set(ip)
            self.device_table.see(ip)
            self._device_selected()

    def _traffic_tick(self):
        if self._closed:
            return
        self.traffic_samples.append((time.monotonic(), net.network_counters()))
        if len(self.traffic_samples) == 2:
            (t0, prev), (t1, current) = self.traffic_samples
            dt = max(0.01, t1 - t0)
            interface = next((a.name for a in self.adapters if a.address == self.local_route_ip), None)
            interface = interface or (self.adapters[0].name if self.adapters else "")
            if interface in prev and interface in current:
                receive = max(0, current[interface][0] - prev[interface][0]) / dt / 1024
                transmit = max(0, current[interface][1] - prev[interface][1]) / dt / 1024
                self.traffic_last_rate = (receive, transmit)
                self.traffic_label.configure(text=f"Трафик {interface}:  ↓ {receive:.1f} КБ/с     ↑ {transmit:.1f} КБ/с")
        self.after(2000, self._traffic_tick)

    def run_tool(self):
        kind = self.tool_kind.get()
        target = self.tool_target.get().strip()
        if kind not in ("ARP-таблица", "Маршруты IPv4"):
            try:
                target = net.valid_target(target)
            except ValueError as exc:
                messagebox.showwarning("Цель диагностики", str(exc), parent=self)
                return
        try:
            port = int(self.tool_port.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Порт", "Укажите TCP-порт от 1 до 65535", parent=self)
            return
        self.tool_button.configure(state="disabled")
        self._console_text(f"$ {kind}  {target}\n\nВыполняется…")
        threading.Thread(target=self._tool_worker, args=(kind, target, port), daemon=True).start()

    def _tool_worker(self, kind, target, port):
        try:
            if kind == "Ping × 4":
                args = (["ping", "-n", "4", "-w", "850", target] if net.os.name == "nt"
                        else ["ping", "-n", "-c", "4", "-W", "1", target])
                code, result = net.command(args, timeout=12)
            elif kind == "Traceroute":
                code, result = net.trace_target(target)
            elif kind == "DNS":
                result = f"Имя: {target}\n\n"
                addresses = sorted({item[4][0] for item in socket.getaddrinfo(target, None)})
                result += "IP-адреса:\n" + "\n".join(addresses)
                try:
                    result += "\n\nReverse DNS: " + socket.gethostbyaddr(addresses[0])[0]
                except (OSError, IndexError):
                    result += "\n\nReverse DNS: нет записи"
                code = 0
            elif kind == "TCP-порт":
                try:
                    with socket.create_connection((target, port), timeout=3):
                        result = f"TCP {target}:{port} — соединение успешно, порт доступен"
                        code = 0
                except OSError as exc:
                    result = f"TCP {target}:{port} — нет соединения ({exc})"
                    code = 1
            elif kind == "ARP-таблица":
                code, result = net.command(["arp", "-a"], timeout=8)
            else:
                code, result = net.command(["route", "print", "-4"] if net.os.name == "nt"
                                           else ["ip", "-4", "route"], timeout=8)
            output = f"$ {kind}  {target}\nКод завершения: {code}\n\n{result}"
        except Exception as exc:
            output = f"Ошибка выполнения: {exc}"
        self.messages.put(("tool", output))

    def _console_text(self, content):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.insert("1.0", content)
        self.console.configure(state="disabled")

    def export_csv(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                                initialfile="bloodsky_devices.csv", parent=self)
        if filename:
            self.store.export_csv(filename, list(self.devices.values()))
            self._set_status(f"Сохранён список: {filename}")

    def export_json(self):
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")],
                                                initialfile="bloodsky_report.json", parent=self)
        if filename:
            self.store.export_json(filename, list(self.devices.values()), self.network_value.get(),
                                   self.gateway, {"connected": asdict(self.wifi_report.status),
                                                  "access_points": [asdict(a) for a in self.wifi_report.aps]})
            self._set_status(f"Сохранён отчёт: {filename}")

    def export_map(self):
        # Vector SVG requires no additional packages and captures the entire map.
        from html import escape
        filename = filedialog.asksaveasfilename(defaultextension=".svg", filetypes=[("Векторная карта SVG", "*.svg")],
                                                initialfile="bloodsky_network_map.svg", parent=self)
        if not filename:
            return
        devices = sorted(self.devices.values(), key=lambda d: ipaddress.ip_address(d.ip))
        positions = []
        offset = 0
        ring = 0
        while offset < len(devices):
            group = devices[offset: offset + 18 + ring * 12]
            radius = 185 + ring * 145
            for i, d in enumerate(group):
                angle = 2 * math.pi * i / len(group) - math.pi / 2
                positions.append((d, radius * math.cos(angle), radius * math.sin(angle)))
            offset += len(group)
            ring += 1
        reach = max(350, 185 + max(0, ring - 1) * 145 + 150)
        width = height = int(2 * reach + 40)
        center = width / 2
        parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
                 f'<rect width="100%" height="100%" fill="{PANEL}"/>',
                 f'<text x="28" y="34" font-family="Segoe UI,sans-serif" font-size="20" fill="{TEXT}">BLOODSKY NET — карта сети (LLDP — сплошные линии)</text>']
        for d, dx, dy in positions:
            x, y = center + dx, center + dy
            parts.append(f'<line x1="{center}" y1="{center}" x2="{x:.1f}" y2="{y:.1f}" stroke="{BORDER}" stroke-dasharray="5 6"/>')
        parts += [f'<circle cx="{center}" cy="{center}" r="59" fill="#1B4566" stroke="{BLUE}" stroke-width="2"/>',
                  f'<text x="{center}" y="{center + 5}" text-anchor="middle" fill="{TEXT}" font-size="17" font-family="Segoe UI,sans-serif">LAN</text>']
        by_ip = {d.ip: (center + dx, center + dy) for d, dx, dy in positions}
        for source, target, neighbor in topology.physical_links(self._fresh_topology(), devices):
            if source in by_ip and target in by_ip:
                x1, y1 = by_ip[source]
                x2, y2 = by_ip[target]
                parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{BLUE}" stroke-width="3"/>')
                port_label = escape((neighbor.local_port + ' ↔ ' + neighbor.remote_port)[:34])
                parts.append(f'<text x="{(x1+x2)/2:.1f}" y="{(y1+y2)/2-9:.1f}" text-anchor="middle" fill="{BLUE}" font-size="11">{port_label}</text>')
        for d, dx, dy in positions:
            x, y = center + dx, center + dy
            color = YELLOW if d.ip in self.ip_alerts else (GREEN if d.online else RED)
            label = escape((d.hostname or d.kind)[:28])
            parts.extend([f'<circle cx="{x:.1f}" cy="{y:.1f}" r="12" fill="{color}"/>',
                          f'<text x="{x:.1f}" y="{y+30:.1f}" text-anchor="middle" fill="{TEXT}" font-family="Consolas,monospace" font-size="13">{escape(d.ip)}</text>',
                          f'<text x="{x:.1f}" y="{y+47:.1f}" text-anchor="middle" fill="{MUTED}" font-family="Segoe UI,sans-serif" font-size="11">{label}</text>'])
        parts.append('</svg>')
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(parts))
            self._set_status(f"Карта SVG сохранена: {filename}")
        except OSError as exc:
            messagebox.showerror("Экспорт карты", str(exc), parent=self)

    def shutdown(self):
        if self._closed:
            return
        self._closed = True
        self.scan_stop.set()
        self.monitor_stop.set()
        self.snmp_auto_enabled = False
        self.snmp_profiles.clear()
        self.snmp_due.clear()
        try:
            self.store.close()
        except Exception:
            pass
        self.destroy()

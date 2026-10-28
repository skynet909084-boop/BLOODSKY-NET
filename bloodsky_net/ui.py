"""Russian-language desktop UI for BLOODSKY NET (Tk 8.6, Windows 10/11)."""
from __future__ import annotations

from collections import deque
import json
import sqlite3
from dataclasses import asdict
import ipaddress
import sys
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
from . import map_view
from . import time_machine
from . import detective
from . import port_health
from . import fdb
from . import traffic
from . import notifications
from . import dhcp
from . import windows_integration
from .tray import TrayController
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
        self.protocol("WM_DELETE_WINDOW", self.close_window)
        self.store = Storage()
        self.devices: dict[str, net.Device] = self.store.load_devices()
        self.topology_snapshots: dict[str, topology.TopologySnapshot] = {}
        self.snmp_busy = False
        self.snmp_profiles: dict[str, topology.SNMPCredentials] = {}  # RAM only
        self.snmp_due: dict[str, float] = {}
        self.topology_received: dict[str, float] = {}
        self.topology_failed: set[str] = set()
        self.port_rates: dict[str, dict[int, traffic.PortRate]] = {}
        self.port_error_deltas: dict[str, tuple[port_health.ErrorDelta, ...]] = {}
        self.selected_port: tuple[str, int] | None = None
        self.snmp_auto_enabled = False
        self.snmp_interval = 60
        self.state_lock = threading.Lock()
        self.messages: queue.Queue = queue.Queue()
        self.scan_stop = threading.Event()
        self.monitor_stop = threading.Event()
        self._wifi_busy = threading.Event()
        self._wifi_lock = threading.Lock()
        self.scanning = False
        self.monitoring = False
        self.monitor_thread: threading.Thread | None = None
        self.monitor_restart_at = 0.0
        self.monitor_failures = 0
        self.tray: TrayController | None = None
        self.gateway, route_ip = net.default_gateway()
        self.local_route_ip = route_ip
        self.adapters = net.get_adapters()
        self.network_value = tk.StringVar(value=net.suggested_network(self.adapters, route_ip))
        self.monitor_enabled = tk.BooleanVar(value=self.store.get_preference("monitor_enabled", True))
        self.interval_value = tk.StringVar(value="5")
        self.current_page = "Обзор"
        self.monitor_interval = 5
        self.pages: dict[str, tk.Frame] = {}
        self.nav_buttons: dict[str, tk.Button] = {}
        self.wifi_report = wifi.WifiReport(wifi.WifiStatus(), [], [])
        self.wifi_warning_previous = ""
        self.wifi_previously_observed = False
        self._wifi_observed_at = float('-inf')
        self.traffic_last_rate = (0.0, 0.0)
        self.mac_history = net.MacHistory()
        self.ip_alerts: dict[str, net.MacChange] = {}
        self.ip_alert_expiry: dict[str, float] = {}
        self.alerts_enabled = tk.BooleanVar(value=self.store.get_preference("alerts_enabled", True))
        self.windows_alerts_enabled = tk.BooleanVar(value=self.store.get_preference("windows_alerts_enabled", False))
        self.minimize_to_tray = tk.BooleanVar(value=self.store.get_preference("minimize_to_tray", False))
        self.autostart_enabled = tk.BooleanVar(value=windows_integration.is_autostart_enabled())
        self.alert_last: dict[tuple[str, str, str], float] = {}
        self.alert_token = 0
        self.wifi_last_saved = float('-inf')
        self.latency_history: deque[float | None] = deque(maxlen=100)
        self.signal_history: deque[float | None] = deque(self.store.wifi_signal_history(100), maxlen=100)
        self.traffic_samples: deque[tuple[float, dict]] = deque(maxlen=2)
        self.selected_ip = ""
        self.map_query = tk.StringVar(value="")
        self.map_status = tk.StringVar(value="Все")
        self.map_zoom = tk.StringVar(value="100%")
        self.map_group = tk.StringVar(value="Без групп")
        self.map_manual_positions = self.store.map_positions()
        self._timeline_status: dict[str, str] = {}  # current-session measurements only
        self._timeline_seen_at: dict[str, float] = {}
        self._timeline_last_capture = time.monotonic()
        self._gateway_failures = 0
        self._detective_findings = ()
        self._timeline_index: dict[str, int] = {}
        self.timeline_before = tk.StringVar(value='')
        self.timeline_after = tk.StringVar(value='')
        self.lldp_before = tk.StringVar(value='')
        self.lldp_after = tk.StringVar(value='')
        self._lldp_timeline_index = {}
        self.map_selected_ip = ""
        self._map_drag_state = None
        self._map_point_by_ip = {}
        self._map_center = (0, 0)
        self._dirty = False
        self._last_paint = 0.0
        self._closed = False
        self._style()
        self._layout()
        self._refresh_ui()
        self.after(150, self._drain)
        self.after(1100, self._traffic_tick)
        self.after(1000, self._snmp_tick)
        self.after(2500, self._monitor_guard)
        self._read_wifi_background()
        self._setup_tray()
        if self.monitor_enabled.get() and (self.devices or self.gateway):
            self._start_monitor()
        if "--minimized" in sys.argv and self.tray and self.tray.active:
            self.withdraw()

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
                      ("◉", "Wi-Fi"), ("⇅", "Порты"), ("◷", "Машина времени"), ("⌕", "Детектив"), ("⌁", "Диагностика"), ("▣", "События")]
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
        self._page_ports()
        self._page_time_machine()
        self._page_detective()
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
                                         "Порты": "Трафик портов коммутаторов",
                                         "Машина времени": "NETWORK TIME MACHINE", "Детектив": "BLOODSKY DETECTIVE",
                                         "Диагностика": "Инструменты диагностики", "События": "Журнал событий"}[page])
        for name, btn in self.nav_buttons.items():
            btn.configure(bg=PANEL_ALT if name == page else SIDEBAR,
                          fg=BLUE if name == page else TEXT)
        self._refresh_ui()
        if page == 'Машина времени':
            self._timeline_refresh()
            self._lldp_timeline_refresh()

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
        self._label(top, "Поиск", 10, color=MUTED).pack(side="left")
        search = tk.Entry(top, textvariable=self.map_query, bg=PANEL_ALT, fg=TEXT,
                          insertbackground=TEXT, relief="flat", width=21, font=("Segoe UI", 10))
        search.pack(side="left", padx=(8, 12), ipady=8)
        search.bind("<KeyRelease>", lambda _event: self._draw_map())
        status = ttk.Combobox(top, state="readonly", values=map_view.STATUS_OPTIONS,
                              textvariable=self.map_status, width=14, style="Night.TCombobox")
        status.pack(side="left", padx=(0, 10))
        status.bind("<<ComboboxSelected>>", lambda _event: self._draw_map())
        zoom = ttk.Combobox(top, state="readonly", values=("75%", "100%", "125%", "150%"),
                            textvariable=self.map_zoom, width=5, style="Night.TCombobox")
        zoom.pack(side="left")
        zoom.bind("<<ComboboxSelected>>", lambda _event: self._draw_map())
        group = ttk.Combobox(top, state="readonly", values=map_view.GROUP_OPTIONS,
                             textvariable=self.map_group, width=14, style="Night.TCombobox")
        group.pack(side="left", padx=(8, 0))
        group.bind("<<ComboboxSelected>>", lambda _event: self._draw_map())
        self._button(top, "Сбросить позиции", self._reset_map_positions).pack(side="right", padx=(7, 0))
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
        self.map_legend = self._label(parent,
            "● Зелёный — доступен   ● Красный — не отвечает   ● Жёлтый — IP-подозрение   "
            "──── Синий — LLDP-наблюдение   - - - Пунктир — схема, не кабель",
            9, color=MUTED)
        self.map_legend.pack(anchor="w", pady=(5, 0))
        self.map_device_detail = self._label(parent,
            "Нажмите на устройство: откроется паспорт. Перетащите узел для сохранения позиции. "
            "VLAN/порт из FDB — наблюдение, не прямой кабель.", 9, color=TEXT,
            justify="left", wraplength=1080)
        self.map_device_detail.pack(anchor="w", pady=(6, 4))
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

    def _page_time_machine(self):
        parent = self._new_page('Машина времени')
        note = self._panel(parent)
        note.pack(fill='x', pady=(0, 12))
        self._label(note, 'История наблюдений сети', 15, True, BLUE).pack(anchor='w', padx=15, pady=(12, 4))
        self._label(note, 'Снимки хранятся локально 7 дней (до 2016 записей). '
                    '«Неизвестно» не означает «отключено». Отсутствие в снимке — не доказательство потери связи.',
                    9, color=MUTED, wraplength=950, justify='left').pack(anchor='w', padx=15, pady=(0, 13))
        toolbar = tk.Frame(parent, bg=BG)
        toolbar.pack(fill='x', pady=(0, 11))
        self._label(toolbar, 'Раньше', 9, color=MUTED).pack(side='left')
        self.timeline_before_combo = ttk.Combobox(toolbar, state='readonly',
            textvariable=self.timeline_before, width=26, style='Night.TCombobox')
        self.timeline_before_combo.pack(side='left', padx=(7, 11))
        self._label(toolbar, 'Позже', 9, color=MUTED).pack(side='left')
        self.timeline_after_combo = ttk.Combobox(toolbar, state='readonly',
            textvariable=self.timeline_after, width=26, style='Night.TCombobox')
        self.timeline_after_combo.pack(side='left', padx=(7, 11))
        self._button(toolbar, 'Сравнить', self._timeline_compare, primary=True).pack(side='left')
        self._button(toolbar, 'Снимок сейчас', lambda: self._timeline_capture('manual')).pack(side='right')
        self._button(toolbar, 'Экспорт JSON', self._timeline_export).pack(side='right', padx=(0, 9))
        self.timeline_note = self._label(parent, 'Снимков ещё нет. Выполните сканирование или сохраните снимок вручную.',
                                        10, color=MUTED)
        self.timeline_note.pack(anchor='w', pady=(0, 9))
        frame, self.timeline_table = self._tree(parent,
            ('IP', 'Категория', 'Раньше', 'Позже', 'Пояснение'), (127, 158, 153, 153, 420))
        frame.pack(fill='both', expand=True)
        self.timeline_table.configure(height=6)
        self.timeline_table.tag_configure('alarm', foreground=RED)
        self.timeline_table.tag_configure('info', foreground=TEXT)
        # Separate LLDP capture sequence; inventory and SNMP polls have different clocks.
        self._label(parent, 'ИСТОРИЯ LLDP-СОЕДИНЕНИЙ И ПОРТОВ', 10, True, BLUE).pack(anchor='w', pady=(12, 5))
        self._label(parent, 'Только успешные опросы SNMP. Отсутствие соседа в LLDP не доказывает повреждение кабеля.',
                    9, color=MUTED).pack(anchor='w', pady=(0, 5))
        lbar = tk.Frame(parent, bg=BG)
        lbar.pack(fill='x', pady=(0, 6))
        self.lldp_before_combo = ttk.Combobox(lbar, state='readonly', textvariable=self.lldp_before,
                                               width=37, style='Night.TCombobox')
        self.lldp_before_combo.pack(side='left', padx=(0, 9))
        self.lldp_after_combo = ttk.Combobox(lbar, state='readonly', textvariable=self.lldp_after,
                                              width=37, style='Night.TCombobox')
        self.lldp_after_combo.pack(side='left', padx=(0, 9))
        self._button(lbar, 'Сравнить LLDP', self._lldp_timeline_compare).pack(side='left')
        self._button(lbar, 'Обновить снимки', self._lldp_timeline_refresh).pack(side='right')
        self.lldp_timeline_note = self._label(parent, 'История LLDP пустая. Опросите коммутатор на карте сети.',
                                               9, color=MUTED)
        self.lldp_timeline_note.pack(anchor='w', pady=(0, 5))
        lframe, self.lldp_timeline_table = self._tree(parent,
            ('Коммутатор', 'Изменение LLDP', 'Сосед', 'Раньше', 'Позже', 'Пояснение'),
            (110, 130, 155, 120, 120, 340))
        self.lldp_timeline_table.configure(height=4)
        lframe.pack(fill='x')

    def _lldp_timeline_refresh(self, select_latest: bool = False):
        captures = self.store.lldp_captures(180)
        choices = [f'{row[1][:19]} · {row[2]} · {row[4]} LLDP · #{row[0]}' for row in captures]
        self._lldp_timeline_index = {label: (row[0], row[2]) for label, row in zip(choices, captures)}
        self.lldp_before_combo.configure(values=choices)
        self.lldp_after_combo.configure(values=choices)
        if select_latest or self.lldp_after.get() not in self._lldp_timeline_index:
            self.lldp_after.set(choices[0] if choices else '')
        if select_latest or self.lldp_before.get() not in self._lldp_timeline_index:
            newest_ip = captures[0][2] if captures else ''
            self.lldp_before.set(next((label for label, row in zip(choices[1:], captures[1:])
                                       if row[2] == newest_ip), ''))
        self._lldp_timeline_compare()

    def _lldp_timeline_compare(self):
        self.lldp_timeline_table.delete(*self.lldp_timeline_table.get_children())
        before = self._lldp_timeline_index.get(self.lldp_before.get())
        after = self._lldp_timeline_index.get(self.lldp_after.get())
        if not before or not after or before[0] == after[0]:
            self.lldp_timeline_note.configure(text='Выберите два LLDP-снимка одного коммутатора.')
            return
        if before[1] != after[1]:
            self.lldp_timeline_note.configure(text='Нельзя сравнить снимки разных коммутаторов.')
            return
        try:
            changes = self.store.compare_lldp_captures(before[0], after[0])
        except (sqlite3.Error, ValueError):
            self.lldp_timeline_note.configure(text='Сравнение LLDP недоступно.')
            return
        for change in changes[:350]:
            self.lldp_timeline_table.insert('', 'end', values=(change.source_ip, change.category,
                change.neighbor, change.before, change.after, change.explanation))
        self.lldp_timeline_note.configure(text=(f'LLDP-снимки #{before[0]} → #{after[0]} · '
            f'изменений: {len(changes)}. Это изменения в таблице соседей, не диагностика целостности кабеля.'))

    def _timeline_capture(self, source: str):
        with self.state_lock:
            devices = list(self.devices.values())
        now = time.monotonic()
        expiry = max(35, self.monitor_interval * 3 + 10)
        observations = {ip: state for ip, state in self._timeline_status.items()
                        if now - self._timeline_seen_at.get(ip, float('-inf')) <= expiry}
        try:
            self.store.save_network_snapshot(devices, observations,
                self.network_value.get().strip() if self.network_value.get().strip() else '', source=source)
            self._timeline_last_capture = now
            if self.current_page == 'Машина времени':
                self._timeline_refresh(select_latest=True)
        except (ValueError, OSError, sqlite3.Error) as exc:
            # Never prevent live monitor updates just because snapshots failed.
            if source == 'manual':
                messagebox.showwarning('Машина времени', f'Не удалось сохранить снимок: {exc}', parent=self)
            else:
                self._set_status('История сети: не удалось сохранить снимок, мониторинг продолжается')

    def _timeline_refresh(self, select_latest: bool = False):
        rows = self.store.network_snapshots(250)
        choices = [f'{stamp[:19]} · {source} · {count} узлов · #{ident}'
                   for ident, stamp, _scope, source, count in rows]
        self._timeline_index = dict(zip(choices, (r[0] for r in rows)))
        self.timeline_before_combo.configure(values=choices)
        self.timeline_after_combo.configure(values=choices)
        if select_latest or self.timeline_after.get() not in self._timeline_index:
            self.timeline_after.set(choices[0] if choices else '')
        if select_latest or self.timeline_before.get() not in self._timeline_index:
            self.timeline_before.set(choices[1] if len(choices) > 1 else '')
        if len(choices) > 1:
            self._timeline_compare()
        else:
            self.timeline_table.delete(*self.timeline_table.get_children())
            self.timeline_note.configure(text=f'Сохранено снимков: {len(choices)}. Для сравнения нужно два разных снимка.')

    def _timeline_changes(self):
        a = self._timeline_index.get(self.timeline_before.get())
        b = self._timeline_index.get(self.timeline_after.get())
        if a is None or b is None or a == b:
            return None
        return a, b, self.store.compare_network_snapshots(a, b)

    def _timeline_compare(self):
        result = self._timeline_changes()
        self.timeline_table.delete(*self.timeline_table.get_children())
        if result is None:
            self.timeline_note.configure(text='Выберите два разных снимка для сравнения.')
            return
        a, b, changes = result
        for change in changes[:500]:
            self.timeline_table.insert('', 'end', values=(change.ip, change.category,
                change.before, change.after, change.description),
                tags=('alarm' if change.category == 'availability' and change.after == 'down' else 'info',))
        totals = time_machine.summary(changes)
        self.timeline_note.configure(text=(
            f'Снимки #{a} → #{b} · изменений: {len(changes)} · '
            f'доступность: {totals["availability"]} · MAC: {totals["mac"]} · '
            f'новых в инвентаре: {totals["new_inventory"]} · '
            'выводы основаны только на сохранённых наблюдениях'))

    def _timeline_export(self):
        result = self._timeline_changes()
        if result is None:
            messagebox.showinfo('Машина времени', 'Выберите два снимка.', parent=self)
            return
        a, b, changes = result
        filename = filedialog.asksaveasfilename(title='Экспорт сравнения (содержит сетевые адреса)',
            defaultextension='.json', filetypes=[('JSON', '*.json')], parent=self)
        if not filename:
            return
        payload = {'app': 'BLOODSKY NET', 'before_id': a, 'after_id': b,
                   'warning': 'Нет измерения ≠ недоступно; новый IP ≠ новое физическое устройство.',
                   'changes': [asdict(change) for change in changes]}
        try:
            with open(filename, 'w', encoding='utf-8') as fp:
                json.dump(payload, fp, ensure_ascii=False, indent=2)
            self._set_status('Экспорт сравнения сохранён локально.')
        except OSError as exc:
            messagebox.showerror('Машина времени', str(exc), parent=self)

    def _page_detective(self):
        parent = self._new_page('Детектив')
        note = self._panel(parent)
        note.pack(fill='x', pady=(0, 12))
        self._label(note, 'ПОИСК ВЕРОЯТНЫХ ПРИЧИН · правила v2', 15, True, BLUE).pack(
            anchor='w', padx=15, pady=(12, 4))
        self._label(note, 'По кнопке анализирует только имеющиеся свежие ICMP/ARP/Wi-Fi/SNMP '
                    'наблюдения и последние изменения LLDP. Не отправляет данные в облако, '
                    'не выполняет скрытых сканирований и не изменяет настройки сети.',
                    9, color=MUTED, wraplength=950, justify='left').pack(anchor='w', padx=15, pady=(0, 12))
        bar = tk.Frame(parent, bg=BG)
        bar.pack(fill='x', pady=(0, 10))
        self._button(bar, 'Найти вероятную причину', self._detective_analyze, primary=True).pack(side='left')
        self._button(bar, 'Экспорт отчёта JSON', self._detective_export).pack(side='right')
        self._button(bar, 'Отчёт HTML', self._detective_export_html).pack(side='right', padx=8)
        self.detective_note = self._label(parent, 'Нажмите кнопку. Для лучших результатов включите мониторинг и SNMP-опрос.',
                                           10, color=MUTED)
        self.detective_note.pack(anchor='w', pady=(0, 10))
        frame, self.detective_table = self._tree(parent,
            ('Важность', 'Уверенность', 'Наблюдение'), (125, 130, 680))
        frame.pack(fill='both', expand=True)
        self.detective_table.configure(height=6)
        self.detective_table.bind('<<TreeviewSelect>>', self._detective_select)
        self.detective_table.tag_configure('warning', foreground=YELLOW)
        self.detective_table.tag_configure('notice', foreground=TEXT)
        self.detective_table.tag_configure('info', foreground=MUTED)
        self._label(parent, 'ПОЧЕМУ ТАКОЙ ВЫВОД И ЧТО ПРОВЕРИТЬ', 10, True, BLUE).pack(
            anchor='w', pady=(12, 5))
        self.detective_detail = tk.Text(parent, height=9, wrap='word', bg=PANEL, fg=TEXT,
            insertbackground=TEXT, relief='flat', font=('Segoe UI', 10), padx=12, pady=10)
        self.detective_detail.pack(fill='x')
        self.detective_detail.configure(state='disabled')
        self._label(parent, 'Выводы основаны на наблюдениях, не являются доказательством причины. '
                    'Экспорт содержит IP, имена устройств и другие сетевые идентификаторы.',
                    9, color=MUTED, wraplength=950, justify='left').pack(anchor='w', pady=(9, 0))

    def _detective_lldp_changes(self):
        """At most one freshest pair per switch; both captures must be recent.

        A historical change is deliberately NOT promoted to a live outage.
        """
        from datetime import datetime, timezone
        try:
            captures = self.store.lldp_captures(100)
        except sqlite3.Error:
            return ()
        grouped = {}
        now = datetime.now(timezone.utc)
        for ident, stamp, ip, _name, _count in captures:
            try:
                age = (now - datetime.fromisoformat(stamp).astimezone(timezone.utc)).total_seconds()
            except (ValueError, TypeError):
                continue
            if age < 0 or age > 1800:
                continue
            if len(grouped.setdefault(ip, [])) < 2:
                grouped[ip].append(ident)
        changes = []
        for ip, ids in list(sorted(grouped.items()))[:10]:
            if len(ids) == 2:
                try:
                    changes.extend(self.store.compare_lldp_captures(ids[1], ids[0])[:5])
                except (ValueError, sqlite3.Error):
                    continue
        return tuple(changes[:20])

    def _detective_analyze(self):
        now = time.monotonic()
        # Only recent measurements are used; restored inventory is not an observation.
        with self.state_lock:
            latest = {ip: state for ip, state in self._timeline_status.items()
                      if now - self._timeline_seen_at.get(ip, float('-inf')) <= max(90, 2 * self.monitor_interval + 30)}
        wifi_status = self.wifi_report.status
        obs = detective.Observation(
            gateway=self.gateway or '', availability=latest,
            wifi_connected=(bool(wifi_status.connected)
                            if self.wifi_previously_observed and wifi_status.adapter
                            and now - self._wifi_observed_at <= 180 else None),
            arp_suspicions=tuple(ip for ip in self.ip_alerts
                                 if self.ip_alert_expiry.get(ip, 0) > now),
            snmp_errors=tuple(sorted(self.topology_failed)),
            lldp_changes=self._detective_lldp_changes(),
            recent_events=detective.recent_device_events(self.store.events(250)),
            port_error_deltas=tuple(d for ip in self._fresh_topology()
                                    for d in self.port_error_deltas.get(ip, ())))
        self._detective_findings = detective.diagnose(obs)
        self.detective_table.delete(*self.detective_table.get_children())
        for n, f in enumerate(self._detective_findings):
            self.detective_table.insert('', 'end', iid=str(n),
                values=({'warning':'Предупреждение','notice':'Внимание','info':'Информация'}[f.severity],
                        f.confidence, f.title), tags=(f.severity,))
        self.detective_note.configure(text=f'Результатов: {len(self._detective_findings)} · '
            f'свежих ICMP: {len(latest)} · ошибок SNMP: {len(self.topology_failed)} · '
            'выводы проверяемы, не являются доказательствами поломки')
        self.detective_table.selection_set('0')
        self._detective_select()

    def _detective_select(self, _event=None):
        selection = self.detective_table.selection()
        if not selection:
            return
        index = int(selection[0])
        if index >= len(self._detective_findings):
            return
        f = self._detective_findings[index]
        detail = f'{f.title} · уверенность: {f.confidence}\n\n{f.interpretation}\n\nДОКАЗАТЕЛЬСТВА/НАБЛЮДЕНИЯ:\n'
        detail += ''.join(f'• {e.source}: {e.observation}\n' for e in f.evidence)
        detail += '\nЧТО ПРОВЕРИТЬ:\n' + ''.join(f'{n}. {a}\n' for n, a in enumerate(f.checks, 1))
        self.detective_detail.configure(state='normal')
        self.detective_detail.delete('1.0', 'end')
        self.detective_detail.insert('1.0', detail)
        self.detective_detail.configure(state='disabled')

    def _detective_export(self):
        if not self._detective_findings:
            messagebox.showinfo('Детектив', 'Сначала выполните анализ.', parent=self)
            return
        filename = filedialog.asksaveasfilename(
            title='Отчёт DETECTIVE (содержит IP и имена оборудования)',
            defaultextension='.json', filetypes=[('JSON', '*.json')], parent=self)
        if not filename:
            return
        try:
            with open(filename, 'w', encoding='utf-8') as fp:
                json.dump(detective.export_report(self._detective_findings), fp, ensure_ascii=False, indent=2)
            self._set_status('DETECTIVE: отчёт записан локально')
        except OSError:
            messagebox.showerror('Детектив', 'Не удалось сохранить отчёт.', parent=self)

    def _detective_export_html(self):
        if not self._detective_findings:
            messagebox.showinfo('Детектив', 'Сначала выполните анализ.', parent=self)
            return
        filename = filedialog.asksaveasfilename(
            title='HTML-отчёт DETECTIVE (содержит IP и имена оборудования)',
            defaultextension='.html', filetypes=[('HTML', '*.html')], parent=self)
        if not filename:
            return
        try:
            with open(filename, 'w', encoding='utf-8') as fp:
                fp.write(detective.export_html_report(self._detective_findings))
            self._set_status('DETECTIVE: HTML-отчёт записан локально')
        except OSError:
            messagebox.showerror('Детектив', 'Не удалось сохранить отчёт.', parent=self)

    def _page_ports(self):
        parent = self._new_page("Порты")
        self.port_note = self._label(parent,
            "SNMP IF-MIB: выберите управляемый коммутатор на вкладке «Карта сети» и включите автоопрос. "
            "Для скорости нужны два снимка 64-битных счётчиков.", 10, color=MUTED,
            wraplength=950, justify='left')
        self.port_note.pack(anchor='w', pady=(0, 15))
        frame, self.port_table = self._tree(parent,
            ("SNMP IP", "Интерфейс", "Состояние", "Вход Мбит/с", "Выход Мбит/с", "Скорость порта"),
            (140, 245, 115, 145, 145, 155))
        frame.pack(fill='both', expand=True)
        self.port_table.bind('<<TreeviewSelect>>', self._port_selected)
        self._label(parent, 'ИСТОРИЯ ТРАФИКА ВЫБРАННОГО ПОРТА (Мбит/с)',
                    10, True, MUTED).pack(anchor='w', pady=(12, 5))
        self.port_history_canvas = tk.Canvas(parent, bg=PANEL, height=110, highlightthickness=0)
        self.port_history_canvas.pack(fill='x', pady=(0, 5))
        self.port_history_canvas.bind('<Configure>', lambda _e: self._paint_port_history())
        self.port_history_note = self._label(parent, 'Выберите порт для просмотра локально сохранённой истории.',
                                             9, color=MUTED)
        self.port_history_note.pack(anchor='w', pady=(0, 5))
        self._label(parent, "Это скорость трафика по SNMP IF-MIB, а не доказательство прямого физического соединения. "
                    "«—» означает отсутствие достоверного измерения; оно не равно нулю.",
                    9, color=MUTED, wraplength=950, justify='left').pack(anchor='w', pady=12)

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
        self.tool_select = ttk.Combobox(line, values=("Ping × 4", "Traceroute", "DNS", "TCP-порт", "ARP-таблица", "Маршруты IPv4", "DHCP Windows"),
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
                       command=lambda: self._save_preference("alerts_enabled", self.alerts_enabled),
                       bg=BG, fg=TEXT, selectcolor=PANEL, activebackground=BG,
                       activeforeground=TEXT, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))
        tk.Checkbutton(parent, text="Уведомления Windows (по умолчанию выключены)",
                       variable=self.windows_alerts_enabled,
                       command=lambda: self._save_preference("windows_alerts_enabled", self.windows_alerts_enabled), bg=BG, fg=TEXT,
                       selectcolor=PANEL, activebackground=BG, activeforeground=TEXT,
                       font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 8))
        self._label(parent, "Работа в фоне (Windows, только текущий пользователь)",
                    11, True, BLUE).pack(anchor="w", pady=(6, 6))
        tk.Checkbutton(parent, text="Сворачивать в трей при закрытии окна (по умолчанию выход)",
                       variable=self.minimize_to_tray,
                       command=lambda: self._save_preference("minimize_to_tray", self.minimize_to_tray),
                       bg=BG, fg=TEXT, selectcolor=PANEL, activebackground=BG,
                       activeforeground=TEXT, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 6))
        tk.Checkbutton(parent, text="Запускать вместе со входом в Windows (без прав администратора)",
                       variable=self.autostart_enabled, command=self._set_autostart,
                       bg=BG, fg=TEXT, selectcolor=PANEL, activebackground=BG,
                       activeforeground=TEXT, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 7))
        self._label(parent, "Автозапуск запускает приложение свёрнутым только при доступном трее. "
                    "После перезапуска SNMP-реквизиты вводятся заново.",
                    9, color=MUTED).pack(anchor="w", pady=(0, 9))
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
        self._save_preference("monitor_enabled", self.monitor_enabled)
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
        self.monitor_thread = threading.Thread(target=self._monitor_worker, args=(self.monitor_stop,),
                                               daemon=True, name="BloodskyMonitor")
        self.monitor_thread.start()
        self._set_state("МОНИТОРИНГ", GREEN)

    def _monitor_worker(self, stop):
        try:
            tick = 0
            while not stop.is_set():
                if not self.scanning:
                    with self.state_lock:
                        ips = list(self.devices.keys())
                        open_ports = {ip: list(d.ports) for ip, d in self.devices.items() if d.ports}
                    if self.gateway and self.gateway not in ips:
                        ips.append(self.gateway)
                    if ips:
                        samples = net.poll_devices(ips, stop, open_ports)
                        neighbors = net.arp_table()
                        if not stop.is_set():
                            self.messages.put(("monitor", samples, neighbors))
                    if tick % 3 == 0:
                        self._read_wifi_background()
                tick += 1
                self.monitor_failures = 0  # a complete iteration succeeded
                stop.wait(max(3, self.monitor_interval))
        except Exception:
            if not stop.is_set():
                # Do not serialize exception text: drivers and command arguments can leak data.
                self.messages.put(("monitor_crashed", stop))
        finally:
            self.messages.put(("monitor_stopped", stop))

    def _monitor_guard(self):
        """Restart a crashed monitor with bounded backoff, never after user Stop."""
        if self._closed:
            return
        if self.monitor_enabled.get() and not self.scanning:
            thread = self.monitor_thread
            if (thread is None or not thread.is_alive()) and time.monotonic() >= self.monitor_restart_at:
                self.monitoring = False
                if self.devices or self.gateway:
                    self._start_monitor()
        self.after(2500, self._monitor_guard)

    def _save_preference(self, name, variable):
        try:
            self.store.set_preference(name, bool(variable.get()))
        except Exception:
            self._set_status("Не удалось сохранить настройки. Проверьте локальную базу данных.")

    def _set_autostart(self):
        desired = self.autostart_enabled.get()
        try:
            actual = windows_integration.set_autostart(desired)
            self.autostart_enabled.set(actual)
            if actual != desired:
                raise OSError("Параметр автозапуска не применён")
            self._set_status("Автозапуск Windows " + ("включён" if actual else "отключён"))
        except OSError as exc:
            self.autostart_enabled.set(windows_integration.is_autostart_enabled())
            messagebox.showwarning("Автозапуск", str(exc), parent=self)

    def _setup_tray(self):
        if sys.platform != "win32":
            return
        tray = TrayController(lambda: self.messages.put(("tray_show",)),
                              lambda: self.messages.put(("tray_exit",)))
        if tray.start():
            self.tray = tray
        else:
            # Without a working tray, never hide the only application window.
            self.tray = None

    def close_window(self):
        if self.minimize_to_tray.get() and self.tray and self.tray.active:
            self.withdraw()
            return
        self.shutdown()

    def show_window(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def _read_wifi_background(self):
        """Allow at most one slow WLAN query at a time (no thread buildup)."""
        with self._wifi_lock:
            if self._closed or self._wifi_busy.is_set():
                return
            self._wifi_busy.set()
        def worker():
            try:
                report = wifi.read_wifi()
                if not self._closed:
                    self.messages.put(("wifi", report))
            except Exception:
                # Background Windows WLAN failures may be transient; never log driver output.
                pass
            finally:
                self._wifi_busy.clear()
        try:
            threading.Thread(target=worker, daemon=True, name="BloodskyWiFi").start()
        except RuntimeError:
            self._wifi_busy.clear()

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
                    last = self.topology_snapshots.get(snapshot.source_ip)
                    last_at = self.topology_received.get(snapshot.source_ip)
                    received_at = time.monotonic()
                    self.port_rates[snapshot.source_ip] = (
                        traffic.calculate_port_rates(last.port_counters, snapshot.port_counters,
                                                     received_at - last_at)
                        if last is not None and last_at is not None else {})
                    self.port_error_deltas[snapshot.source_ip] = (
                        port_health.calculate_error_deltas(
                            snapshot.source_ip, last.error_counters, snapshot.error_counters,
                            received_at - last_at,
                            {idx: port.name for idx, port in snapshot.port_counters.items()})
                        if last is not None and last_at is not None else ())
                    self.store.save_port_rates(snapshot.source_ip, self.port_rates[snapshot.source_ip])
                    try:
                        self.store.save_lldp_capture(snapshot)
                        if self.current_page == 'Машина времени':
                            self._lldp_timeline_refresh(select_latest=True)
                    except (ValueError, sqlite3.Error):
                        self._set_status('Не удалось сохранить историю LLDP; текущий SNMP опрос продолжает работать')
                    self.topology_snapshots[snapshot.source_ip] = snapshot
                    self.topology_received[snapshot.source_ip] = received_at
                    self.topology_failed.discard(snapshot.source_ip)
                    self.snmp_due[snapshot.source_ip] = time.monotonic() + self.snmp_interval
                    self._event("info", "SNMP опрос", f"{snapshot.source_ip}: LLDP {len(snapshot.neighbors)}, FDB {len(snapshot.fdb_entries)}")
                    self._set_status(f"SNMP {snapshot.source_ip}: найдено {len(snapshot.neighbors)} LLDP соседей")
                    self._dirty = True
                elif kind == "topology_error":
                    self.snmp_busy = False
                    self.topology_failed.add(item[1])
                    self.port_rates.pop(item[1], None)
                    self.port_error_deltas.pop(item[1], None)
                    self.snmp_due[item[1]] = time.monotonic() + self.snmp_interval
                    self._set_status(f"SNMP {item[1]}: ошибка чтения, снимок помечен устаревшим")
                    self._event("warning", "SNMP/LLDP", f"{item[1]}: опрос не удался (проверьте SNMP/ACL)")
                    self._dirty = True
                elif kind == "tool":
                    self._console_text(item[1])
                    self.tool_button.configure(state="normal")
                elif kind == "monitor_crashed":
                    if item[1] is self.monitor_stop and self.monitor_enabled.get():
                        self.monitoring = False
                        self.monitor_failures += 1
                        delay = min(60, 3 * (2 ** min(self.monitor_failures - 1, 5)))
                        self.monitor_restart_at = time.monotonic() + delay
                        self._event("warning", "Мониторинг", f"Сбой опроса, повтор через {delay} сек")
                        self._set_state("ВОССТАНОВЛЕНИЕ", YELLOW)
                elif kind == "monitor_stopped":
                    if item[1] is self.monitor_stop and not item[1].is_set() and self.monitor_enabled.get():
                        self.monitoring = False
                elif kind == "tray_show":
                    self.show_window()
                elif kind == "tray_exit":
                    self.shutdown()
                    return
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
        if self.current_page in ('Карта сети', 'Порты') and self.topology_snapshots:
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
            now = time.monotonic()
            for dev in devices:
                self._timeline_status[dev.ip] = 'up' if dev.online else 'unknown'
                self._timeline_seen_at[dev.ip] = now
            self._timeline_capture('scan')
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
        now = time.monotonic()
        with self.state_lock:
            if self.gateway and self.gateway in samples:
                gw_result = samples[self.gateway]
                self._gateway_failures = 0 if gw_result.alive else self._gateway_failures + 1
                self._timeline_status[self.gateway] = ('up' if gw_result.alive else
                    ('down' if self._gateway_failures >= 2 else 'unknown'))
                self._timeline_seen_at[self.gateway] = now
            for ip, ping in samples.items():
                dev = self.devices.get(ip)
                if dev is not None:
                    self._timeline_status[ip] = ('up' if ping.alive else
                        ('down' if dev.failures >= 2 else 'unknown'))
                    self._timeline_seen_at[ip] = now
        if samples and now - self._timeline_last_capture >= 300:
            self._timeline_capture('monitor')
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
        self._wifi_observed_at = time.monotonic()
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
        if severity not in ("warning", "error") or self._closed:
            return
        if not self.alerts_enabled.get() and not self.windows_alerts_enabled.get():
            return
        now = time.monotonic()
        key = (severity, title, detail)
        if now - self.alert_last.get(key, float('-inf')) < 120:
            return
        self.alert_last[key] = now
        if len(self.alert_last) > 300:
            self.alert_last = {k: t for k, t in self.alert_last.items() if now - t < 300}
        if self.windows_alerts_enabled.get():
            notifications.alert_async(title, detail)
        if self.alerts_enabled.get():
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
        elif self.current_page == "Порты":
            self._paint_ports()
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

    def _map_selection(self, devices=None):
        if devices is None:
            with self.state_lock:
                devices = list(self.devices.values())
        return map_view.select_devices(devices, self.map_query.get(),
                                       self.map_status.get(), self.ip_alerts)

    def _map_layout(self, devices):
        zoom = int(self.map_zoom.get().rstrip("%")) / 100.0
        return map_view.layout_positions(devices, zoom, self.map_group.get(),
                                         self.map_manual_positions)

    def _draw_map(self, devices=None):
        if not hasattr(self, "map_canvas"):
            return
        view = self._map_selection(devices)
        canvas = self.map_canvas
        canvas.delete("all")
        width, height = max(canvas.winfo_width(), 880), max(canvas.winfo_height(), 590)
        center_x, center_y = width // 2, max(280, height // 2)
        self._map_center = (center_x, center_y)
        observed = map_view.lldp_edges(self._fresh_topology(), view.devices)
        fdb_rows = map_view.learned_ports(self._fresh_topology(), view.devices)
        canvas.create_text(24, 22,
            text=f"LIVE MAP · показано {len(view.devices)} из {view.total_matched} "
                 f"(всего {view.total_inventory}) · LLDP-соседств: {len(observed)}",
            fill=MUTED, anchor="w", font=("Segoe UI Semibold", 10))
        canvas.create_oval(center_x-68, center_y-46, center_x+68, center_y+46,
                           fill="#1B4566", outline=BLUE, width=2)
        canvas.create_text(center_x, center_y-10, text="ЛОКАЛЬНАЯ", fill=TEXT,
                           font=("Segoe UI Semibold", 10))
        canvas.create_text(center_x, center_y+9, text="СЕТЬ", fill=TEXT,
                           font=("Segoe UI Semibold", 10))
        canvas.create_text(center_x, center_y+57, text=f"Шлюз: {self.gateway or '—'}",
                           fill=BLUE, font=("Segoe UI", 10))
        positions = self._map_layout(view.devices)
        reach = max((abs(x) for _, x, _ in positions), default=185)
        reach_y = max((abs(y) for _, _, y in positions), default=185)
        canvas.configure(scrollregion=(min(0, center_x-reach-170), min(0, center_y-reach_y-155),
                                       max(width, center_x+reach+170),
                                       max(height, center_y+reach_y+155)))
        for group, (gx, gy) in map_view.group_centers(positions, self.map_group.get()).items():
            canvas.create_text(center_x+gx, center_y+gy, text=f"ГРУППА: {group}"[:55],
                               fill=BLUE, font=("Segoe UI Semibold", 10))
        for dev, dx, dy in positions:
            x, y = center_x+dx, center_y+dy
            canvas.create_line(center_x, center_y, x, y, fill="#2D4761", width=1,
                               dash=(4, 4))  # illustrative scheme, not a physical cable
        point_by_ip = {dev.ip: (center_x+dx, center_y+dy) for dev, dx, dy in positions}
        self._map_point_by_ip = point_by_ip
        for source, target, neighbor in observed:
            if source not in point_by_ip or target not in point_by_ip:
                continue
            x1, y1 = point_by_ip[source]
            x2, y2 = point_by_ip[target]
            canvas.create_line(x1, y1, x2, y2, fill=BLUE, width=3)
            canvas.create_text((x1+x2)/2, (y1+y2)/2-9,
                               text=f"{neighbor.local_port} ↔ {neighbor.remote_port}"[:34],
                               fill=BLUE, font=("Segoe UI", 9))
        for dev, dx, dy in positions:
            x, y = center_x+dx, center_y+dy
            key = f"host:{dev.ip}"
            color = YELLOW if dev.ip in self.ip_alerts else (GREEN if dev.online else RED)
            outline = BLUE if dev.ip == self.map_selected_ip else BG
            canvas.create_oval(x-12, y-12, x+12, y+12,
                               fill=color, outline=outline, width=3, tags=(key, "node"))
            canvas.create_text(x, y+23, text=dev.ip, fill=TEXT,
                               font=("Consolas", 10), tags=(key, "node"))
            canvas.create_text(x, y+38, text=(dev.hostname or dev.kind)[:24], fill=MUTED,
                               font=("Segoe UI", 9), tags=(key, "node"))
            evidence = fdb_rows.get(dev.ip, ())
            if evidence:
                if len(evidence) == 1:
                    ent = evidence[0]
                    label = f"FDB: {ent.interface[:12]} · VLAN {ent.vlan if ent.vlan is not None else '?'}"
                else:
                    label = f"FDB: {len(evidence)} наблюдения (порт неоднозначен)"
                canvas.create_text(x, y+53, text=label[:52], fill=YELLOW,
                                   font=("Segoe UI", 8), tags=(key, "node"))
            canvas.tag_bind(key, "<ButtonPress-1>", lambda e, ip=dev.ip: self._map_drag_begin(e, ip))
            canvas.tag_bind(key, "<B1-Motion>", lambda e, ip=dev.ip: self._map_drag_move(e, ip))
            canvas.tag_bind(key, "<ButtonRelease-1>", lambda e, ip=dev.ip: self._map_drag_end(e, ip))
        if view.omitted:
            canvas.create_text(24, 46, text=f"Ещё {view.omitted} узлов не помещаются на карту: уточните фильтр",
                               fill=YELLOW, anchor="w", font=("Segoe UI", 9))
        if not view.devices:
            canvas.create_text(center_x, center_y+85,
                text=("Нет устройств под текущим фильтром" if view.total_inventory else
                      "Начните сканирование подсети для построения карты"),
                fill=MUTED, font=("Segoe UI", 12))
        if self.map_selected_ip in {d.ip for d in view.devices}:
            self._show_map_passport(self.map_selected_ip, view.devices, observed, fdb_rows)

    def _map_drag_begin(self, event, ip):
        self._map_drag_state = (ip, event.x, event.y, event.x, event.y)

    def _map_drag_move(self, event, ip):
        state = self._map_drag_state
        if not state or state[0] != ip:
            return
        _, x0, y0, last_x, last_y = state
        self.map_canvas.move(f"host:{ip}", event.x-last_x, event.y-last_y)
        self._map_drag_state = (ip, x0, y0, event.x, event.y)

    def _map_drag_end(self, event, ip):
        state = self._map_drag_state
        self._map_drag_state = None
        if not state or state[0] != ip:
            return
        _, x0, y0, _, _ = state
        dx, dy = event.x-x0, event.y-y0
        if abs(dx) + abs(dy) < 5:
            self._map_pick(ip)
            return
        if ip not in self._map_point_by_ip:
            return
        px, py = self._map_point_by_ip[ip]
        zoom = int(self.map_zoom.get().rstrip("%")) / 100.0
        x, y = (px+dx-self._map_center[0])/zoom, (py+dy-self._map_center[1])/zoom
        if map_view.valid_position(x, y):
            self.store.save_map_position(ip, x, y)
            self.map_manual_positions[ip] = (x, y)
        self._draw_map()

    def _reset_map_positions(self):
        self.store.clear_map_positions()
        self.map_manual_positions.clear()
        self._draw_map()

    def _show_map_passport(self, ip, devices=None, observed=None, fdb_rows=None):
        if not hasattr(self, 'map_device_detail'):
            return
        if devices is None:
            with self.state_lock:
                devices = list(self.devices.values())
        device = next((d for d in devices if d.ip == ip), None)
        if not device:
            self.map_device_detail.configure(text="Выберите обнаруженное устройство")
            return
        fresh = self._fresh_topology()
        observed = observed if observed is not None else map_view.lldp_edges(fresh, devices)
        fdb_rows = fdb_rows if fdb_rows is not None else map_view.learned_ports(fresh, devices)
        links = [n for source, target, n in observed if ip in (source, target)]
        self.map_device_detail.configure(text=map_view.passport(device, fdb_rows.get(ip, ()), links))

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

    def _paint_ports(self):
        self.port_table.delete(*self.port_table.get_children())
        fresh = self._fresh_topology()
        count = 0
        for ip, snapshot in sorted(fresh.items()):
            rates = self.port_rates.get(ip, {})
            for idx, counter in sorted(snapshot.port_counters.items()):
                if count >= 500:
                    break
                rate = rates.get(idx)
                def fmt(value):
                    return f'{value:.3f}' if value is not None else '—'
                self.port_table.insert('', 'end', iid=f'{ip}|{idx}', values=(
                    ip, counter.name,
                    'Up' if counter.oper_up is True else 'Down' if counter.oper_up is False else 'неизвестно',
                    fmt(rate.inbound_mbps) if rate else '—',
                    fmt(rate.outbound_mbps) if rate else '—',
                    f'{counter.speed_mbps} Мбит/с' if counter.speed_mbps else '—'))
                count += 1
        self.port_note.configure(text=(
            f'Получено {count} портов из {len(fresh)} свежих SNMP-снимков. '
            'Скорость рассчитывается по разнице последовательных 64-битных счётчиков; '
            'неизвестные значения не подменяются нулём.'))
        self._paint_port_history()

    def _port_selected(self, _event=None):
        selected = self.port_table.selection()
        if selected:
            try:
                ip, index = selected[0].rsplit('|', 1)
                self.selected_port = (ip, int(index))
            except (ValueError, IndexError):
                self.selected_port = None
        self._paint_port_history()

    def _paint_port_history(self):
        if not hasattr(self, 'port_history_canvas'):
            return
        if self.selected_port is None:
            self._draw_curve(self.port_history_canvas, [], BLUE)
            return
        ip, idx = self.selected_port
        rows = self.store.port_history(ip, idx)
        received = [row[1] for row in rows]
        transmitted = [row[2] for row in rows]
        self._draw_port_traffic_curves(received, transmitted)
        if len(rows) >= 2:
            self.port_history_note.configure(
                text=f'{ip}, ifIndex {idx}: {len(rows)} точек, {rows[0][0]} — {rows[-1][0]}. '
                     f'Вход: {received[-1]:.3f}, выход: {transmitted[-1]:.3f} Мбит/с.')
        else:
            self.port_history_note.configure(text=f'{ip}, ifIndex {idx}: для графика нужно не менее двух измерений.')

    def _draw_port_traffic_curves(self, received: list[float], transmitted: list[float]):
        canvas = self.port_history_canvas
        canvas.delete('all')
        w, h = max(90, canvas.winfo_width()), max(75, canvas.winfo_height())
        left, right, top, bottom = 32, 10, 12, 20
        usable_h = max(10, h - top - bottom)
        usable_w = max(10, w - left - right)
        for i in range(4):
            y = top + usable_h * i / 3
            canvas.create_line(left, y, w - right, y, fill=BORDER, dash=(3, 5))
        if len(received) < 2:
            canvas.create_text(w / 2, h / 2, text='История появится после двух замеров порта',
                               fill=MUTED, font=('Segoe UI', 10))
            return
        maximum = max(1.0, max(received + transmitted) * 1.15)
        for values, color in ((received, BLUE), (transmitted, GREEN)):
            points = []
            for i, value in enumerate(values):
                x = left + usable_w * i / (len(values) - 1)
                y = top + usable_h * (1 - min(1.0, value / maximum))
                points.extend([x, y])
            canvas.create_line(*points, fill=color, width=2)
        canvas.create_text(left + 5, h - 5, anchor='w', text='Вход', fill=BLUE, font=('Segoe UI', 9))
        canvas.create_text(left + 63, h - 5, anchor='w', text='Выход', fill=GREEN, font=('Segoe UI', 9))
        canvas.create_text(left - 2, top, anchor='e', text=f'{maximum:.1f}', fill=MUTED, font=('Segoe UI', 8))

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
        self.map_selected_ip = ip
        self._show_map_passport(ip)
        self._draw_map()

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
        if kind not in ("ARP-таблица", "Маршруты IPv4", "DHCP Windows"):
            try:
                target = net.valid_target(target)
            except ValueError as exc:
                messagebox.showwarning("Цель диагностики", str(exc), parent=self)
                return
        port = 443
        if kind == "TCP-порт":
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
            elif kind == "DHCP Windows":
                code, result = dhcp.read_dhcp_configuration()
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
        """Export the exact filtered view, with observed LLDP lines distinguished from layout."""
        from html import escape
        filename = filedialog.asksaveasfilename(defaultextension=".svg", filetypes=[("Векторная карта SVG", "*.svg")],
                                                initialfile="bloodsky_network_map.svg", parent=self)
        if not filename:
            return
        view = self._map_selection()
        zoom = int(self.map_zoom.get().rstrip("%")) / 100.0
        positions = self._map_layout(view.devices)
        reach = max(350, max((max(abs(x), abs(y)) for _, x, y in positions), default=185*zoom)+150)
        width = height = int(2*reach+40)
        center = width/2
        parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
                 f'<rect width="100%" height="100%" fill="{PANEL}"/>',
                 f'<text x="28" y="34" font-family="Segoe UI,sans-serif" font-size="20" fill="{TEXT}">BLOODSKY NET — LIVE MAP (LLDP-наблюдение ≠ проверка кабеля)</text>']
        for d, dx, dy in positions:
            x, y = center+dx, center+dy
            parts.append(f'<line x1="{center}" y1="{center}" x2="{x:.1f}" y2="{y:.1f}" stroke="{BORDER}" stroke-dasharray="5 6"/>')
        parts += [f'<circle cx="{center}" cy="{center}" r="59" fill="#1B4566" stroke="{BLUE}" stroke-width="2"/>',
                  f'<text x="{center}" y="{center+5}" text-anchor="middle" fill="{TEXT}" font-size="17" font-family="Segoe UI,sans-serif">LAN</text>']
        for group, (gx, gy) in map_view.group_centers(positions, self.map_group.get()).items():
            parts.append(f'<text x="{center+gx:.1f}" y="{center+gy:.1f}" text-anchor="middle" fill="{BLUE}" font-size="14">ГРУППА: {escape(group[:55])}</text>')
        by_ip = {d.ip: (center+dx, center+dy) for d, dx, dy in positions}
        fdb_rows = map_view.learned_ports(self._fresh_topology(), view.devices)
        for source, target, neighbor in map_view.lldp_edges(self._fresh_topology(), view.devices):
            if source not in by_ip or target not in by_ip:
                continue
            x1, y1 = by_ip[source]
            x2, y2 = by_ip[target]
            parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{BLUE}" stroke-width="3"/>')
            port_label = escape((neighbor.local_port+' ↔ '+neighbor.remote_port)[:34])
            parts.append(f'<text x="{(x1+x2)/2:.1f}" y="{(y1+y2)/2-9:.1f}" text-anchor="middle" fill="{BLUE}" font-size="11">{port_label}</text>')
        for d, dx, dy in positions:
            x, y = center+dx, center+dy
            color = YELLOW if d.ip in self.ip_alerts else (GREEN if d.online else RED)
            label = escape((d.hostname or d.kind)[:28])
            parts.extend([f'<circle cx="{x:.1f}" cy="{y:.1f}" r="12" fill="{color}"/>',
                          f'<text x="{x:.1f}" y="{y+30:.1f}" text-anchor="middle" fill="{TEXT}" font-family="Consolas,monospace" font-size="13">{escape(d.ip)}</text>',
                          f'<text x="{x:.1f}" y="{y+47:.1f}" text-anchor="middle" fill="{MUTED}" font-family="Segoe UI,sans-serif" font-size="11">{label}</text>'])
            evidence = fdb_rows.get(d.ip, ())
            if evidence:
                if len(evidence) == 1:
                    item = evidence[0]
                    summary = f'FDB {item.interface[:12]} / VLAN {item.vlan if item.vlan is not None else "?"} (изучен MAC)'
                else:
                    summary = f'FDB: {len(evidence)} наблюдения, порт неоднозначен'
                parts.append(f'<text x="{x:.1f}" y="{y+62:.1f}" text-anchor="middle" fill="{YELLOW}" font-size="10">{escape(summary)}</text>')
        parts.append('</svg>')
        try:
            with open(filename, "w", encoding="utf-8") as fd:
                fd.write("\n".join(parts))
            self._set_status(f"Карта SVG сохранена: {filename}")
        except OSError as exc:
            messagebox.showerror("Экспорт карты", str(exc), parent=self)

    def shutdown(self):
        if self._closed:
            return
        self._closed = True
        self.scan_stop.set()
        self.monitor_stop.set()
        if self.tray is not None:
            self.tray.stop()
            self.tray = None
        self.snmp_auto_enabled = False
        self.snmp_profiles.clear()
        self.snmp_due.clear()
        try:
            self.store.close()
        except Exception:
            pass
        self.destroy()

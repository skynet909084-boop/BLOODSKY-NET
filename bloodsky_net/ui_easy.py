"""BLOODSKY NET: optional beginner navigation around the unchanged professional UI.

Inherits the existing NetApp; all diagnostics and permissions remain unchanged.
Only the navigation and an opt-in quick-start guide differ. Never scans on its own.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from .ui import NetApp as ProfessionalNetApp, BG, SIDEBAR, PANEL, PANEL_ALT, TEXT, MUTED, BLUE
from .ui_modes import read_ui_flag, write_ui_flag

SIMPLE_PAGES = ("Обзор", "Устройства", "Карта сети", "Wi-Fi", "Детектив")
SIMPLE_NAMES = {
    "Обзор": "Главная",
    "Устройства": "Мои устройства",
    "Карта сети": "Карта сети",
    "Wi-Fi": "Мой Wi-Fi",
    "Детектив": "Проблемы",
}
SIMPLE_TITLES = {
    "Обзор": "Главная · состояние сети",
    "Устройства": "Устройства в моей сети",
    "Карта сети": "Карта сети",
    "Wi-Fi": "Мой Wi-Fi",
    "Детектив": "Проверка возможных проблем",
}
PAGE_HELP = {
    "Устройства": "Это найденные в сети устройства. Отсутствие ответа Ping не всегда означает неисправность.",
    "Карта сети": "Карта помогает увидеть устройства. Реальные кабели и порты известны только при наличии LLDP/SNMP.",
    "Wi-Fi": "Показатели сигнала берутся из Windows. Проценты сигнала не равны скорости подключения.",
    "Детектив": "Нажмите «Найти вероятную причину»: программа объяснит имеющиеся измерения и что проверить.",
}


class NetApp(ProfessionalNetApp):
    """Friendly shell, preserving the professional screen implementation."""

    def _layout(self):
        # Called by ProfessionalNetApp.__init__ only after self.store exists.
        self.simple_mode = tk.BooleanVar(value=not read_ui_flag(self.store, "advanced_ui"))
        super()._layout()
        self._original_nav_text = {name: btn.cget("text") for name, btn in self.nav_buttons.items()}
        self._sidebar = next(iter(self.nav_buttons.values())).master
        self._sidebar_spacer = next((child for child in self._sidebar.winfo_children()
                                     if child.winfo_manager() == "pack" and
                                     str(child.pack_info().get("expand", "0")) in ("1", "True")), None)
        self._make_mode_switch()
        self._make_guides()
        self._apply_mode(persist=False)

    def _make_mode_switch(self):
        panel = tk.Frame(self._sidebar, bg=SIDEBAR)
        self.mode_panel = panel
        first = next(iter(self.nav_buttons.values()))
        panel.pack(fill="x", padx=12, pady=(3, 9), before=first)
        self._label(panel, "РЕЖИМ", 9, True, MUTED).pack(anchor="w", pady=(0, 4))
        options = tk.Frame(panel, bg=SIDEBAR)
        options.pack(fill="x")
        for name, value in (("Простой", True), ("Специалист", False)):
            tk.Radiobutton(options, text=name, variable=self.simple_mode, value=value,
                           indicatoron=False, command=self._apply_mode,
                           font=("Segoe UI", 9), relief="flat", bd=0, padx=4, pady=6,
                           bg=PANEL_ALT, fg=TEXT, activebackground="#235577",
                           activeforeground=TEXT, selectcolor="#235577",
                           highlightthickness=0).pack(side="left", fill="x", expand=True, padx=1)
        help_button = self._button(self._sidebar, "?  Как пользоваться", self._show_help)
        help_button.configure(font=("Segoe UI", 9), padx=7, pady=5)
        self.ui_help_button = help_button
        if self._sidebar_spacer:
            help_button.pack(fill="x", padx=12, pady=4, before=self._sidebar_spacer)
        else:
            help_button.pack(fill="x", padx=12, pady=4)

    def _make_guides(self):
        self._guide_labels = {}
        for page, body in PAGE_HELP.items():
            host = self.pages[page]
            first = host.winfo_children()[0]
            hint = self._label(host, body, 9, color=MUTED, wraplength=940, justify="left")
            self._guide_labels[page] = (hint, first)
        overview = self.pages["Обзор"]
        self._first_overview_widget = overview.winfo_children()[0]
        intro = self._panel(overview)
        self.quick_start = intro
        self._label(intro, "НАЧНИТЕ С ПРОВЕРКИ СЕТИ", 11, True, BLUE).pack(anchor="w", padx=15, pady=(10, 3))
        self._label(intro, "1. Проверьте адрес сети сверху.  2. Нажмите «Сканировать».  3. Откройте «Проблемы».",
                    9, color=TEXT, wraplength=950, justify="left").pack(anchor="w", padx=15, pady=(0, 8))
        bar = tk.Frame(intro, bg=PANEL)
        bar.pack(fill="x", padx=15, pady=(0, 10))
        self._button(bar, "Сканировать сеть", self.start_scan, primary=True).pack(side="left")
        self._button(bar, "Что означают результаты?", self._show_help).pack(side="left", padx=8)
        self._button(bar, "Понятно", self._dismiss_guide).pack(side="right")

    def _dismiss_guide(self):
        write_ui_flag(self.store, "onboarding_seen", True)
        self.quick_start.pack_forget()

    def _show_help(self):
        messagebox.showinfo("BLOODSKY NET · Как пользоваться",
                            "1. На главной странице проверьте предложенный адрес подсети.\n"
                            "2. Нажмите «Сканировать» — это поиск устройств в выбранной локальной сети.\n"
                            "3. Откройте «Мои устройства» или «Карта сети» для просмотра результатов.\n"
                            "4. Раздел «Проблемы» объясняет наблюдения и предлагает проверки.\n"
                            "5. «Мой Wi-Fi» показывает данные беспроводного адаптера Windows.\n\n"
                            "Для LLDP, SNMP, истории, Wi-Fi-обследований и TLS-датчиков выберите «Специалист».\n"
                            "Отсутствие ответа Ping не доказывает отключение устройства.\n"
                            "Никакие настройки сети не меняются автоматически.", parent=self)

    def _apply_mode(self, persist: bool = True):
        simple = bool(self.simple_mode.get())
        if persist:
            write_ui_flag(self.store, "advanced_ui", not simple)
        # Keep every original page alive; only the navigation is simplified.
        for name, btn in self.nav_buttons.items():
            btn.pack_forget()
            if simple and name not in SIMPLE_PAGES:
                continue
            btn.configure(text=("  ◆   " + SIMPLE_NAMES[name]) if simple
                          else self._original_nav_text[name], pady=3, font=("Segoe UI", 10))
            if self._sidebar_spacer:
                btn.pack(fill="x", padx=9, pady=1, before=self._sidebar_spacer)
            else:
                btn.pack(fill="x", padx=9, pady=1)
        for hint, first in self._guide_labels.values():
            hint.pack_forget()
        if simple:
            for hint, first in self._guide_labels.values():
                hint.pack(anchor="w", fill="x", before=first, pady=(0, 10))
        self.quick_start.pack_forget()
        if simple and not read_ui_flag(self.store, "onboarding_seen"):
            self.quick_start.pack(fill="x", before=self._first_overview_widget, pady=(0, 12))
        if simple and self.current_page not in SIMPLE_PAGES:
            self.show_page("Обзор")
        else:
            self.show_page(self.current_page)

    def show_page(self, page):
        super().show_page(page)
        if getattr(self, "simple_mode", None) is not None and self.simple_mode.get():
            if page in SIMPLE_TITLES:
                self.title_label.configure(text=SIMPLE_TITLES[page])

"""
kernels/k4_phantom_dashboard/tui.py — Rich TUI + FastAPI WebSocket (Phantom Mode)
Autor: Luis Sánchez — BLACK LEVIATAN v29

Modo TUI:     Rich Live en terminal — para uso local
Modo Phantom: Solo WebSocket FastAPI — para SSH remoto / headless
Modo Silent:  Sin output visual — para CI/CD o scripting
"""
from __future__ import annotations
import asyncio
import json
import logging
import time
from typing import Optional, TYPE_CHECKING

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich import box

if TYPE_CHECKING:
    from bl_config import BLConfig, MochaTheme
    from core.event_bus import EventBus
    from core.state_manager import StateManager
    from core.vigilante_v2 import VigilanteV2

log = logging.getLogger("bl.k4")


# ──────────────────────────────────────────────
# Colores Catppuccin Mocha (constantes Rich)
# ──────────────────────────────────────────────
C_BG      = "#1E1E2E"
C_SURFACE = "#313244"
C_TEXT    = "#CDD6F4"
C_GREEN   = "#A6E3A1"
C_RED     = "#F38BA8"
C_YELLOW  = "#F9E2AF"
C_BLUE    = "#89B4FA"
C_MAUVE   = "#CBA6F7"
C_TEAL    = "#94E2D5"
C_PEACH   = "#FAB387"
C_LAVENDER= "#B4BEFE"
C_PINK    = "#F5C2E7"
C_SUBTEXT = "#BAC2DE"


def severity_color(sev: str) -> str:
    return {
        "CRITICAL": C_RED,
        "HIGH":     C_PEACH,
        "MEDIUM":   C_YELLOW,
        "LOW":      C_TEAL,
        "INFO":     C_BLUE,
    }.get(sev, C_TEXT)


def status_color(status: str) -> str:
    return {
        "SCANNING":   C_GREEN,
        "EVADING":    C_YELLOW,
        "PAUSED":     C_YELLOW,
        "DONE":       C_TEAL,
        "ERROR":      C_RED,
        "IDLE":       C_SUBTEXT,
    }.get(status, C_TEXT)


class PhantomDashboard:
    """
    K4: Dashboard con 3 modos de operación.
    """

    BANNER = f"""[bold {C_MAUVE}]
 ██████╗ ██╗      █████╗  ██████╗██╗  ██╗    ██╗     ███████╗██╗   ██╗██╗ █████╗ ████████╗ █████╗ ███╗   ██╗
 ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝    ██║     ██╔════╝██║   ██║██║██╔══██╗╚══██╔══╝██╔══██╗████╗  ██║
 ██████╔╝██║     ███████║██║     █████╔╝     ██║     █████╗  ██║   ██║██║███████║   ██║   ███████║██╔██╗ ██║
 ██╔══██╗██║     ██╔══██║██║     ██╔═██╗     ██║     ██╔══╝  ╚██╗ ██╔╝██║██╔══██║   ██║   ██╔══██║██║╚██╗██║
 ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗    ███████╗███████╗ ╚████╔╝ ██║██║  ██║   ██║   ██║  ██║██║ ╚████║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    ╚══════╝╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝[/]"""

    def __init__(
        self,
        config:    "BLConfig",
        bus:       "EventBus",
        state:     "StateManager",
        vigilante: "VigilanteV2",
    ) -> None:
        self._config    = config
        self._bus       = bus
        self._state     = state
        self._vigilante = vigilante
        self._mode      = config.dashboard.mode
        self._console   = Console(highlight=False)
        self._live:     Optional[Live] = None
        self._task:     Optional[asyncio.Task] = None
        self._ws_task:  Optional[asyncio.Task] = None
        self._recent_findings: list[dict] = []
        self._recent_events:   list[str]  = []

        # Suscribirse a findings para el feed en vivo
        bus.subscribe("finding.new",    self._on_finding)
        bus.subscribe("phase.*.start",  self._on_phase_start)
        bus.subscribe("phase.*.done",   self._on_phase_done)

    async def start(self) -> None:
        if self._mode == "tui":
            self._task = asyncio.create_task(self._tui_loop(), name="k4_tui")
        elif self._mode == "phantom":
            self._ws_task = asyncio.create_task(self._ws_server(), name="k4_ws")
            log.info("K4 Phantom: WebSocket en ws://%s:%d",
                     self._config.dashboard.ws_host,
                     self._config.dashboard.ws_port)
        # silent mode: sin output

    async def stop(self) -> None:
        if self._live:
            self._live.stop()
        if self._task:
            self._task.cancel()
            try: await self._task
            except asyncio.CancelledError: pass
        if self._ws_task:
            self._ws_task.cancel()
            try: await self._ws_task
            except asyncio.CancelledError: pass

    # ── TUI Loop ──────────────────────────────
    async def _tui_loop(self) -> None:
        self._console.clear()
        self._console.print(self.BANNER)
        self._console.print(
            f"[{C_SUBTEXT}]Creado por [{C_MAUVE}]Luis Sánchez[/] | "
            f"{self._config.dashboard.project_name} "
            f"[{C_BLUE}]{self._config.dashboard.version}[/][/]"
        )

        with Live(
            self._build_layout(),
            console=self._console,
            refresh_per_second=1.0 / self._config.dashboard.refresh_rate,
            screen=False,
        ) as live:
            self._live = live
            while True:
                await asyncio.sleep(self._config.dashboard.refresh_rate)
                try:
                    live.update(self._build_layout())
                except Exception:
                    break

    def _build_layout(self) -> Layout:
        s = self._state.state

        layout = Layout()
        layout.split_column(
            Layout(self._header_panel(), size=3),
            Layout(name="main"),
            Layout(self._queue_panel(), size=4),
            Layout(self._footer_panel(), size=3),
        )
        layout["main"].split_row(
            Layout(self._status_panel(), ratio=1),
            Layout(self._phases_panel(), ratio=1),
            Layout(self._findings_panel(), ratio=1),
        )
        return layout

    def _queue_panel(self) -> Panel:
        # Queue / Rate / Resources — nueva observabilidad
        try:
            from pathlib import Path
            import psutil, os
            rss = psutil.Process(os.getpid()).memory_info().rss // 1024 // 1024
            rss_str = f"{rss} MB"
        except Exception:
            rss_str = "?"
        # Bus stats
        try:
            qsize = self._bus.stats["queue_size"]
            dlq = self._bus.stats["dead_letter_count"]
        except: qsize=0; dlq=0
        cb = self._state.state.circuit_breaks
        rate = getattr(self._vigilante._bpm, "current_delay", "?") if hasattr(self, "_vigilante") else "?"
        msg = f"[{C_SUBTEXT}]COLA[/] pending:{qsize} dlq:{dlq} cb:{cb} │ [{C_SUBTEXT}]RATE[/] delay:{rate}s │ [{C_SUBTEXT}]RAM[/] {rss_str} │ [{C_SUBTEXT}]Target[/] {self._state.state.target[:22]}"
        # Add target_info warnings if any
        return Panel(msg, border_style=C_SURFACE, style=f"on {C_BG}")

    def _header_panel(self) -> Panel:
        s = self._state.state
        target_str = f"[{C_TEAL}]{s.target or 'sin target'}[/]"
        status_str = f"[bold {status_color(s.status.name)}]{s.status.name}[/]"
        elapsed    = f"[{C_SUBTEXT}]{s.elapsed:.0f}s[/]"
        cb_str     = f"[{C_YELLOW}]{s.circuit_breaks} CB[/]" if s.circuit_breaks > 0 else ""
        title = (
            f"[bold {C_MAUVE}]BLACK LEVIATAN v29[/] | "
            f"[{C_SUBTEXT}]by[/] [{C_LAVENDER}]Luis Sánchez[/] | "
            f"Target: {target_str} | Status: {status_str} | ⏱ {elapsed} {cb_str}"
        )
        return Panel(title, style=f"on {C_BG}", border_style=C_SURFACE)

    def _status_panel(self) -> Panel:
        s = self._state.state
        t = Table(box=None, padding=(0, 1), show_header=False)
        t.add_column(style=C_SUBTEXT)
        t.add_column(style=C_TEXT)

        risk_color = C_RED if s.risk_score >= 8 else C_PEACH if s.risk_score >= 6 else C_GREEN
        t.add_row("Risk Score",    f"[bold {risk_color}]{s.risk_score:.1f}/10[/]")
        t.add_row("Findings",      f"[{C_TEXT}]{s.total_findings}[/]")
        t.add_row("  Critical",    f"[{C_RED}]{s.critical_count}[/]")
        t.add_row("  High",        f"[{C_PEACH}]{s.high_count}[/]")
        t.add_row("Requests",      f"[{C_BLUE}]{s.requests_sent:,}[/]")
        t.add_row("Proxy Rot.",    f"[{C_TEAL}]{s.proxy_rotations}[/]")
        t.add_row("Circuit Brk",  f"[{C_YELLOW}]{s.circuit_breaks}[/]")
        t.add_row("Plugins",       f"[{C_LAVENDER}]{s.plugins_loaded}[/]")
        t.add_row("Progress",      f"[{C_GREEN}]{s.overall_progress*100:.1f}%[/]")
        t.add_row("Module",        f"[{C_MAUVE}]{s.active_module or '—'}[/]")

        # Vigilante FSM
        vsm = self._vigilante.fsm_state
        vsm_col = C_YELLOW if vsm in ("EVADING", "BLOCKED") else C_GREEN
        t.add_row("Vigilante",    f"[{vsm_col}]{vsm}[/]")

        return Panel(t, title=f"[bold {C_BLUE}]▸ Estado del Sistema[/]",
                     border_style=C_SURFACE, style=f"on {C_BG}")

    def _phases_panel(self) -> Panel:
        s = self._state.state
        t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {C_BLUE}")
        t.add_column("Fase",    style=C_SUBTEXT, width=4)
        t.add_column("Nombre",  style=C_TEXT,    width=14)
        t.add_column("Estado",  width=10)
        t.add_column("Prog",    width=6)
        t.add_column("Findings",width=8)

        phase_names = {
            1:"Recon",2:"Discovery",3:"Enum",4:"Correlate",5:"Breach",
            6:"Social",7:"AI",8:"Deep",9:"Historical",10:"Cloud"
        }
        for i in range(1, 11):
            ph = s.phases.get(i)
            if ph:
                status_icons = {
                    "pending":  f"[{C_SUBTEXT}]○ Pending[/]",
                    "running":  f"[{C_YELLOW}]◉ Running[/]",
                    "done":     f"[{C_GREEN}]✓ Done[/]",
                    "failed":   f"[{C_RED}]✗ Failed[/]",
                    "skipped":  f"[{C_SUBTEXT}]— Skip[/]",
                }
                prog = f"{ph.progress*100:.0f}%" if ph.status == "running" else ""
                t.add_row(
                    str(i),
                    phase_names.get(i, f"P{i}"),
                    status_icons.get(ph.status, ph.status),
                    prog,
                    str(ph.findings) if ph.findings > 0 else "—",
                )

        return Panel(t, title=f"[bold {C_MAUVE}]▸ DAG — 10 Fases[/]",
                     border_style=C_SURFACE, style=f"on {C_BG}")

    def _findings_panel(self) -> Panel:
        t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {C_BLUE}")
        t.add_column("Sev",   width=3)
        t.add_column("Tipo",  width=14)
        t.add_column("Valor", width=28, no_wrap=True)

        for f in self._recent_findings[-12:]:
            sev = f.get("severity", "INFO")
            col = severity_color(sev)
            sev_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}.get(sev,"●")
            val = str(f.get("value", ""))
            if len(val) > 28:
                val = val[:25] + "..."
            t.add_row(
                sev_icon,
                f"[{C_SUBTEXT}]{f.get('type','?')[:14]}[/]",
                f"[{col}]{val}[/]",
            )

        return Panel(t, title=f"[bold {C_TEAL}]▸ Findings en Vivo[/]",
                     border_style=C_SURFACE, style=f"on {C_BG}")

    def _footer_panel(self) -> Panel:
        s = self._state.state
        events_str = " │ ".join(self._recent_events[-5:]) if self._recent_events else "Iniciando..."
        msg = f"[{C_SUBTEXT}]{events_str}[/]"
        return Panel(msg, border_style=C_SURFACE, style=f"on {C_BG}")

    # ── Phantom WebSocket ─────────────────────
    async def _ws_server(self) -> None:
        try:
            import websockets
            from websockets.server import serve
            import secrets

            ws_token = secrets.token_urlsafe(32)
            log.info("K4 Phantom WebSocket token: %s", ws_token)

            async def handler(ws):
                try:
                    first_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    if first_msg != ws_token:
                        await ws.close(4001, "Unauthorized")
                        return
                except asyncio.TimeoutError:
                    await ws.close(4001, "Token timeout")
                    return

                async def sender():
                    while True:
                        await asyncio.sleep(1.0)
                        try:
                            payload = json.dumps(self._state.snapshot())
                            await ws.send(payload)
                        except Exception:
                            break
                await sender()

            async with serve(
                handler,
                self._config.dashboard.ws_host,
                self._config.dashboard.ws_port,
            ):
                log.info("K4 Phantom WebSocket escuchando en %s:%d (auth requerido)",
                         self._config.dashboard.ws_host,
                         self._config.dashboard.ws_port)
                await asyncio.Future()   # run forever
        except Exception as exc:
            log.error("K4 WebSocket error: %s", exc)

    # ── Callbacks del bus ─────────────────────
    async def _on_finding(self, event) -> None:
        self._recent_findings.append(event.data)
        if len(self._recent_findings) > 200:
            self._recent_findings.pop(0)

    async def _on_phase_start(self, event) -> None:
        n = event.data.get("phase", "?")
        name = event.data.get("name", "")
        self._recent_events.append(f"[P{n}] {name} iniciada")

    async def _on_phase_done(self, event) -> None:
        n = event.data.get("phase", "?")
        f = event.data.get("findings", 0)
        self._recent_events.append(f"[P{n}] Completada — {f} findings")
        if len(self._recent_events) > 50:
            self._recent_events.pop(0)

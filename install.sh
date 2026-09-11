#!/usr/bin/env bash
# BLACK LEVIATAN v29 — Installer robusto
# Autor: Luis Sánchez
# Target: Parrot Security / Kali Linux aarch64 + x86_64

set -euo pipefail

# Directorio raíz del proyecto (absoluto, no cambia con cd)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MAUVE='\033[38;2;203;166;247m'
GREEN='\033[38;2;166;227;161m'
RED='\033[38;2;243;139;168m'
BLUE='\033[38;2;137;180;250m'
YELLOW='\033[38;2;249;226;175m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✓ $*${NC}"; }
info() { echo -e "${BLUE}▶ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }
fail() { echo -e "${RED}✗ $*${NC}"; exit 1; }

SKIP_RUST=false
DEV_MODE=false
for arg in "$@"; do
  case $arg in
    --no-rust) SKIP_RUST=true ;;
    --dev)     DEV_MODE=true  ;;
    --help|-h) echo "Uso: $0 [--no-rust] [--dev]"; exit 0 ;;
  esac
done

echo -e ""
echo -e "${MAUVE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAUVE}║   🦑  BLACK LEVIATAN v29 — Installer                    ║${NC}"
echo -e "${MAUVE}║   Creado por: Luis Sánchez                               ║${NC}"
echo -e "${MAUVE}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

# ── Detectar Python ──────────────────────────────────────────────────────────
PYTHON=""
for py in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$py" &>/dev/null; then
    PYVER=$("$py" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYMAJ=$(echo "$PYVER" | cut -d. -f1)
    PYMIN=$(echo "$PYVER" | cut -d. -f2)
    if [ "$PYMAJ" -ge 3 ] && [ "$PYMIN" -ge 10 ]; then
      PYTHON="$py"
      break
    fi
  fi
done
[ -z "$PYTHON" ] && fail "Python 3.10+ requerido. Instala con: sudo apt install python3.11"
ok "Python: $($PYTHON --version)"

# ── Crear .venv ───────────────────────────────────────────────────────────────
VENV=".venv"
if [ ! -d "$VENV" ]; then
  info "Creando entorno virtual (.venv)..."
  "$PYTHON" -m venv "$VENV" || fail "No se pudo crear .venv"
fi
ok "Entorno virtual: $VENV"

# Paths absolutos — no se rompen con cd dentro de subshells
PIP="$PROJECT_ROOT/$VENV/bin/pip"
PY="$PROJECT_ROOT/$VENV/bin/python"

# ── pip ───────────────────────────────────────────────────────────────────────
info "Actualizando pip..."
"$PIP" install --quiet --upgrade pip wheel setuptools

# ── Dependencias Python ───────────────────────────────────────────────────────
info "Instalando dependencias Python..."
if "$PIP" install --quiet -r requirements.txt; then
  ok "Dependencias Python instaladas"
else
  fail "Error instalando requirements.txt"
fi

# ── Playwright (opcional) ─────────────────────────────────────────────────────
info "Instalando Playwright Chromium..."
if "$PY" -m playwright install chromium --quiet 2>/dev/null; then
  ok "Playwright Chromium instalado"
else
  warn "Playwright sin browsers — K1 usará aiohttp como fallback"
fi

# ── Kernels Rust ─────────────────────────────────────────────────────────────
if [ "$SKIP_RUST" = false ]; then
  # Verificar cargo
  if ! command -v cargo &>/dev/null; then
    warn "Rust/cargo no encontrado — intentando instalar via rustup..."
    if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet; then
      # shellcheck disable=SC1090
      source "$HOME/.cargo/env"
    else
      warn "No se pudo instalar Rust. Continuando sin kernels Rust."
      SKIP_RUST=true
    fi
  fi
fi

if [ "$SKIP_RUST" = false ]; then
  ok "Rust: $(cargo --version)"

  # Verificar que maturin existe en el venv (no en PATH del sistema)
  if ! "$PIP" show maturin &>/dev/null; then
    info "Instalando maturin en .venv..."
    "$PIP" install --quiet maturin || fail "No se pudo instalar maturin"
  fi
  MATURIN="$PROJECT_ROOT/$VENV/bin/maturin"
  [ -x "$MATURIN" ] || fail "maturin no encontrado en $MATURIN"
  ok "maturin: $($MATURIN --version)"

  # K1 — bl_crawler
  K1_DIR="$PROJECT_ROOT/kernels/k1_stealth_crawler/rust_core"
  if [ -d "$K1_DIR" ]; then
    info "Compilando K1 bl_crawler (aarch64/x86_64)..."
    if (cd "$K1_DIR" && "$MATURIN" develop --release 2>&1); then
      ok "K1 bl_crawler compilado y enlazado"
    else
      warn "K1 bl_crawler falló — K1 usará fallback Python puro"
    fi
  else
    warn "Directorio K1 no encontrado — K1 sin Rust"
  fi

  # K5 — bl_intel
  K5_DIR="$PROJECT_ROOT/kernels/k5_autonomous_intel/rust_core"
  if [ -d "$K5_DIR" ]; then
    info "Compilando K5 bl_intel (aarch64/x86_64)..."
    if (cd "$K5_DIR" && "$MATURIN" develop --release 2>&1); then
      ok "K5 bl_intel compilado y enlazado"
    else
      warn "K5 bl_intel falló — K5 usará heurísticas Python"
    fi
  else
    warn "Directorio K5 no encontrado — K5 sin Rust"
  fi
else
  warn "Kernels Rust omitidos (--no-rust o Rust no disponible)"
fi

# ── Directorios de trabajo ────────────────────────────────────────────────────
mkdir -p "$PROJECT_ROOT/data" "$PROJECT_ROOT/reports" "$PROJECT_ROOT/logs"
ok "Directorios: data/ reports/ logs/"

# ── .env ─────────────────────────────────────────────────────────────────────
if [ ! -f "$PROJECT_ROOT/.env" ] && [ -f "$PROJECT_ROOT/.env.example" ]; then
  cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
  sed -i -E '/^[A-Z_]+=\s*$/ s/^/#/' "$PROJECT_ROOT/.env"
  ok ".env creado (configura tus API keys antes de correr scans)"
elif [ -f "$PROJECT_ROOT/.env" ]; then
  ok ".env ya existe"
fi

# ── Fish alias (opcional) ─────────────────────────────────────────────────────
if command -v fish &>/dev/null; then
  FISH_CONF="$HOME/.config/fish/conf.d"
  mkdir -p "$FISH_CONF"
  cat > "$FISH_CONF/bl_alias.fish" << FISHEOF
# BLACK LEVIATAN v29
function bl
    $PROJECT_ROOT/.venv/bin/python $PROJECT_ROOT/black_leviathan.py \$argv
end
FISHEOF
  ok "Fish: alias 'bl' configurado en $FISH_CONF/bl_alias.fish"
fi

# ── Verificación final ────────────────────────────────────────────────────────
info "Verificando que el entry point arranca..."
if "$PY" "$PROJECT_ROOT/black_leviathan.py" --help > /dev/null 2>&1; then
  ok "black_leviathan.py --help OK"
else
  warn "black_leviathan.py --help falló — corre manualmente para ver el traceback"
fi

echo -e ""
echo -e "${MAUVE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAUVE}║   ✅  BLACK LEVIATAN v29 listo                          ║${NC}"
echo -e "${MAUVE}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${MAUVE}║   Uso:                                                   ║${NC}"
echo -e "${MAUVE}║   .venv/bin/python black_leviathan.py -t example.com    ║${NC}"
echo -e "${MAUVE}║   .venv/bin/python black_leviathan.py --list-modules    ║${NC}"
echo -e "${MAUVE}║   .venv/bin/python black_leviathan.py --validate-config ║${NC}"
echo -e "${MAUVE}║   (fish) bl -t example.com                              ║${NC}"
echo -e "${MAUVE}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e ""

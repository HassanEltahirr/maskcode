#!/bin/bash
# MaskCode one-click installer and launcher for macOS (and Linux).
# Double-click in Finder. The first run installs MaskCode for your user account;
# later runs open the app straight away.
cd "$(dirname "$0")" || exit 1
VENV="$HOME/.maskcode/venv"
unset PYTHONPATH PYTHONHOME
if [ ! -x "$VENV/bin/maskcode" ]; then
  echo "Setting up MaskCode for the first time..."
  if ! command -v python3 >/dev/null || ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
    echo "MaskCode needs Python 3.10 or newer. Opening the download page..."
    open "https://www.python.org/downloads/macos/" 2>/dev/null || xdg-open "https://www.python.org/downloads/" 2>/dev/null
    read -r -p "Install Python, then press Enter to close." _
    exit 1
  fi
  python3 -m venv "$VENV" && "$VENV/bin/python" -m pip install -q --disable-pip-version-check --upgrade pip \
    && "$VENV/bin/python" -m pip install -q --disable-pip-version-check . \
    || { echo "Setup did not finish. Check your internet connection and try again."; read -r _; exit 1; }
  echo "Done."
fi
echo "Opening MaskCode in your browser. Keep this window open while you use it."
exec "$VENV/bin/maskcode" app

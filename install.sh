#!/usr/bin/env bash
# Installs a "cybersec-intel" launcher in ~/.local/bin that runs intel.py from this folder.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin"
LAUNCHER="$BIN/cybersec-intel"

command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }

if [ ! -f "$HERE/.env" ]; then
    (umask 077 && cp "$HERE/.env.example" "$HERE/.env")
    echo "created .env from .env.example - add your API keys to it"
fi
chmod 600 "$HERE/.env"

mkdir -p "$BIN"
printf '#!/usr/bin/env bash\nexec python3 %q "$@"\n' "$HERE/intel.py" > "$LAUNCHER"
chmod 755 "$LAUNCHER"
echo "installed: $LAUNCHER"

case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "note: $BIN is not in your PATH - add it to use the 'cybersec-intel' command" ;;
esac

for tool in searchsploit msfconsole nuclei; do
    command -v "$tool" >/dev/null || echo "optional: $tool not found (local exploit search will skip it)"
done
echo "done. run: cybersec-intel"

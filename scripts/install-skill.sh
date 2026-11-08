#!/usr/bin/env bash

set -euo pipefail

SKILL_DIR="$(pwd)/skills/mail-triage"
TARGET="$HOME/.config/opencode/skills/mail-triage"

if [[ ! -f "$SKILL_DIR/SKILL.md" ]]; then
  echo "No se encontró $SKILL_DIR/SKILL.md; ejecuta este script desde la raíz del repo." >&2
  exit 1
fi

mkdir -p "$(dirname "$TARGET")"
ln -sfn "$SKILL_DIR" "$TARGET"
echo "Skill enlazada en $TARGET"

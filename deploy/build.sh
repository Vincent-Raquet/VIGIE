#!/bin/sh
# Construit le wheel versionné et la liste figée des dépendances (avec empreintes) dans dist/.
set -eu
cd "$(dirname "$0")/.."
rm -rf dist
uv build --wheel --out-dir dist
uv export --frozen --no-dev --no-emit-project --format requirements-txt -o dist/requirements.txt
version=$(uv run python -c "import vigie; print(vigie.__version__)")
commit=$(git rev-parse --short HEAD)
dirty=$(git diff --quiet && git diff --cached --quiet || echo "-modifie")
printf '%s-%s%s\n' "$version" "$commit" "$dirty" > dist/release.txt
echo "Version prête : $(cat dist/release.txt)"

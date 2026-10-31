#!/usr/bin/env bash
#
# Fetch a small corpus of real, unmaintained open-source repositories to run
# the scanner against. These are external, untrusted repositories: they are
# only ever STATICALLY ANALYZED (parsed), never installed or executed. Do not
# run `pip install`, `npm install`, or any build/test step from inside them.
#
# Each repo is shallow-cloned into its own subdirectory of test-corpus/, which
# is gitignored and not part of this project.
#
# Usage:  scripts/fetch_test_corpus.sh
# Then:   ./.venv/bin/vscan scan test-corpus/<repo-name>

set -u

DEST="test-corpus"
mkdir -p "$DEST"

# name<TAB>clone-url  (stale 2021-2023 repos with real pinned manifests)
REPOS=(
  "flask_weather|https://github.com/M0nica/flask_weather"
  "flask-mxnet-img-classifier|https://github.com/XD-DENG/flask-app-for-mxnet-img-classifier"
  "django-rest-framework-jwt|https://github.com/jpadilla/django-rest-framework-jwt"
  "express-api-es6-starter|https://github.com/mesaugat/express-api-es6-starter"
  "base-express-api|https://github.com/dbuarque/base-express-api"
  # one large project (scale/throughput test): Flask backend + JS frontend, many pinned deps
  "redash|https://github.com/getredash/redash"
)

for entry in "${REPOS[@]}"; do
  name="${entry%%|*}"
  url="${entry##*|}"
  target="$DEST/$name"
  if [ -d "$target" ]; then
    echo "skip   $name (already present)"
    continue
  fi
  echo "clone  $name  <- $url"
  git clone --depth 1 --no-tags --quiet "$url" "$target" \
    && echo "   ok  $name" \
    || echo "  FAIL $name"
done

echo
echo "Corpus ready under $DEST/ :"
ls -1 "$DEST"

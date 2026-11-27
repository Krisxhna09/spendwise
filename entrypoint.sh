#!/bin/sh
set -e

if [ "$(id -u)" = "0" ]; then
  TARGET_DIR="${DATA_DIR:-${RAILWAY_VOLUME_MOUNT_PATH:-}}"
  if [ -n "$TARGET_DIR" ]; then
    mkdir -p "$TARGET_DIR"
    chown -R node:node "$TARGET_DIR"
  fi

  if [ -n "${DB_PATH:-}" ] && [ "$DB_PATH" != ":memory:" ]; then
    DB_DIR="$(dirname "$DB_PATH")"
    mkdir -p "$DB_DIR"
    chown -R node:node "$DB_DIR"
  fi

  exec su-exec node "$@"
fi

exec "$@"

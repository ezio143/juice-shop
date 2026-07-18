"""
fetch_secret.py

Demonstrates the pattern an application should use instead of hardcoded
secrets in .env / docker-compose.yml: authenticate to Vault, retrieve a
secret at runtime, use it in memory only.

This is what a real app's startup code would do — pull credentials from
Vault right before they're needed, rather than having them committed
anywhere or baked into an image.

Usage:
    export VAULT_ADDR=http://127.0.0.1:8200
    export VAULT_TOKEN=root   # dev-mode root token
    python fetch_secret.py --path secret/juice-shop --key SNYK_TOKEN
"""

import argparse
import os
import sys

import requests


def fetch_secret(vault_addr: str, vault_token: str, path: str, key: str) -> str:
    # KV v2 secrets engine requires "data/" inserted into the API path
    # even though it's not part of the CLI path you type with `vault kv get`.
    api_path = path.replace("secret/", "secret/data/", 1)
    url = f"{vault_addr}/v1/{api_path}"
    headers = {"X-Vault-Token": vault_token}

    resp = requests.get(url, headers=headers, timeout=10)

    if resp.status_code == 403:
        print("Error: Vault token invalid or lacks permission for this path.", file=sys.stderr)
        sys.exit(1)
    if resp.status_code == 404:
        print(f"Error: no secret found at path '{path}'.", file=sys.stderr)
        sys.exit(1)
    resp.raise_for_status()

    data = resp.json()["data"]["data"]  # KV v2 nests the actual secret under data.data

    if key not in data:
        print(f"Error: key '{key}' not found at '{path}'. Available keys: {list(data.keys())}", file=sys.stderr)
        sys.exit(1)

    return data[key]


def main():
    parser = argparse.ArgumentParser(description="Fetch a secret from Vault programmatically")
    parser.add_argument("--path", required=True, help="Vault KV path, e.g. secret/juice-shop")
    parser.add_argument("--key", required=True, help="Key within the secret to retrieve")
    args = parser.parse_args()

    vault_addr = os.environ.get("VAULT_ADDR")
    vault_token = os.environ.get("VAULT_TOKEN")

    if not vault_addr or not vault_token:
        print("Error: set VAULT_ADDR and VAULT_TOKEN environment variables first.", file=sys.stderr)
        sys.exit(1)

    secret_value = fetch_secret(vault_addr, vault_token, args.path, args.key)

    # In a real app, this value would be used directly in memory (e.g. passed
    # to an API client), never printed or written to disk. We mask it here
    # only to prove retrieval worked without exposing the real value in logs.
    masked = secret_value[:4] + "*" * max(len(secret_value) - 4, 0)
    print(f"Retrieved '{args.key}' from '{args.path}': {masked}")
    print("(In a real app, this value is held in memory only — never logged or written to disk.)")


if __name__ == "__main__":
    main()
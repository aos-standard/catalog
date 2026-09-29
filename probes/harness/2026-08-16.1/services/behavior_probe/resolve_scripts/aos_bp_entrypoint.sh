#!/bin/sh
# Behavior-probe run ENTRYPOINT: point resolv to local recorder, then exec strace.
# Recorder runs outside strace (not a child of the traced server).
# Positive control: one A query for aos-bp-selftest.invalid before the server starts.
# strace -ttt = epoch seconds (compare with host time.time(); no TZ env).
set -eu

printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf

: > /tmp/dns_queries.log
python3 /usr/local/lib/aos-bp/dns_recorder.py >/tmp/dns_recorder.out 2>/tmp/dns_recorder.err &
# Brief settle so bind(53) wins the race before the selftest / server starts.
sleep 0.05

# Selftest must land in the log; host treats missing entry as dns_recorder_not_recording.
python3 /usr/local/lib/aos-bp/dns_recorder.py --send-selftest >/tmp/dns_selftest.out 2>/tmp/dns_selftest.err || true
sleep 0.05
# Log lines are "<epoch> <name> <qtype>" (epoch added 2026-09-15); match name anywhere.
if grep -qE '(^|[[:space:]])aos-bp-selftest\.invalid[[:space:]]' /tmp/dns_queries.log 2>/dev/null; then
  printf 'ok\n' > /tmp/dns_recorder_selftest.status
else
  printf 'dns_recorder_not_recording\n' > /tmp/dns_recorder_selftest.status
fi

exec strace -f -ttt -e "trace=network,execve,openat,unlink,rename" -o /tmp/strace.log "$@"

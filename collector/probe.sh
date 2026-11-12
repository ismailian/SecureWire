# SecureWire probe (protocol §4). POSIX sh, sent on stdin of:  exec sh -s
# Prints key=value lines, one per capability, then exits. Read-only; installs nothing.

has() { command -v "$1" >/dev/null 2>&1 && echo 1 || echo 0; }

echo "uid=$(id -u 2>/dev/null)"
echo "user=$(id -un 2>/dev/null)"
if command -v bash >/dev/null 2>&1; then
    echo "bash=$(bash -c 'echo $BASH_VERSION' 2>/dev/null)"
else
    echo "bash="
fi
echo "sudo=$(has sudo)"
if command -v sudo >/dev/null 2>&1 && sudo -n true </dev/null >/dev/null 2>&1; then
    echo "sudo_n=1"
else
    echo "sudo_n=0"
fi
echo "systemd=$(has systemctl)"
if command -v journalctl >/dev/null 2>&1 && journalctl -n 0 -q </dev/null >/dev/null 2>&1; then
    echo "journal_read=1"
else
    echo "journal_read=0"
fi
for t in ufw nft iptables fail2ban-client ss docker; do
    echo "$t=$(has "$t")"
done
if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "os=${ID:-unknown}:${VERSION_ID:-}"
fi
echo "probe=done"

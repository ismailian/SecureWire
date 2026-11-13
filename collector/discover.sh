# SecureWire log discovery (protocol §6). Read-only.
# Sent on stdin of:  exec bash -s securewire-discover <priv>
# priv: none | root | nopasswd | password (password = first stdin line after this script).
# Output: "unit <name> <description>" and "file <path> <r|sudo>" lines.
# Test hook: SW_LOG_ROOT (default /var/log).

discover() {
    local priv=${2:-none} root=${SW_LOG_ROOT:-/var/log} pw= f
    PATH=$PATH:/usr/sbin:/sbin
    if [[ $priv == password ]]; then
        IFS= read -r pw || exit 0
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=running --no-legend --plain --no-pager 2>/dev/null |
            while read -r unit _ _ _ desc; do echo "unit $unit $desc"; done
    fi
    # Root can see into 0750 log directories (mysql, nginx on some distros).
    local -a find_args=("$root" -maxdepth 3 -type f "(" -name "*.log" -o -name syslog -o -name messages -o -name secure -o -name kern.log ")" -size +0)
    {
        case $priv in
            root) find "${find_args[@]}" ;;
            nopasswd) sudo -n -- find "${find_args[@]}" ;;
            password) printf "%s\n" "$pw" | sudo -S -p "" -- find "${find_args[@]}" ;;
            *) find "${find_args[@]}" ;;
        esac
    } 2>/dev/null | head -n 300 | while IFS= read -r f; do
        # Skip paths that need quoting tricks; tail gets them quoted anyway, but keep the list sane.
        [[ $f == *[[:space:]]* ]] && continue
        if [[ -r $f ]]; then echo "file $f r"; else echo "file $f sudo"; fi
    done
}

discover "$@"

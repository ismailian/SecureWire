# SecureWire directory listing (protocol §15). POSIX sh, sent on stdin of:
#   LC_ALL=C exec sh -s -- <dir>        (no argument = the login user's home)
# Output fields are NUL-terminated: "P" <resolved path>, then 8 fields per entry
# (%y%Y size mtime mode user group name link-target), or "E" <noent|notdir|perm>.
# Read-only; installs nothing.

d=${1:-$HOME}
if ! cd -- "$d" 2>/dev/null; then
    if [ ! -e "$d" ]; then e=noent; elif [ ! -d "$d" ]; then e=notdir; else e=perm; fi
    printf 'E\000%s\000' "$e"
    exit 0
fi
printf 'P\000%s\000' "$(pwd -P)"
if find . -maxdepth 0 -printf '' >/dev/null 2>&1; then
    # GNU find: one process for the whole directory.
    find . -mindepth 1 -maxdepth 1 -printf '%y%Y\0%s\0%T@\0%m\0%u\0%g\0%f\0%l\0' 2>/dev/null
else
    # BusyBox / BSD: one stat per entry.
    for f in .* *; do
        case $f in .|..) continue ;; esac
        [ -e "$f" ] || [ -L "$f" ] || continue
        l=
        if [ -L "$f" ]; then
            t=l; l=$(readlink -- "$f" 2>/dev/null)
            if [ -d "$f" ]; then y=d; else y=f; fi
        elif [ -d "$f" ]; then t=d; y=d
        elif [ -f "$f" ]; then t=f; y=f
        else t=o; y=o
        fi
        s=$(stat -c '%s %Y %a %U %G' -- "$f" 2>/dev/null) || s='0 0 0 - -'
        set -f  # the list above is already expanded
        # shellcheck disable=SC2086
        set -- $s
        printf '%s%s\000%s\000%s\000%s\000%s\000%s\000%s\000%s\000' "$t" "$y" "$1" "$2" "$3" "$4" "$5" "$f" "$l"
    done
fi

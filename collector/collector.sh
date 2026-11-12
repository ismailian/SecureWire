# SecureWire collector, protocol v1 (design/collector-protocol.md).
#
# Sent over SSH on the stdin of:   exec bash -s securewire-collector <fast> <medium> <slow>
# bash reads this script from stdin one command at a time, so every line the
# client writes AFTER the final "main" line arrives in main as a control command.
# Rules for this file:
#   * everything is a function; the LAST line is the call to main
#   * the fast tier (cpu, mem, net, dio) uses builtins only: no fork every tick
#   * no secrets ever appear in argv or the environment
#   * test hooks: SW_PROC (fake /proc root), SW_OS_RELEASE (fake os-release)

sw_init() {
    P=${SW_PROC:-/proc}
    OSREL=${SW_OS_RELEASE:-/etc/os-release}
    printf -v RS "\036"
    printf -v NL "\n"
    F=${2:-2}
    M=${3:-10}
    S=${4:-60}
    seq=0
    SVC=()
    SECTIONS=(cpu mem net dio df who ps svc)
    declare -gA ON PREV DUE TIER KNOWN
    local s
    for s in static "${SECTIONS[@]}"; do KNOWN[$s]=1; ON[$s]=1; DUE[$s]=0; done
    for s in cpu mem net dio; do TIER[$s]=fast; done
    for s in df who ps svc; do TIER[$s]=medium; done
    TIER[static]=never
}

# frame <section> <payload> <dedupe 0|1>
frame() {
    seq=$((seq + 1))
    if [[ $3 == 1 && ${PREV[$1]+set} == set && ${PREV[$1]} == "$2" ]]; then
        printf "%sSAME %s %d\n" "$RS" "$1" "$seq"
        return
    fi
    PREV[$1]=$2
    printf "%sSW1 %s %d\n%s\n%sEND %s %d\n" "$RS" "$1" "$seq" "$2" "$RS" "$1" "$seq"
}

missing() {
    seq=$((seq + 1))
    printf "%sERR %s %d %s\n" "$RS" "$1" "$seq" "${2:-missing}"
    ON[$1]=0
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------- fast tier: builtins only ----------

s_cpu() {
    local l o
    read -r l < "$P/uptime" || { missing cpu unreadable; return; }
    o="uptime $l"
    while IFS= read -r l; do
        case $l in cpu* | ctxt* | procs_running*) o+=$NL$l ;; esac
    done < "$P/stat"
    read -r l < "$P/loadavg"
    o+="${NL}loadavg $l"
    frame cpu "$o" 0
}

s_mem() {
    local l o=
    while IFS= read -r l; do
        case $l in
            MemTotal:* | MemFree:* | MemAvailable:* | Buffers:* | Cached:* | Shmem:* | SReclaimable:* | SwapTotal:* | SwapFree:*)
                o+=$l$NL ;;
        esac
    done < "$P/meminfo" || { missing mem unreadable; return; }
    frame mem "${o%"$NL"}" 0
}

s_net() {
    [[ -r $P/net/dev ]] || { missing net; return; }
    local l o=
    while IFS= read -r l; do o+=$l$NL; done < "$P/net/dev"
    frame net "${o%"$NL"}" 0
}

s_dio() {
    [[ -r $P/diskstats ]] || { missing dio; return; }
    local l o=
    while IFS= read -r l; do
        case $l in *" loop"* | *" ram"* | *" zram"*) ;; *) o+=$l$NL ;; esac
    done < "$P/diskstats"
    frame dio "${o%"$NL"}" 0
}

# ---------- medium tier: one or two forks each ----------

s_df() {
    have df || { missing df; return; }
    frame df "$(df -P -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null)" 1
}

s_who() {
    have who || { missing who; return; }
    frame who "$(who -u 2>/dev/null)" 1
}

s_ps() {
    have ps || { missing ps; return; }
    frame ps "$(ps -eo pid,user,pcpu,rss,etimes,args --sort=-pcpu --no-headers 2>/dev/null | head -n 25)" 1
}

s_svc() {
    ((${#SVC[@]})) || return
    have systemctl || { missing svc; return; }
    frame svc "$(systemctl show -p Id,ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec,TasksCurrent,NRestarts,Result,ActiveEnterTimestampMonotonic,InactiveEnterTimestampMonotonic -- "${SVC[@]}" 2>&1)" 1
}

# ---------- once ----------

s_static() {
    local l o host=unknown kernel= pretty= cpus=0 memk=0 arch virt=none
    [[ -r $P/sys/kernel/hostname ]] && read -r host < "$P/sys/kernel/hostname"
    [[ -r $P/sys/kernel/osrelease ]] && read -r kernel < "$P/sys/kernel/osrelease"
    if [[ -r $OSREL ]]; then
        while IFS= read -r l; do
            case $l in PRETTY_NAME=*) pretty=${l#PRETTY_NAME=} ;; esac
        done < "$OSREL"
    fi
    while IFS= read -r l; do
        case $l in cpu[0-9]*) cpus=$((cpus + 1)) ;; esac
    done < "$P/stat"
    while IFS= read -r l; do
        case $l in MemTotal:*) l=${l#MemTotal:}; l=${l% kB}; memk=${l// /} ;; esac
    done < "$P/meminfo"
    arch=$(uname -m 2>/dev/null)
    have systemd-detect-virt && virt=$(systemd-detect-virt 2>/dev/null)
    o="hostname=$host${NL}os=${pretty//\"/}${NL}kernel=$kernel${NL}arch=$arch${NL}cpus=$cpus${NL}virt=${virt:-none}${NL}mem_total_kib=$memk"
    frame static "$o" 0
}

# ---------- control ----------

handle() {
    # Parameter expansion only: here-strings may create temp files on older bash.
    local cmd a b rest
    cmd=${1%% *}
    rest=${1#"$cmd"}
    rest=${rest# }
    a=${rest%% *}
    b=${rest#"$a"}
    b=${b# }
    case $cmd in
        TIER)
            [[ $b =~ ^[0-9]+$ ]] || return
            case $a in fast) F=$b ;; medium) M=$b ;; slow) S=$b ;; esac
            ;;
        ON) [[ ${KNOWN[$a]} == 1 ]] && { ON[$a]=1; DUE[$a]=0; } ;;
        OFF) [[ ${KNOWN[$a]} == 1 ]] && ON[$a]=0 ;;
        NOW) [[ ${KNOWN[$a]} == 1 ]] && "s_$a" ;;
        SVC)
            local u ok=() words
            set -f # no glob expansion of unit names
            words=($rest)
            set +f
            for u in "${words[@]}"; do [[ $u =~ ^[A-Za-z0-9@._:-]+$ && $u != -* ]] && ok+=("$u"); done
            SVC=("${ok[@]}")
            unset "PREV[svc]"
            s_svc
            ;;
        PING) [[ $a =~ ^[0-9]+$ ]] && printf "%sPONG %s\n" "$RS" "$a" ;;
        QUIT) exit 0 ;;
    esac
}

interval() {
    case ${TIER[$1]} in
        fast) IV=$F ;;
        medium) IV=$M ;;
        slow) IV=$S ;;
        *) IV=0 ;;
    esac
}

main() {
    sw_init "$@"
    printf "%sHELLO 1 %s\n" "$RS" "$BASH_VERSION"
    s_static
    local s now next wait line rc
    while :; do
        now=$SECONDS
        next=$((now + 3600))
        for s in "${SECTIONS[@]}"; do
            ((ON[$s])) || continue
            interval "$s"
            ((IV > 0)) || continue
            if ((DUE[$s] <= now)); then
                "s_$s"
                DUE[$s]=$((now + IV))
            fi
            ((DUE[$s] < next)) && next=${DUE[$s]}
        done
        wait=$((next - SECONDS))
        ((wait < 1)) && wait=1
        if IFS= read -r -t "$wait" line; then
            handle "$line"
        else
            rc=$?
            # > 128: timeout (next tick). Anything else: EOF, the client is gone.
            ((rc > 128)) || exit 0
        fi
    done
}

main "$@"

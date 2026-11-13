#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: sh run.sh /path/to/compiled-lab /path/to/bwrap" >&2
    echo "       sh run.sh /path/to/interpreter /path/to/bwrap script" >&2
    exit 2
fi
binary=$(realpath "$1")
bwrap=$(realpath "$2")
script=
if [ "$#" -eq 3 ]; then
    script=$(realpath "$3")
    test -r "$script"
fi
test -x "$binary"
test -x "$bwrap"
test "$(id -u)" -ne 0

printf 'runner uid=%s kernel=%s arch=%s\n' "$(id -u)" "$(uname -r)" "$(uname -m)"
"$bwrap" --version

# Keep the receivers and the unsandboxed controls on a private link with no uplink.
exec timeout 30s unshare --user --map-root-user --net sh -eu -c '
    ip link set lo up
    ip link add lab0 type veth peer name lab1
    ip link set lab0 up
    ip link set lab1 up
    ip addr add 10.253.0.1/32 dev lab0
    test -z "$(ip -4 route show default)"
    test -z "$(ip -6 route show default)"
    ip -br -4 addr
    printf "lab default_routes=none\n"
    if [ -n "$3" ]; then
        exec "$1" "$3" run "$2" 10.253.0.1
    fi
    exec "$1" run "$2" 10.253.0.1
' lab "$binary" "$bwrap" "$script"

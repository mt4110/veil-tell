# DNS observation in isolation

Run `python3 experiments/dns-attempts/probe.py` as a normal user. The host UDP
socket acts as a stand-in for an external DNS receiver. No public resolver is
contacted. Linux uses a new bubblewrap network namespace. macOS uses a Seatbelt
profile with networking and named Mach services denied.

On Ubuntu 26.04.1 with Ubuntu bubblewrap 0.11.1 and the packaged AppArmor profile,
the namespace-local high-port sink recorded `probe.test` and returned NXDOMAIN.
The host receiver recorded one control packet and zero isolated packets. Binding
UDP 53 failed with EACCES. The packaged `unpriv_bwrap` profile denies capabilities
after exec, including when the child is offered CAP_NET_BIND_SERVICE. A high
port does not let standard resolvers that use port 53 reach this sink.

On macOS 27.2, the host receiver recorded one control packet and zero isolated
packets. A host-loopback DNS service would require another Seatbelt exception.
The system resolver uses mDNSResponder. Opening its IPC would change the existing
isolation boundary, so the experiment keeps it denied.

2026-11-20: Linux aarch64, Debian kernel 6.12.95+deb13-cloud-arm64, uid 501.
Inside non-setuid bubblewrap with separate PID, user and network namespaces,
the notify probe installed NEW_LISTENER and an ancestor read 16 sockaddr bytes
for 192.0.2.1:443. The child received ENETUNREACH. The probe reads socket
addresses only. DNS question decoding (stage B) was not evaluated by this probe.

Stage A in the CLI recorded Python's direct TCP attempt and two 127.0.0.1:53
attempts from curl using the system resolver. A DNS socket connect carries no
question name. Returning ENETUNREACH at that point prevents later transmission
of the question. Stage B would need another observation point for that path.

The Debian VM used ptrace_scope=0. Compatibility with ptrace_scope=1 has not
been established by that measurement. If ancestor reads are denied by kernel
policy, the CLI leaves direct coverage unobserved and retains network isolation.

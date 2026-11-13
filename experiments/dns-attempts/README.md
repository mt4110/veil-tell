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

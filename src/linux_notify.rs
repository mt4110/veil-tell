// Runs outside the target's seccomp filter, inside the same private namespaces.
// The original namespace and syscall restrictions still apply to every continued call.
use crate::report::DirectAttempt;
use std::{
    collections::BTreeMap,
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{Arc, Mutex},
};
use tokio::process::{Child, Command};

#[derive(Default)]
struct Counts {
    rows: BTreeMap<SocketAddr, u64>,
    total: u64,
    incomplete: bool,
    unavailable: bool,
}
#[derive(Default, Clone)]
pub(super) struct Capture(Arc<Mutex<Counts>>);

impl Capture {
    pub fn snapshot(&self) -> Option<(bool, Vec<DirectAttempt>)> {
        let s = self.0.lock().unwrap();
        if s.unavailable {
            return None;
        }
        Some((
            s.incomplete,
            s.rows
                .iter()
                .map(|(a, n)| DirectAttempt {
                    ip: a.ip(),
                    port: a.port(),
                    attempts: *n,
                })
                .collect(),
        ))
    }
}

fn listener() -> io::Result<OwnedFd> {
    let op = super::instruction;
    let mut code = vec![op(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0)];
    for syscall in [libc::SYS_connect, libc::SYS_sendto, libc::SYS_sendmsg] {
        code.push(op(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            0,
            1,
            syscall as u32,
        ));
        code.push(op(
            libc::BPF_RET | libc::BPF_K,
            0,
            0,
            libc::SECCOMP_RET_USER_NOTIF,
        ));
    }
    code.push(op(
        libc::BPF_RET | libc::BPF_K,
        0,
        0,
        libc::SECCOMP_RET_ALLOW,
    ));
    let prog = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn read(pid: u32, addr: u64, bytes: &mut [u8]) -> io::Result<()> {
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as usize as *mut _,
        iov_len: bytes.len(),
    };
    let count = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
    if count < 0 {
        Err(io::Error::last_os_error())
    } else if count != bytes.len() as isize {
        Err(io::Error::from(io::ErrorKind::UnexpectedEof))
    } else {
        Ok(())
    }
}

fn address(n: &libc::seccomp_notif) -> io::Result<Option<SocketAddr>> {
    let args = n.data.args;
    let (ptr, len) = match n.data.nr as libc::c_long {
        libc::SYS_connect => (args[1], args[2]),
        libc::SYS_sendto => (args[4], args[5]),
        libc::SYS_sendmsg => {
            // On both supported 64-bit ABIs msg_name and msg_namelen are first.
            let mut header = [0; 12];
            read(n.pid, args[1], &mut header)?;
            (
                u64::from_ne_bytes(header[..8].try_into().unwrap()),
                u32::from_ne_bytes(header[8..].try_into().unwrap()) as u64,
            )
        }
        _ => return Ok(None),
    };
    if ptr == 0 || len < 2 {
        return Ok(None);
    }
    let mut sockaddr = [0; 28];
    let size = len.min(28) as usize;
    read(n.pid, ptr, &mut sockaddr[..size])?;
    let port = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
    let ip = match u16::from_ne_bytes([sockaddr[0], sockaddr[1]]) as i32 {
        libc::AF_INET if size >= 16 => IpAddr::V4(Ipv4Addr::new(
            sockaddr[4],
            sockaddr[5],
            sockaddr[6],
            sockaddr[7],
        )),
        libc::AF_INET6 if size >= 28 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&sockaddr[8..24]).unwrap(),
        )),
        _ => return Ok(None),
    };
    Ok(Some(SocketAddr::new(ip, port)))
}

fn monitor(fd: OwnedFd, capture: Capture) {
    let fd = fd.as_raw_fd();
    loop {
        let mut n: libc::seccomp_notif = unsafe { mem::zeroed() };
        if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_RECV, &mut n) } < 0 {
            if matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::ENOENT)
            ) {
                continue;
            }
            capture.0.lock().unwrap().incomplete = true;
            break;
        }
        if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &n.id) } < 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
        {
            continue;
        }
        let addr = address(&n);
        let denied = matches!(addr, Ok(Some(a)) if !a.ip().is_loopback() || a.port()==53);
        let mut reply = libc::seccomp_notif_resp {
            id: n.id,
            val: 0,
            error: if denied { -libc::ENETUNREACH } else { 0 },
            flags: if denied {
                0
            } else {
                libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32
            },
        };
        let mut c = capture.0.lock().unwrap();
        if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_SEND, &mut reply) } < 0 {
            if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                c.incomplete = true;
                break;
            }
        } else if let Err(err) = &addr {
            if matches!(
                err.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOSYS)
            ) {
                c.unavailable = true;
            } else {
                c.incomplete = true;
            }
        } else if let Ok(Some(a)) = addr
            && denied
        {
            if c.total >= 16384 || (c.rows.len() >= 1024 && !c.rows.contains_key(&a)) {
                c.incomplete = true
            } else {
                c.total += 1;
                *c.rows.entry(a).or_default() += 1;
            }
        }
    }
}

pub(super) fn spawn(mut command: Command) -> io::Result<(Child, Option<Capture>)> {
    let runtime = tokio::runtime::Handle::current();
    let (send, recv) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((fd, capture)) = recv.recv() {
            monitor(fd, capture);
        }
    });
    std::thread::spawn(move || {
        let _guard = runtime.enter();
        let capture = listener().ok().map(|fd| {
            let capture = Capture::default();
            send.send((fd, capture.clone())).expect("monitor waiting");
            capture
        });
        command.spawn().map(|child| (child, capture))
    })
    .join()
    .map_err(|_| io::Error::other("notification launcher stopped"))?
}

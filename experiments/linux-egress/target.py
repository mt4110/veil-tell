"""Experiment launcher. Apply target-only restrictions before exec."""

import ctypes as C
import errno
import os
import socket
import stat
import subprocess
import sys

SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO_EPERM = 0x00050000 | errno.EPERM
SCMP_CMP_EQ = 4


class ArgComparison(C.Structure):
    _fields_ = [
        ("arg", C.c_uint),
        ("op", C.c_int),
        ("datum_a", C.c_uint64),
        ("datum_b", C.c_uint64),
    ]


def require_ok(result):
    if result < 0:
        raise OSError(-result, os.strerror(-result))
    return result


def install_filter():
    lib = C.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [C.c_uint32]
    lib.seccomp_init.restype = C.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [C.c_char_p]
    lib.seccomp_rule_add_array.argtypes = [
        C.c_void_p, C.c_uint32, C.c_int, C.c_uint, C.POINTER(ArgComparison)
    ]
    lib.seccomp_load.argtypes = [C.c_void_p]
    lib.seccomp_release.argtypes = [C.c_void_p]
    lib.seccomp_release.restype = None

    context = lib.seccomp_init(SCMP_ACT_ALLOW)
    if not context:
        raise RuntimeError("seccomp_init failed")
    try:
        unix_socket = ArgComparison(0, SCMP_CMP_EQ, socket.AF_UNIX, 0)
        socket_syscall = require_ok(lib.seccomp_syscall_resolve_name(b"socket"))
        require_ok(lib.seccomp_rule_add_array(
            context, SCMP_ACT_ERRNO_EPERM, socket_syscall, 1, C.byref(unix_socket)
        ))
        # The relay stays outside this filter. The target keeps local socketpair().
        for name in (
            b"io_uring_setup", b"io_uring_enter", b"io_uring_register",
            b"ptrace", b"pidfd_getfd", b"process_vm_readv", b"process_vm_writev",
        ):
            syscall = require_ok(lib.seccomp_syscall_resolve_name(name))
            require_ok(lib.seccomp_rule_add_array(
                context, SCMP_ACT_ERRNO_EPERM, syscall, 0, None
            ))
        require_ok(lib.seccomp_load(context))
    finally:
        lib.seccomp_release(context)


def exec_target(command):
    for fd in (0, 1, 2):
        if stat.S_ISSOCK(os.fstat(fd).st_mode):
            raise RuntimeError("target stdio must not refer to a socket")
    os.closerange(3, os.sysconf("SC_OPEN_MAX"))
    install_filter()
    os.execv(command[0], command)


if __name__ == "__main__":
    command = sys.argv[1:]
    if command[0] == "--pipes":
        # Node's child-process "pipe" can be a Unix socketpair. Start the
        # restricted process with anonymous pipes and /dev/null instead.
        target = subprocess.run(
            [sys.executable, __file__, *command[1:]],
            stdin=subprocess.DEVNULL, capture_output=True,
        )
        sys.stdout.buffer.write(target.stdout)
        sys.stderr.buffer.write(target.stderr)
        sys.exit(target.returncode if target.returncode >= 0 else 128 - target.returncode)
    exec_target(command)

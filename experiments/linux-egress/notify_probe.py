"""Measure seccomp listener and sockaddr visibility inside the existing net namespace."""
import ctypes as c
import errno
import fcntl
import os
import platform
import struct
import subprocess
import sys
import threading

lib = c.CDLL(None, use_errno=True)
arch = platform.machine()
seccomp, connect = {"aarch64": (277, 203), "x86_64": (317, 42)}[arch]
class Filter(c.Structure):
    _fields_ = [("op", c.c_ushort), ("yes", c.c_ubyte), ("no", c.c_ubyte), ("k", c.c_uint)]
class Program(c.Structure):
    _fields_ = [("length", c.c_ushort), ("code", c.POINTER(Filter))]
class Vector(c.Structure):
    _fields_ = [("base", c.c_void_p), ("length", c.c_size_t)]

def supervise(fd):
    packet = bytearray(80)
    fcntl.ioctl(fd, 0xc0502100, packet)
    ident, pid, = struct.unpack_from("=QI", packet)
    addr, size = struct.unpack_from("=QQ", packet, 40)
    if size != 16:
        raise ValueError(size)
    buf = c.create_string_buffer(16)
    copied = lib.process_vm_readv(pid, c.byref(Vector(c.addressof(buf),16)),1,c.byref(Vector(addr,16)),1,0)
    ip = ".".join(map(str,buf.raw[4:8]))
    print(f"kernel={platform.release()} arch={arch} uid={os.getuid()} sockaddr_bytes={copied} ip={ip} port={int.from_bytes(buf.raw[2:4],'big')} errno={c.get_errno()}",flush=True)
    fcntl.ioctl(fd, 0xc0182101, struct.pack("=QqiI",ident,0,-errno.ENETUNREACH,0))

def launch():
    code = (Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,connect),Filter(6,0,0,0x7fc00000),Filter(6,0,0,0x7fff0000))
    assert lib.prctl(38,1,0,0,0) == 0
    fd=lib.syscall(seccomp,1,8,c.byref(Program(4,code)))
    if fd<0: raise OSError(c.get_errno(),"NEW_LISTENER")
    channel.append(fd)
    ready.set()
    result=subprocess.run([sys.executable,"-c","import errno,socket;assert socket.socket().connect_ex(('192.0.2.1',443))==errno.ENETUNREACH"])
    assert result.returncode==0
channel=[]
ready=threading.Event()
worker=threading.Thread(target=launch)
worker.start()
if not ready.wait(3): raise RuntimeError("listener unavailable")
supervise(channel[0])
worker.join()

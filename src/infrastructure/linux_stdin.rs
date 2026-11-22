//! Give the target a seekable file description opened on a read-only mount.
//! Only this description is shared back with the host, before the target starts.
use crate::{Result, error};
use rustix::fs::{StatVfsMountFlags, fstatvfs};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use std::fs::{self, File};
use std::io::{IoSlice, IoSliceMut, Seek, SeekFrom};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::{fs::MetadataExt, net::UnixDatagram};
use std::path::Path;
use tokio::process::Command;

const MOUNT: &str = "/veil-tell-stdin";
const CHANNEL: &str = "/veil-tell-stdin.sock";
const SPEC: &str = "VEIL_TELL_RELAY_FILE_STDIN";

pub struct FileInput {
    source: File,
    start: u64,
    channel: UnixDatagram,
}

impl FileInput {
    pub fn prepare(
        command: &mut Command,
        stdin: Option<&OwnedFd>,
        dir: &Path,
    ) -> Result<Option<Self>> {
        let Some(input) = stdin else { return Ok(None) };
        let mut source = File::from(input.try_clone()?);
        let stat = source.metadata()?;
        if !stat.is_file() {
            command.stdin(source);
            return Ok(None);
        }
        let start = source.stream_position()?;
        let path = fs::read_link(format!("/proc/self/fd/{}", source.as_raw_fd()))?;
        if stat.nlink() == 0 || !path.is_absolute() {
            return Err(error("isolated regular-file stdin needs a named file"));
        }
        let socket = dir.join("stdin.sock");
        let channel = UnixDatagram::bind(&socket)?;
        // Keep the inode pinned in the host. The relay verifies its identity after
        // mounting, so a rename cannot substitute another file before target exec.
        command
            .arg("--ro-bind")
            .arg(path)
            .arg(MOUNT)
            .arg("--ro-bind")
            .arg(socket)
            .arg(CHANNEL)
            .args(["--setenv", SPEC])
            .arg(format!("{} {} {start}", stat.dev(), stat.ino()));
        Ok(Some(Self {
            source,
            start,
            channel,
        }))
    }

    pub fn finish(mut self, success: bool) -> Result<()> {
        let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut storage);
        let mut byte = [0; 1];
        match recvmsg(
            &self.channel,
            &mut [IoSliceMut::new(&mut byte)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
        ) {
            Err(rustix::io::Errno::AGAIN) if !success => return Ok(()), // failed before target launch
            result => {
                result?;
            }
        }
        let Some(RecvAncillaryMessage::ScmRights(mut rights)) = control.drain().next() else {
            return Err(error("missing isolated stdin cursor"));
        };
        let mut view = File::from(
            rights
                .next()
                .ok_or_else(|| error("missing isolated stdin file"))?,
        );
        let end = view.stream_position()?;
        if end != self.start {
            if self.source.stream_position()? != self.start {
                return Err(error("redirected input was repositioned concurrently"));
            }
            self.source.seek(SeekFrom::Start(end))?;
        }
        Ok(())
    }
}

pub fn attach(command: &mut Command) -> Result<()> {
    let Some(spec) = std::env::var_os(SPEC) else {
        return Ok(());
    };
    let spec = spec.to_str().ok_or_else(|| error("invalid stdin setup"))?;
    let fields: Vec<_> = spec.split_whitespace().collect();
    let [dev, ino, start] = fields.as_slice() else {
        return Err(error("invalid stdin setup"));
    };
    let stat = fs::metadata(MOUNT)?;
    if !stat.is_file() || stat.dev() != dev.parse::<u64>()? || stat.ino() != ino.parse::<u64>()? {
        return Err(error("redirected stdin file changed before isolation"));
    }
    let mut view = File::open(MOUNT)?;
    if !fstatvfs(&view)?.f_flag.contains(StatVfsMountFlags::RDONLY) {
        return Err(error("isolated stdin mount is not read-only"));
    }
    view.seek(SeekFrom::Start(start.parse()?))?;
    let channel = UnixDatagram::unbound()?;
    channel.connect(CHANNEL)?;
    let mut storage = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut storage);
    let fds = [view.as_fd()];
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(error("cannot send isolated stdin cursor"));
    }
    sendmsg(
        &channel,
        &[IoSlice::new(b"I")],
        &mut control,
        SendFlags::empty(),
    )?;
    command.stdin(view);
    Ok(())
}

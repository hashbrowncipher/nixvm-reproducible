//! Read-only EROFS images, decoded on demand by the vendored rust-fs-erofs.
//!
//! The filesystem owns its block reader, so a host image is opened once and
//! remains open for the lifetime of the mount. Paths stay inside the image;
//! symlink traversal belongs to the guest mount table.

use std::io;
#[cfg(any(unix, windows))]
use std::path::Path;
use std::sync::Arc;

use fs_core::BlockRead;
use fs_erofs::{FileType, Filesystem, Inode, InodeVersion};

use super::{Attrs, DirEntry, MountFs, NodeKind, SetTime};

pub struct ErofsMount {
    fs: Filesystem,
}

impl std::fmt::Debug for ErofsMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErofsMount").finish_non_exhaustive()
    }
}

impl ErofsMount {
    /// Open a host image read-only, retaining the open file in this mount.
    #[cfg(any(unix, windows))]
    pub fn open(path: &Path) -> io::Result<Self> {
        let device = fs_core::FileDevice::open(path).map_err(block_error)?;
        Self::from_device(Arc::new(device))
    }

    /// Mount an owned block reader, including an embedder's in-memory reader.
    pub fn from_device(device: Arc<dyn BlockRead>) -> io::Result<Self> {
        let fs = Filesystem::open(device).map_err(to_io)?;
        if !fs.root_inode().map_err(to_io)?.is_dir() {
            return Err(io::Error::from_raw_os_error(20)); // ENOTDIR
        }
        Ok(Self { fs })
    }

    fn inode(&self, rel: &str) -> io::Result<Inode> {
        self.fs.lookup_path(rel).map_err(to_io)
    }

    fn attrs(&self, inode: &Inode) -> io::Result<Attrs> {
        let kind = node_kind(inode)?;
        let mtime = if inode.format.version == InodeVersion::Compact {
            self.fs.superblock().build_time
        } else {
            inode.mtime
        };
        Ok(Attrs {
            kind,
            size: inode.size,
            mode: u32::from(inode.mode),
            uid: inode.uid,
            gid: inode.gid,
            atime: mtime as i64,
            mtime: mtime as i64,
            // NIDs identify the actual inode, including every hard-link name.
            inode: inode.nid,
            nlink: inode.nlink,
            rdev: if matches!(kind, NodeKind::CharDevice | NodeKind::BlockDevice) {
                u64::from(inode.raw_u)
            } else {
                0
            },
        })
    }
}

fn node_kind(inode: &Inode) -> io::Result<NodeKind> {
    match inode.file_type() {
        FileType::RegularFile => Ok(NodeKind::File),
        FileType::Dir => Ok(NodeKind::Dir),
        FileType::Symlink => Ok(NodeKind::Symlink),
        FileType::ChrDev => Ok(NodeKind::CharDevice),
        FileType::BlkDev => Ok(NodeKind::BlockDevice),
        FileType::Fifo => Ok(NodeKind::Fifo),
        FileType::Sock => Ok(NodeKind::Socket),
        FileType::Unknown => Err(io::Error::from_raw_os_error(5)), // EIO
    }
}

fn block_error(error: fs_core::Error) -> io::Error {
    match error {
        fs_core::Error::Io(error) => error,
        fs_core::Error::ReadOnly => io::Error::from_raw_os_error(30),
        _ => io::Error::from_raw_os_error(5), // EIO
    }
}

fn to_io(error: fs_erofs::Error) -> io::Error {
    match error {
        fs_erofs::Error::Block(error) => block_error(error),
        fs_erofs::Error::NotFound => io::Error::from_raw_os_error(2),
        fs_erofs::Error::NotADirectory => io::Error::from_raw_os_error(20),
        fs_erofs::Error::UnsupportedLayout(_) => io::Error::from_raw_os_error(95),
        fs_erofs::Error::NotErofs => io::Error::new(io::ErrorKind::InvalidData, error),
        _ => io::Error::from_raw_os_error(5), // malformed image: EIO
    }
}

impl MountFs for ErofsMount {
    fn stat(&mut self, rel: &str) -> Option<Attrs> {
        self.try_stat(rel).ok()
    }

    fn try_stat(&mut self, rel: &str) -> io::Result<Attrs> {
        self.attrs(&self.inode(rel)?)
    }

    fn read_at(&mut self, rel: &str, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let inode = self.inode(rel)?;
        if inode.is_dir() {
            return Err(io::Error::from_raw_os_error(21)); // EISDIR
        }
        if !inode.is_regular_file() && !inode.is_symlink() {
            return Err(io::Error::from_raw_os_error(22)); // EINVAL
        }
        // The crate requires an exact in-bounds read; MountFs returns a short
        // read at EOF, including zero for offsets beyond the end.
        let count = inode.size.saturating_sub(off).min(buf.len() as u64) as usize;
        if count != 0 {
            self.fs
                .read_file(&inode, off, &mut buf[..count])
                .map_err(to_io)?;
        }
        Ok(count)
    }

    fn readdir(&mut self, rel: &str) -> io::Result<Vec<DirEntry>> {
        let inode = self.inode(rel)?;
        self.fs
            .read_dir(&inode)
            .map_err(to_io)?
            .into_iter()
            .filter(|entry| entry.name != b"." && entry.name != b"..")
            .map(|entry| {
                let inode = self.fs.read_inode(entry.nid).map_err(to_io)?;
                Ok(DirEntry {
                    name: String::from_utf8(entry.name)
                        .map_err(|_| io::Error::from_raw_os_error(84))?, // EILSEQ
                    kind: node_kind(&inode)?,
                    inode: inode.nid,
                })
            })
            .collect()
    }

    fn readlink(&mut self, rel: &str) -> io::Result<String> {
        let inode = self.inode(rel)?;
        if !inode.is_symlink() {
            return Err(io::Error::from_raw_os_error(22));
        }
        let target = self.fs.read_symlink_target(&inode).map_err(to_io)?;
        String::from_utf8(target).map_err(|_| io::Error::from_raw_os_error(84))
    }

    fn getxattr(&mut self, rel: &str, name: &str) -> io::Result<Vec<u8>> {
        let inode = self.inode(rel)?;
        self.fs
            .xattrs(&inode)
            .map_err(to_io)?
            .into_iter()
            .find(|(key, _)| key == name.as_bytes())
            .map(|(_, value)| value)
            .ok_or_else(|| io::Error::from_raw_os_error(61)) // ENODATA
    }

    fn listxattr(&mut self, rel: &str) -> io::Result<Vec<String>> {
        let inode = self.inode(rel)?;
        self.fs
            .xattrs(&inode)
            .map_err(to_io)?
            .into_iter()
            .map(|(name, _)| String::from_utf8(name).map_err(|_| io::Error::from_raw_os_error(84)))
            .collect()
    }

    fn set_times(&mut self, _: &str, _: SetTime, _: SetTime) -> io::Result<()> {
        Err(super::erofs())
    }

    fn set_owner(&mut self, _: &str, _: Option<u32>, _: Option<u32>) -> io::Result<()> {
        Err(super::erofs())
    }

    fn set_mode(&mut self, _: &str, _: u32) -> io::Result<()> {
        Err(super::erofs())
    }

    fn setxattr(&mut self, _: &str, _: &str, _: &[u8]) -> io::Result<()> {
        Err(super::erofs())
    }

    fn removexattr(&mut self, _: &str, _: &str) -> io::Result<()> {
        Err(super::erofs())
    }

    fn link(&mut self, _: &str, _: &str) -> io::Result<()> {
        Err(super::erofs())
    }
}

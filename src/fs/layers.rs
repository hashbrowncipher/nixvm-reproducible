//! A read-only merged stack of filesystem layers, ordered base to top.
//!
//! Directory lookup carries only the contributing parent directories forward.
//! This prevents a lower child from leaking through an intervening file,
//! symlink, whiteout or opaque directory, even when a newer layer creates a
//! directory at that same path.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use super::{Attrs, DevFs, DirEntry, MountFs, NodeKind, SetTime};

#[derive(Debug)]
pub struct LayerStack {
    layers: Vec<Box<dyn MountFs>>,
    /// Allocate merged inode numbers by source identity, retaining hard links
    /// while keeping separate images distinct. The writable Overlay reserves
    /// bit 63, so lower inode numbers stay below that bit.
    inodes: BTreeMap<(usize, u64), u64>,
}

impl LayerStack {
    /// Merge layers in base-to-top order. The last layer has precedence.
    /// Layer backends must stay immutable for the lifetime of the stack.
    pub fn new(mut layers: Vec<Box<dyn MountFs>>) -> io::Result<Self> {
        if layers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no filesystem layers",
            ));
        }
        for layer in &mut layers {
            if layer.try_stat("")?.kind != NodeKind::Dir {
                return Err(io::Error::from_raw_os_error(20));
            }
        }
        Ok(Self {
            layers,
            inodes: BTreeMap::new(),
        })
    }

    /// Matching directories, in top-to-base order, or the single visible
    /// non-directory. A non-directory below a higher directory stops merging.
    fn lookup(&mut self, rel: &str) -> io::Result<Vec<(usize, Attrs)>> {
        let mut parents = self.select("", (0..self.layers.len()).rev().collect())?;
        let mut path = String::new();
        for component in rel.split('/').filter(|component| !component.is_empty()) {
            if parents[0].1.kind != NodeKind::Dir {
                return Err(io::Error::from_raw_os_error(20));
            }
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(component);
            parents = self.select(&path, parents.into_iter().map(|(index, _)| index).collect())?;
        }
        Ok(parents)
    }

    fn select(&mut self, rel: &str, candidates: Vec<usize>) -> io::Result<Vec<(usize, Attrs)>> {
        let mut selected = Vec::new();
        for index in candidates {
            let layer = &mut self.layers[index];
            let attrs = match layer.try_stat(rel) {
                Ok(attrs) => attrs,
                Err(error) if error.raw_os_error() == Some(2) => continue,
                Err(error) => return Err(error),
            };
            if is_whiteout(&mut **layer, rel, &attrs)? {
                break;
            }
            if attrs.kind != NodeKind::Dir {
                if selected.is_empty() {
                    check_features(&mut **layer, rel, attrs.kind)?;
                    selected.push((index, attrs));
                }
                break;
            }
            check_features(&mut **layer, rel, attrs.kind)?;
            let opaque = overlay_attr(&mut **layer, rel, "opaque")?.as_deref() == Some(b"y");
            selected.push((index, attrs));
            if opaque {
                break;
            }
        }
        if selected.is_empty() {
            return Err(io::Error::from_raw_os_error(2));
        }
        Ok(selected)
    }

    fn merged_attrs(&mut self, layer: usize, mut attrs: Attrs) -> Attrs {
        let next = self.inodes.len() as u64 + 1;
        attrs.inode = *self.inodes.entry((layer, attrs.inode)).or_insert(next);
        attrs
    }
}

fn overlay_attr(layer: &mut dyn MountFs, rel: &str, suffix: &str) -> io::Result<Option<Vec<u8>>> {
    for namespace in ["trusted", "user"] {
        match layer.getxattr(rel, &format!("{namespace}.overlay.{suffix}")) {
            Ok(value) => return Ok(Some(value)),
            Err(error) if matches!(error.raw_os_error(), Some(61 | 95)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

fn is_whiteout(layer: &mut dyn MountFs, rel: &str, attrs: &Attrs) -> io::Result<bool> {
    if attrs.kind == NodeKind::CharDevice && attrs.rdev == 0 {
        return Ok(true);
    }
    Ok(attrs.kind == NodeKind::File
        && attrs.size == 0
        && overlay_attr(layer, rel, "whiteout")?.is_some())
}

/// Redirects and metadata-only copies require following a separate lower
/// path for data. Refuse them rather than expose an empty file or wrong tree.
fn check_features(layer: &mut dyn MountFs, rel: &str, kind: NodeKind) -> io::Result<()> {
    let attribute = match kind {
        NodeKind::Dir => "redirect",
        NodeKind::File => "metacopy",
        _ => return Ok(()),
    };
    if overlay_attr(layer, rel, attribute)?.is_some() {
        return Err(io::Error::from_raw_os_error(95)); // EOPNOTSUPP
    }
    Ok(())
}

fn overlay_name(name: &str) -> bool {
    name.starts_with("trusted.overlay.") || name.starts_with("user.overlay.")
}

impl MountFs for LayerStack {
    fn visit_devfs_mut(&mut self, visitor: &mut dyn FnMut(&mut DevFs)) {
        for layer in &mut self.layers {
            layer.visit_devfs_mut(visitor);
        }
    }

    fn stat(&mut self, rel: &str) -> Option<Attrs> {
        self.try_stat(rel).ok()
    }

    fn try_stat(&mut self, rel: &str) -> io::Result<Attrs> {
        let (layer, attrs) = self.lookup(rel)?.remove(0);
        Ok(self.merged_attrs(layer, attrs))
    }

    fn read_at(&mut self, rel: &str, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let (layer, _) = self.lookup(rel)?.remove(0);
        self.layers[layer].read_at(rel, off, buf)
    }

    fn readdir(&mut self, rel: &str) -> io::Result<Vec<DirEntry>> {
        let directories = self.lookup(rel)?;
        if directories[0].1.kind != NodeKind::Dir {
            return Err(io::Error::from_raw_os_error(20));
        }
        let mut names = BTreeSet::new();
        for (index, _) in directories {
            for entry in self.layers[index].readdir(rel)? {
                if entry.name != "." && entry.name != ".." {
                    names.insert(entry.name);
                }
            }
        }
        let mut entries = Vec::new();
        for name in names {
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            match self.lookup(&path) {
                Ok(mut nodes) => {
                    let (index, attrs) = nodes.remove(0);
                    let attrs = self.merged_attrs(index, attrs);
                    entries.push(DirEntry {
                        name,
                        kind: attrs.kind,
                        inode: attrs.inode,
                    });
                }
                Err(error) if error.raw_os_error() == Some(2) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(entries)
    }

    fn readlink(&mut self, rel: &str) -> io::Result<String> {
        let (layer, _) = self.lookup(rel)?.remove(0);
        self.layers[layer].readlink(rel)
    }

    fn getxattr(&mut self, rel: &str, name: &str) -> io::Result<Vec<u8>> {
        let (layer, _) = self.lookup(rel)?.remove(0);
        if overlay_name(name) {
            return Err(io::Error::from_raw_os_error(61));
        }
        self.layers[layer].getxattr(rel, name)
    }

    fn listxattr(&mut self, rel: &str) -> io::Result<Vec<String>> {
        let (layer, _) = self.lookup(rel)?.remove(0);
        let mut names = self.layers[layer].listxattr(rel)?;
        names.retain(|name| !overlay_name(name));
        Ok(names)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::TmpFs;

    fn file(fs: &mut TmpFs, path: &str, data: &[u8]) {
        fs.create(path, 0o644).unwrap();
        fs.write_at(path, 0, data).unwrap();
    }

    fn names(fs: &mut dyn MountFs, path: &str) -> Vec<String> {
        fs.readdir(path)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect()
    }

    #[test]
    fn merges_directories_and_uses_the_topmost_file() {
        let mut base = TmpFs::new();
        base.mkdir("dir", 0o755).unwrap();
        file(&mut base, "dir/shared", b"base");
        file(&mut base, "dir/base", b"base");
        let mut top = TmpFs::new();
        top.mkdir("dir", 0o755).unwrap();
        file(&mut top, "dir/shared", b"top!");
        file(&mut top, "dir/top", b"top");
        let mut stack = LayerStack::new(vec![Box::new(base), Box::new(top)]).unwrap();
        assert_eq!(names(&mut stack, "dir"), ["base", "shared", "top"]);
        let mut data = [0; 4];
        assert_eq!(stack.read_at("dir/shared", 0, &mut data).unwrap(), 4);
        assert_eq!(&data, b"top!");
    }

    #[test]
    fn an_intervening_file_blocks_an_older_directory() {
        let mut base = TmpFs::new();
        base.mkdir("dir", 0o755).unwrap();
        file(&mut base, "dir/old", b"old");
        let mut middle = TmpFs::new();
        file(&mut middle, "dir", b"file");
        let mut top = TmpFs::new();
        top.mkdir("dir", 0o755).unwrap();
        file(&mut top, "dir/new", b"new");
        let mut stack =
            LayerStack::new(vec![Box::new(base), Box::new(middle), Box::new(top)]).unwrap();
        assert_eq!(names(&mut stack, "dir"), ["new"]);
        assert!(stack.stat("dir/old").is_none());
        assert_eq!(
            stack
                .read_at("dir/old", 0, &mut [0])
                .unwrap_err()
                .raw_os_error(),
            Some(2)
        );
    }

    #[test]
    fn xattr_whiteouts_and_opaque_directories_hide_lower_children() {
        let mut base = TmpFs::new();
        file(&mut base, "removed", b"old");
        base.mkdir("dir", 0o755).unwrap();
        file(&mut base, "dir/old", b"old");
        let mut middle = TmpFs::new();
        file(&mut middle, "removed", b"");
        middle
            .setxattr("removed", "user.overlay.whiteout", b"")
            .unwrap();
        middle.mkdir("dir", 0o755).unwrap();
        middle.setxattr("dir", "user.overlay.opaque", b"y").unwrap();
        file(&mut middle, "dir/middle", b"middle");
        let mut top = TmpFs::new();
        top.mkdir("dir", 0o755).unwrap();
        file(&mut top, "dir/top", b"top");
        let mut stack =
            LayerStack::new(vec![Box::new(base), Box::new(middle), Box::new(top)]).unwrap();
        assert!(stack.stat("removed").is_none());
        assert_eq!(names(&mut stack, ""), ["dir"]);
        assert_eq!(names(&mut stack, "dir"), ["middle", "top"]);
        assert!(stack.stat("dir/old").is_none());
        assert!(stack.listxattr("dir").unwrap().is_empty());
        assert_eq!(
            stack
                .getxattr("dir", "user.overlay.opaque")
                .unwrap_err()
                .raw_os_error(),
            Some(61)
        );
    }

    #[test]
    fn an_opaque_root_and_the_x_optimization_flag_are_distinct() {
        for (flag, expected) in [(b"y", vec!["top"]), (b"x", vec!["base", "top"])] {
            let mut base = TmpFs::new();
            file(&mut base, "base", b"base");
            let mut top = TmpFs::new();
            file(&mut top, "top", b"top");
            top.setxattr("", "trusted.overlay.opaque", flag).unwrap();
            let mut stack = LayerStack::new(vec![Box::new(base), Box::new(top)]).unwrap();
            assert_eq!(names(&mut stack, ""), expected);
        }
    }

    #[test]
    fn inode_identity_preserves_hard_links_and_separates_many_images() {
        let mut layers: Vec<Box<dyn MountFs>> = Vec::new();
        for index in 0..80 {
            let mut layer = TmpFs::new();
            let path = format!("file{index}");
            file(&mut layer, &path, b"data");
            layer.link(&path, &format!("alias{index}")).unwrap();
            layers.push(Box::new(layer));
        }
        let mut stack = LayerStack::new(layers).unwrap();
        let mut identities = BTreeSet::new();
        for index in 0..80 {
            let attrs = stack.stat(&format!("file{index}")).unwrap();
            assert!(identities.insert(attrs.inode));
            assert_eq!(
                attrs.inode,
                stack.stat(&format!("alias{index}")).unwrap().inode
            );
            assert_eq!(attrs.nlink, 2);
            assert_eq!(attrs.inode & (1 << 63), 0);
        }
        for entry in stack.readdir("").unwrap() {
            assert_eq!(entry.inode, stack.stat(&entry.name).unwrap().inode);
        }
    }

    #[test]
    fn invalid_roots_and_non_directory_traversal_fail() {
        assert!(LayerStack::new(Vec::new()).is_err());
        let mut top = TmpFs::new();
        file(&mut top, "file", b"data");
        let mut stack = LayerStack::new(vec![Box::new(top)]).unwrap();
        assert_eq!(
            stack.try_stat("file/child").unwrap_err().raw_os_error(),
            Some(20)
        );
        assert_eq!(stack.readdir("file").unwrap_err().raw_os_error(), Some(20));
        assert_eq!(
            stack.read_at("", 0, &mut [0]).unwrap_err().raw_os_error(),
            Some(21)
        );
        assert_eq!(
            stack.set_mode("file", 0o600).unwrap_err().raw_os_error(),
            Some(30)
        );
    }

    #[derive(Debug)]
    struct Unreadable {
        root: TmpFs,
    }

    impl MountFs for Unreadable {
        fn stat(&mut self, rel: &str) -> Option<Attrs> {
            self.try_stat(rel).ok()
        }
        fn try_stat(&mut self, rel: &str) -> io::Result<Attrs> {
            if rel.is_empty() {
                self.root.try_stat("")
            } else {
                Err(io::Error::from_raw_os_error(5))
            }
        }
        fn read_at(&mut self, _: &str, _: u64, _: &mut [u8]) -> io::Result<usize> {
            panic!("an unreadable layer must not reach data reads")
        }
        fn readdir(&mut self, _: &str) -> io::Result<Vec<DirEntry>> {
            Err(io::Error::from_raw_os_error(5))
        }
    }

    #[test]
    fn an_unreadable_higher_layer_does_not_expose_older_data() {
        let mut base = TmpFs::new();
        file(&mut base, "file", b"stale contents");
        let unreadable = Unreadable { root: TmpFs::new() };
        let mut stack = LayerStack::new(vec![Box::new(base), Box::new(unreadable)]).unwrap();
        assert_eq!(stack.try_stat("file").unwrap_err().raw_os_error(), Some(5));
        assert_eq!(
            stack
                .read_at("file", 0, &mut [0; 32])
                .unwrap_err()
                .raw_os_error(),
            Some(5)
        );
        assert_eq!(stack.readdir("").unwrap_err().raw_os_error(), Some(5));
    }

    #[test]
    fn refuses_redirects_and_metadata_only_copies_in_visible_layers() {
        let mut base = TmpFs::new();
        file(&mut base, "file", b"lower contents");
        let mut top = TmpFs::new();
        file(&mut top, "file", b"");
        top.setxattr("file", "trusted.overlay.metacopy", b"")
            .unwrap();
        top.mkdir("redirected", 0o755).unwrap();
        top.setxattr("redirected", "user.overlay.redirect", b"/original")
            .unwrap();
        let mut stack = LayerStack::new(vec![Box::new(base), Box::new(top)]).unwrap();
        assert_eq!(
            stack
                .read_at("file", 0, &mut [0; 32])
                .unwrap_err()
                .raw_os_error(),
            Some(95)
        );
        assert_eq!(
            stack.readdir("redirected").unwrap_err().raw_os_error(),
            Some(95)
        );
    }
}

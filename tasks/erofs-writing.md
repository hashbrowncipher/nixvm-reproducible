# Save guest changes as EROFS layers

Reading and layering EROFS images comes first. Writing is deferred.

## Goals

- Open an ordered set of EROFS image files on the host when nixvm starts.
  Present their merged contents to the guest using overlayfs semantics.
- Keep those images immutable. Guest changes accumulate in a writable upper.
- At well-defined lifecycle moments, especially guest exit, write that upper
  as a new EROFS layer using the locally vendored `rust-fs-erofs` crate.
- Save the changes rather than flattening every input image into a new full
  filesystem. On the next run, append the saved layer above the earlier images.
- Preserve changed data and metadata, created files and directories, symlinks,
  hard links, and extended attributes. Preserve deletions as whiteouts and
  directory replacement as opacity, so hidden lower entries stay hidden.
- Save the root upper alone. Separate mounts such as `/tmp`, `/proc`, `/dev`,
  `/sys`, `/work`, and host bind mounts are outside that layer.
- Report save failures. Publish a complete image atomically so a failed save
  does not replace an earlier valid layer or alter an input image.

## Acceptance

Run a guest over multiple layers, make changes, exit and save, then start a
fresh guest with the saved image as its highest lower layer. The guest must
see the same persisted root contents and metadata. Cover modification,
creation, deletion, rename, directory replacement, symlinks, hard links and
xattrs. Verify that the original images remain unchanged.

Writing happens at an explicit checkpoint or exit, rather than rebuilding an
image on each guest write.

## Decisions for the writing task

- Define the checkpoint API and the option that requests an exit-time save.
- Define behavior after a guest execution error, an abnormal exit, or a host
  interruption, and how save errors affect the reported guest result.
- Choose image compression and resource limits for serializing large uppers.
- Decide how to handle metadata EROFS does not store, such as independent
  access times.
- Decide whether a successful checkpoint starts a fresh writable upper or
  leaves the current upper in place.

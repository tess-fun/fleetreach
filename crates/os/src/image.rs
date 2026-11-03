//! Reading a container image into one merged filesystem view.
//!
//! Three inputs are accepted: an image archive (`docker save` output, or an OCI image layout
//! packed as a tar), the same two layouts unpacked into a directory, and a plain root
//! filesystem directory (`docker export` unpacked, or a mounted rootfs). Layers are applied
//! in order with OCI whiteouts: `.wh.<name>` deletes `<name>` from the layers below and
//! `.wh..wh..opq` empties its directory of everything the layers below put there.
//!
//! Only the files the caller asks for are kept in memory (package databases, os-release,
//! lockfiles); every other path is kept as a name, so whiteouts, symlinks and "is this file
//! here" questions are answered for the whole image. Layer blobs named by digest are
//! checked against it, so a corrupt or tampered layer fails the scan instead of reading as
//! a smaller image.

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::OsError;
use crate::tar::{self, Kind, Source};

/// The largest single file kept in memory; a bigger wanted file is noted and skipped.
pub const MAX_FILE_BYTES: u64 = 64 << 20;

/// How many symlinks a path lookup follows before giving up (Linux's own limit).
const MAX_LINK_HOPS: usize = 40;

/// What is at a path in the merged image.
#[derive(Debug, Clone)]
enum Node {
    /// A regular file; its content when it was wanted and small enough.
    File(Option<Arc<Vec<u8>>>),
    Symlink(String),
    Dir,
    Other,
}

#[derive(Debug, Clone)]
struct Entry {
    layer: usize,
    node: Node,
}

/// The merged filesystem of an image, keyed by path relative to `/` (`etc/os-release`).
#[derive(Debug, Default)]
pub struct ImageFs {
    entries: BTreeMap<String, Entry>,
    /// How many layers were applied (1 for a rootfs directory).
    layers: usize,
    /// Wanted files that could not be kept (too large, unreadable), as `path: reason`.
    skipped: Vec<String>,
}

/// Normalize an archive path to `a/b/c`; `None` for the root itself. A `..` component is an
/// error: no real image has one, and honouring it could escape the image.
fn normalize(path: &str) -> Result<Option<String>, String> {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(format!("path with `..` in the image: {path:?}")),
            p => parts.push(p),
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join("/")))
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

impl ImageFs {
    /// Remove `path` and everything under it that came from a layer below `layer`.
    fn remove_tree(&mut self, path: &str, below: usize) {
        let prefix = format!("{path}/");
        let doomed: Vec<String> = self
            .entries
            .range(path.to_string()..)
            .take_while(|(k, _)| k.as_str() == path || k.starts_with(&prefix))
            .filter(|(_, e)| e.layer < below)
            .map(|(k, _)| k.clone())
            .collect();
        for k in doomed {
            self.entries.remove(&k);
        }
    }

    /// Remove everything under `dir` (not `dir` itself) from layers below `layer`.
    fn remove_children(&mut self, dir: &str, below: usize) {
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let doomed: Vec<String> = self
            .entries
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .filter(|(k, e)| e.layer < below && k.as_str() != dir)
            .map(|(k, _)| k.clone())
            .collect();
        for k in doomed {
            self.entries.remove(&k);
        }
    }

    /// Apply one archive entry of `layer`.
    fn apply(&mut self, layer: usize, path: String, node: Node) {
        let (dir, name) = match path.rsplit_once('/') {
            Some((d, n)) => (d.to_string(), n.to_string()),
            None => (String::new(), path.clone()),
        };
        if name == ".wh..wh..opq" {
            self.remove_children(&dir, layer);
            return;
        }
        if let Some(target) = name.strip_prefix(".wh.") {
            self.remove_tree(&join(&dir, target), layer);
            return;
        }
        // Anything but a directory replaces a whole subtree; a directory over a directory
        // merges with it.
        let replaces_dir = !matches!(node, Node::Dir);
        match self.entries.get(&path) {
            Some(Entry {
                node: Node::Dir, ..
            }) if !replaces_dir => {}
            Some(Entry {
                node: Node::Dir, ..
            }) => self.remove_tree(&path, layer + 1),
            _ => {}
        }
        self.entries.insert(path, Entry { layer, node });
    }

    /// Follow symlinks in every component of `path`, returning the real path.
    pub fn canonical(&self, path: &str) -> Option<String> {
        let mut pending: Vec<String> = normalize(path)
            .ok()??
            .split('/')
            .rev()
            .map(str::to_string)
            .collect();
        let mut current = String::new();
        let mut hops = 0;
        while let Some(part) = pending.pop() {
            let next = join(&current, &part);
            match self.entries.get(&next).map(|e| &e.node) {
                Some(Node::Symlink(target)) => {
                    hops += 1;
                    if hops > MAX_LINK_HOPS {
                        return None;
                    }
                    let base = if target.starts_with('/') {
                        String::new()
                    } else {
                        current.clone()
                    };
                    // Re-walk the target from its base, then the rest of the path.
                    let mut resolved: Vec<String> = Vec::new();
                    for seg in base.split('/').chain(target.split('/')) {
                        match seg {
                            "" | "." => {}
                            ".." => {
                                resolved.pop();
                            }
                            s => resolved.push(s.to_string()),
                        }
                    }
                    current = String::new();
                    for seg in resolved.into_iter().rev() {
                        pending.push(seg);
                    }
                }
                Some(_) => current = next,
                // Tars often omit parent directory entries: a missing intermediate
                // component is an implicit directory, a missing last one is absent.
                None if !pending.is_empty() || self.has_children(&next) => current = next,
                None => return None,
            }
        }
        Some(current)
    }

    /// Whether any entry lies under `dir` (an implicit directory).
    fn has_children(&self, dir: &str) -> bool {
        let prefix = format!("{dir}/");
        self.entries
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(k, _)| k.starts_with(&prefix))
    }

    /// The content of the file at `path` (symlinks followed), if it was kept.
    pub fn read(&self, path: &str) -> Option<&[u8]> {
        let real = self.canonical(path)?;
        match &self.entries.get(&real)?.node {
            Node::File(Some(data)) => Some(data.as_slice()),
            _ => None,
        }
    }

    /// Whether `path` exists (symlinks followed).
    pub fn exists(&self, path: &str) -> bool {
        self.canonical(path).is_some()
    }

    /// Whether `path` is a regular file in the merged image (symlinks followed).
    pub fn is_file(&self, path: &str) -> bool {
        self.canonical(path)
            .and_then(|p| self.entries.get(&p))
            .is_some_and(|e| matches!(e.node, Node::File(_)))
    }

    /// The names directly inside directory `dir` (symlinks in `dir` followed), sorted.
    pub fn list_dir(&self, dir: &str) -> Vec<String> {
        let Some(real) = self.canonical(dir) else {
            return Vec::new();
        };
        let prefix = if real.is_empty() {
            String::new()
        } else {
            format!("{real}/")
        };
        self.entries
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(k, _)| k.get(prefix.len()..))
            .filter(|rest| !rest.is_empty() && !rest.contains('/'))
            .map(str::to_string)
            .collect()
    }

    /// Every regular file, with its content when it was kept.
    pub fn files(&self) -> impl Iterator<Item = (&str, Option<&[u8]>)> {
        self.entries.iter().filter_map(|(k, e)| match &e.node {
            Node::File(data) => Some((k.as_str(), data.as_deref().map(Vec::as_slice))),
            _ => None,
        })
    }

    /// How many layers were merged.
    pub fn layers(&self) -> usize {
        self.layers
    }

    /// Wanted files that could not be kept, as `path: reason`.
    pub fn skipped(&self) -> &[String] {
        &self.skipped
    }

    /// Build a view from in-memory `(path, content)` files, for tests and callers that
    /// already hold the files.
    pub fn from_files<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> ImageFs {
        let mut fs = ImageFs {
            layers: 1,
            ..ImageFs::default()
        };
        for (path, data) in files {
            if let Ok(Some(p)) = normalize(path) {
                fs.apply(0, p, Node::File(Some(Arc::new(data.to_vec()))));
            }
        }
        fs
    }

    /// Read one layer's tar stream into the view as layer `layer`.
    fn apply_layer<S: Source>(
        &mut self,
        layer: usize,
        src: S,
        want: &dyn Fn(&str) -> bool,
    ) -> io::Result<()> {
        let mut reader = tar::Reader::new(src);
        while let Some(entry) = reader.next_entry()? {
            let path = match normalize(&entry.path) {
                Ok(Some(p)) => p,
                Ok(None) => continue,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };
            let node = match entry.kind {
                Kind::File if want(&path) => {
                    if entry.size > MAX_FILE_BYTES {
                        self.skipped
                            .push(format!("{path}: larger than {MAX_FILE_BYTES} bytes"));
                        Node::File(None)
                    } else {
                        Node::File(Some(Arc::new(reader.read_data(MAX_FILE_BYTES)?)))
                    }
                }
                Kind::File => Node::File(None),
                Kind::Hardlink(target) => {
                    // A hard link shares its target's content (an earlier entry).
                    let target = normalize(&target)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                        .unwrap_or_default();
                    match self.entries.get(&target).map(|e| &e.node) {
                        Some(Node::File(data)) => Node::File(data.clone()),
                        _ => {
                            if want(&path) {
                                self.skipped
                                    .push(format!("{path}: hard link to a missing {target}"));
                            }
                            Node::File(None)
                        }
                    }
                }
                Kind::Symlink(target) => Node::Symlink(target),
                Kind::Dir => Node::Dir,
                Kind::Other => Node::Other,
            };
            self.apply(layer, path, node);
        }
        Ok(())
    }
}

/// A reader that hashes every byte it passes on.
struct Hashing<'a, R> {
    inner: R,
    hasher: &'a mut Sha256,
}

impl<R: Read> Read for Hashing<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(buf.get(..n).unwrap_or_default());
        Ok(n)
    }
}

/// zstd, frame after frame (ruzstd's own reader stops at the first frame), skipping
/// skippable frames such as the zstd:chunked metadata.
struct Zstd<R: BufRead> {
    src: R,
    dec: ruzstd::decoding::FrameDecoder,
    in_frame: bool,
}

impl<R: BufRead> Read for Zstd<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
        loop {
            if self.in_frame {
                if self.dec.can_collect() > 0 {
                    return self.dec.read(buf);
                }
                if self.dec.is_finished() {
                    self.in_frame = false;
                    continue;
                }
                self.dec
                    .decode_blocks(
                        &mut self.src,
                        ruzstd::decoding::BlockDecodingStrategy::UptoBlocks(1),
                    )
                    .map_err(io::Error::other)?;
                continue;
            }
            if self.src.fill_buf()?.is_empty() {
                return Ok(0);
            }
            match self.dec.reset(&mut self.src) {
                Ok(()) => self.in_frame = true,
                Err(FrameDecoderError::ReadFrameHeaderError(ReadFrameHeaderError::SkipFrame {
                    length,
                    ..
                })) => {
                    let n = u64::from(length);
                    if io::copy(&mut (&mut self.src).take(n), &mut io::sink())? < n {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "zstd skippable frame cut short",
                        ));
                    }
                }
                Err(e) => return Err(io::Error::other(e)),
            }
        }
    }
}

/// Wrap `raw` in the decompressor its first bytes call for (gzip, zstd, or none).
pub(crate) fn decompress<'a, R: Read + 'a>(raw: R) -> io::Result<Box<dyn Read + 'a>> {
    let mut buf = BufReader::with_capacity(1 << 16, raw);
    let head = buf.fill_buf()?;
    Ok(if head.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::bufread::MultiGzDecoder::new(buf))
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Box::new(Zstd {
            src: buf,
            dec: ruzstd::decoding::FrameDecoder::new(),
            in_frame: false,
        })
    } else {
        Box::new(buf)
    })
}

/// Where an image's blobs live: a directory, or members of a tar archive.
enum Archive {
    Dir(PathBuf),
    Tar {
        file: PathBuf,
        /// member path -> (data offset, size), symlinks already followed.
        members: BTreeMap<String, (u64, u64)>,
    },
}

impl Archive {
    /// Index the members of an (uncompressed) image archive.
    fn index_tar(file: &Path) -> Result<Archive, OsError> {
        let f = std::fs::File::open(file).map_err(|e| OsError::io(file, e))?;
        let mut reader = tar::Reader::new(SeekFile(f));
        let mut members = BTreeMap::new();
        let mut links = Vec::new();
        while let Some(entry) = reader.next_entry().map_err(|e| OsError::io(file, e))? {
            let Ok(Some(path)) = normalize(&entry.path) else {
                continue;
            };
            match entry.kind {
                Kind::File => {
                    members.insert(path, (reader.position(), entry.size));
                }
                Kind::Symlink(t) => links.push((path.clone(), join(parent(&path), &t))),
                Kind::Hardlink(t) => links.push((path, t)),
                _ => {}
            }
        }
        // Older `docker save` deduplicates layers with symlinks between layer directories.
        for (path, target) in links {
            let target = normalize_lexical(&target);
            if let Some(&m) = members.get(&target) {
                members.insert(path, m);
            }
        }
        Ok(Archive::Tar {
            file: file.to_path_buf(),
            members,
        })
    }

    fn has(&self, name: &str) -> bool {
        match self {
            Archive::Dir(d) => d.join(name).is_file(),
            Archive::Tar { members, .. } => members.contains_key(name),
        }
    }

    /// Open member `name` for reading, with its size.
    fn open(&self, name: &str) -> Result<(Box<dyn Read>, u64), OsError> {
        match self {
            Archive::Dir(d) => {
                let path = d.join(name);
                let f = std::fs::File::open(&path).map_err(|e| OsError::io(&path, e))?;
                let len = f.metadata().map_err(|e| OsError::io(&path, e))?.len();
                Ok((Box::new(f), len))
            }
            Archive::Tar { file, members } => {
                let &(offset, size) = members
                    .get(name)
                    .ok_or_else(|| OsError::image(file, format!("{name} is not in the archive")))?;
                let mut f = std::fs::File::open(file).map_err(|e| OsError::io(file, e))?;
                f.seek(SeekFrom::Start(offset))
                    .map_err(|e| OsError::io(file, e))?;
                Ok((Box::new(f.take(size)), size))
            }
        }
    }

    fn read_json<T: for<'de> Deserialize<'de>>(
        &self,
        name: &str,
        label: &Path,
    ) -> Result<T, OsError> {
        let (mut r, len) = self.open(name)?;
        if len > MAX_FILE_BYTES {
            return Err(OsError::image(label, format!("{name} is too large")));
        }
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).map_err(|e| OsError::io(label, e))?;
        serde_json::from_slice(&buf)
            .map_err(|e| OsError::image(label, format!("{name}: invalid JSON: {e}")))
    }
}

/// Resolve `.`/`..` lexically (for links inside the outer archive, which are relative).
fn normalize_lexical(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

/// A file that skips by seeking.
struct SeekFile(std::fs::File);

impl Read for SeekFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Source for SeekFile {
    fn skip(&mut self, n: u64) -> io::Result<()> {
        let n = i64::try_from(n).map_err(|_| io::Error::other("seek too far"))?;
        self.0.seek(SeekFrom::Current(n)).map(|_| ())
    }
}

#[derive(Deserialize)]
struct DockerManifest {
    #[serde(rename = "Layers")]
    layers: Vec<String>,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct OciIndex {
    #[serde(default)]
    manifests: Vec<Descriptor>,
}

#[derive(Deserialize, Clone)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Deserialize, Clone)]
struct Platform {
    #[serde(default)]
    os: String,
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    variant: Option<String>,
}

impl Platform {
    fn label(&self) -> String {
        match &self.variant {
            Some(v) => format!("{}/{}/{v}", self.os, self.architecture),
            None => format!("{}/{}", self.os, self.architecture),
        }
    }
}

#[derive(Deserialize)]
struct OciManifest {
    #[serde(default)]
    layers: Vec<Descriptor>,
    /// Present when this "manifest" is in fact an index (nested image index).
    #[serde(default)]
    manifests: Option<Vec<Descriptor>>,
}

/// One layer to apply: its member name, and the digest it must hash to when known.
struct Layer {
    name: String,
    digest: Option<String>,
}

fn blob_name(digest: &str) -> Option<String> {
    let (alg, hex) = digest.split_once(':')?;
    (!alg.is_empty()
        && !hex.is_empty()
        && hex.bytes().all(|b| b.is_ascii_alphanumeric())
        && alg.bytes().all(|b| b.is_ascii_alphanumeric()))
    .then(|| format!("blobs/{alg}/{hex}"))
}

/// The digest a `blobs/sha256/<hex>` member name stands for.
fn digest_of_name(name: &str) -> Option<String> {
    let hex = name.strip_prefix("blobs/sha256/")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| format!("sha256:{hex}"))
}

/// The layers of the one image in an archive, bottom first.
fn layers_of(
    archive: &Archive,
    label: &Path,
    platform: Option<&str>,
) -> Result<Vec<Layer>, OsError> {
    if archive.has("manifest.json") {
        let manifests: Vec<DockerManifest> = archive.read_json("manifest.json", label)?;
        let one = match manifests.as_slice() {
            [one] => one,
            [] => return Err(OsError::image(label, "manifest.json lists no image")),
            many => {
                let tags: Vec<String> = many
                    .iter()
                    .flat_map(|m| m.repo_tags.clone().unwrap_or_default())
                    .collect();
                return Err(OsError::image(
                    label,
                    format!(
                        "the archive holds {} images ({}); save one image per archive",
                        many.len(),
                        tags.join(", ")
                    ),
                ));
            }
        };
        return Ok(one
            .layers
            .iter()
            .map(|l| {
                let name = normalize_lexical(l);
                Layer {
                    digest: digest_of_name(&name),
                    name,
                }
            })
            .collect());
    }
    if archive.has("index.json") {
        let index: OciIndex = archive.read_json("index.json", label)?;
        // Walk nested indexes down to image manifests whose blobs are present, skipping
        // attestation manifests (platform unknown/unknown).
        let mut stack = index.manifests;
        let mut images: Vec<(Option<Platform>, OciManifest)> = Vec::new();
        let mut guard = 0;
        while let Some(d) = stack.pop() {
            guard += 1;
            if guard > 1000 {
                return Err(OsError::image(label, "index.json nests too deeply"));
            }
            if d.platform.as_ref().is_some_and(|p| p.os == "unknown") {
                continue;
            }
            let Some(name) = blob_name(&d.digest) else {
                return Err(OsError::image(label, format!("bad digest {:?}", d.digest)));
            };
            if !archive.has(&name) {
                continue;
            }
            let m: OciManifest = archive.read_json(&name, label)?;
            match m.manifests {
                Some(children) if d.media_type.contains("index") || m.layers.is_empty() => {
                    stack.extend(children);
                }
                _ => images.push((d.platform.clone(), m)),
            }
        }
        if let Some(wanted) = platform {
            images.retain(|(p, _)| p.as_ref().is_some_and(|p| p.label() == wanted));
        }
        let manifest = match images.len() {
            1 => images.pop().map(|(_, m)| m),
            0 => None,
            _ => {
                let labels: Vec<String> = images
                    .iter()
                    .map(|(p, _)| p.as_ref().map_or("unknown".to_string(), Platform::label))
                    .collect();
                return Err(OsError::image(
                    label,
                    format!(
                        "the layout holds images for several platforms ({}); choose one with \
                         `platform`",
                        labels.join(", ")
                    ),
                ));
            }
        };
        let Some(manifest) = manifest else {
            return Err(OsError::image(
                label,
                "no image manifest with its layers present",
            ));
        };
        return manifest
            .layers
            .iter()
            .map(|l| {
                let name = blob_name(&l.digest)
                    .ok_or_else(|| OsError::image(label, format!("bad digest {:?}", l.digest)))?;
                Ok(Layer {
                    name,
                    digest: Some(l.digest.clone()),
                })
            })
            .collect();
    }
    Err(OsError::image(
        label,
        "neither manifest.json (docker save) nor index.json (OCI layout) found",
    ))
}

/// Open the image at `path` (archive, layout directory or rootfs directory), keeping the
/// files `want` selects. `platform` (`linux/amd64`) picks one image from a multi-platform
/// OCI layout.
///
/// # Errors
///
/// [`OsError`] when the input cannot be read, is not an image, holds several images, or a
/// layer is corrupt or does not match its digest.
pub fn open(
    path: &Path,
    want: &dyn Fn(&str) -> bool,
    platform: Option<&str>,
) -> Result<ImageFs, OsError> {
    let md = std::fs::metadata(path).map_err(|e| OsError::io(path, e))?;
    if md.is_dir() {
        if path.join("manifest.json").is_file() || path.join("index.json").is_file() {
            return open_layers(&Archive::Dir(path.to_path_buf()), path, want, platform);
        }
        return open_rootfs(path, want);
    }
    // A compressed archive is a compressed root filesystem tarball (a single layer).
    let mut head = [0u8; 4];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .map_err(|e| OsError::io(path, e))?;
    let compressed =
        n >= 2 && (head.starts_with(&[0x1f, 0x8b]) || head == [0x28, 0xb5, 0x2f, 0xfd]);
    if !compressed {
        let archive = Archive::index_tar(path)?;
        if archive.has("manifest.json") || archive.has("index.json") {
            return open_layers(&archive, path, want, platform);
        }
    }
    // A single root filesystem tarball (`docker export`, a minirootfs).
    let f = std::fs::File::open(path).map_err(|e| OsError::io(path, e))?;
    let mut fs = ImageFs {
        layers: 1,
        ..ImageFs::default()
    };
    let stream = decompress(f).map_err(|e| OsError::io(path, e))?;
    fs.apply_layer(0, stream, want)
        .map_err(|e| OsError::io(path, e))?;
    Ok(fs)
}

fn open_layers(
    archive: &Archive,
    label: &Path,
    want: &dyn Fn(&str) -> bool,
    platform: Option<&str>,
) -> Result<ImageFs, OsError> {
    let layers = layers_of(archive, label, platform)?;
    let mut fs = ImageFs::default();
    for (i, layer) in layers.iter().enumerate() {
        let (raw, _) = archive.open(&layer.name)?;
        let mut hasher = Sha256::new();
        {
            let hashing = Hashing {
                inner: raw,
                hasher: &mut hasher,
            };
            let mut counted = BufReader::new(hashing);
            {
                let stream = decompress(&mut counted)
                    .map_err(|e| OsError::image(label, format!("layer {}: {e}", layer.name)))?;
                fs.apply_layer(i, stream, want)
                    .map_err(|e| OsError::image(label, format!("layer {}: {e}", layer.name)))?;
            }
            // The digest covers the whole blob, including what follows the tar's end.
            io::copy(&mut counted, &mut io::sink())
                .map_err(|e| OsError::image(label, format!("layer {}: {e}", layer.name)))?;
        }
        if let Some(digest) = layer.digest.as_deref() {
            if let Some(expected) = digest.strip_prefix("sha256:") {
                let got: String = hasher
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                if !got.eq_ignore_ascii_case(expected) {
                    return Err(OsError::image(
                        label,
                        format!("layer {} does not match its digest", layer.name),
                    ));
                }
            }
        }
        fs.layers = i + 1;
    }
    Ok(fs)
}

/// A root filesystem directory: walked without following symlinks.
fn open_rootfs(root: &Path, want: &dyn Fn(&str) -> bool) -> Result<ImageFs, OsError> {
    let mut fs = ImageFs {
        layers: 1,
        ..ImageFs::default()
    };
    let walk = walkdir::WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .sort_by_file_name()
        .into_iter()
        // Kernel filesystems of a live root are not part of the image.
        .filter_entry(|e| {
            !(e.depth() == 1
                && e.file_type().is_dir()
                && matches!(e.file_name().to_str(), Some("proc" | "sys" | "dev")))
        });
    for entry in walk {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                let at = e
                    .path()
                    .and_then(|p| p.strip_prefix(root).ok())
                    .map_or_else(String::new, |p| p.display().to_string());
                fs.skipped.push(format!("{at}: {e}"));
                continue;
            }
        };
        let Some(rel) = entry
            .path()
            .strip_prefix(root)
            .ok()
            .and_then(|p| p.to_str())
        else {
            continue;
        };
        let rel = rel.replace('\\', "/");
        let ft = entry.file_type();
        let node = if ft.is_symlink() {
            match std::fs::read_link(entry.path()) {
                Ok(t) => Node::Symlink(t.to_string_lossy().into_owned()),
                Err(e) => {
                    fs.skipped.push(format!("{rel}: {e}"));
                    continue;
                }
            }
        } else if ft.is_dir() {
            Node::Dir
        } else if ft.is_file() {
            if want(&rel) {
                match entry.metadata() {
                    Ok(md) if md.len() > MAX_FILE_BYTES => {
                        fs.skipped
                            .push(format!("{rel}: larger than {MAX_FILE_BYTES} bytes"));
                        Node::File(None)
                    }
                    _ => match std::fs::read(entry.path()) {
                        Ok(data) => Node::File(Some(Arc::new(data))),
                        Err(e) => {
                            fs.skipped.push(format!("{rel}: {e}"));
                            Node::File(None)
                        }
                    },
                }
            } else {
                Node::File(None)
            }
        } else {
            Node::Other
        };
        fs.apply(0, rel, node);
    }
    Ok(fs)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::tar::build::{tar, E};

    fn all(_: &str) -> bool {
        true
    }

    fn layered(layers: &[Vec<u8>]) -> ImageFs {
        let mut fs = ImageFs::default();
        for (i, l) in layers.iter().enumerate() {
            fs.apply_layer(i, l.as_slice(), &all).unwrap();
        }
        fs
    }

    #[test]
    fn whiteouts_delete_lower_layers_only() {
        let base = tar(&[
            E::Dir("app/"),
            E::File("app/package-lock.json", b"old"),
            E::File("app/keep", b"k"),
            E::Dir("var/lib/dpkg/"),
            E::File("var/lib/dpkg/status", b"s"),
        ]);
        let top = tar(&[
            E::File("app/.wh.package-lock.json", b""),
            E::File("var/lib/dpkg/.wh..wh..opq", b""),
            E::File("var/lib/dpkg/status", b"new"),
        ]);
        let fs = layered(&[base, top]);
        assert!(fs.read("app/package-lock.json").is_none());
        assert_eq!(fs.read("app/keep"), Some(&b"k"[..]));
        // The opaque marker empties the directory below, but the same layer's file stays.
        assert_eq!(fs.read("var/lib/dpkg/status"), Some(&b"new"[..]));
    }

    #[test]
    fn whiteout_of_a_directory_removes_its_tree() {
        let base = tar(&[E::Dir("opt/x/"), E::File("opt/x/Gemfile.lock", b"g")]);
        let top = tar(&[E::File("opt/.wh.x", b"")]);
        let fs = layered(&[base, top]);
        assert!(!fs.exists("opt/x/Gemfile.lock"));
        assert!(!fs.exists("opt/x"));
    }

    #[test]
    fn symlinks_resolve_through_directories_and_files() {
        let l = tar(&[
            E::Dir("usr/lib/"),
            E::File("usr/lib/os-release", b"ID=wolfi\n"),
            E::Symlink("etc/os-release", "../usr/lib/os-release"),
            E::Symlink("lib", "usr/lib"),
            E::Dir("usr/lib/apk/db/"),
            E::File("usr/lib/apk/db/installed", b"P:x\n"),
        ]);
        let fs = layered(&[l]);
        assert_eq!(fs.read("etc/os-release"), Some(&b"ID=wolfi\n"[..]));
        assert_eq!(fs.read("/lib/apk/db/installed"), Some(&b"P:x\n"[..]));
        assert_eq!(fs.canonical("lib/apk").as_deref(), Some("usr/lib/apk"));
    }

    #[test]
    fn symlink_loops_end() {
        let l = tar(&[E::Symlink("a", "b"), E::Symlink("b", "a")]);
        let fs = layered(&[l]);
        assert!(fs.read("a").is_none());
    }

    #[test]
    fn dotdot_paths_are_refused() {
        let l = tar(&[E::File("../../etc/passwd", b"x")]);
        let mut fs = ImageFs::default();
        assert!(fs.apply_layer(0, l.as_slice(), &all).is_err());
    }

    #[test]
    fn a_file_replacing_a_directory_drops_its_contents() {
        let base = tar(&[E::Dir("srv/"), E::File("srv/composer.lock", b"c")]);
        let top = tar(&[E::File("srv", b"now a file")]);
        let fs = layered(&[base, top]);
        assert!(!fs.exists("srv/composer.lock"));
        assert_eq!(fs.read("srv"), Some(&b"now a file"[..]));
    }

    #[test]
    fn unwanted_files_are_names_only_and_hardlinks_share_content() {
        let l = tar(&[
            E::File("big.bin", b"zzz"),
            E::File("etc/os-release", b"ID=alpine\n"),
            E::Hardlink("usr/lib/os-release", "etc/os-release"),
        ]);
        let mut fs = ImageFs::default();
        fs.apply_layer(0, l.as_slice(), &|p| p.ends_with("os-release"))
            .unwrap();
        assert!(fs.is_file("big.bin"));
        assert!(fs.read("big.bin").is_none());
        assert_eq!(fs.read("usr/lib/os-release"), Some(&b"ID=alpine\n"[..]));
    }

    #[test]
    fn docker_save_archive_with_digest_check() {
        let dir = std::env::temp_dir().join(format!("fr-os-img-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let layer = tar(&[E::File("etc/os-release", b"ID=debian\nVERSION_ID=\"12\"\n")]);
        let hex: String = Sha256::digest(&layer)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let manifest = format!(
            r#"[{{"Config":"c.json","RepoTags":["t:1"],"Layers":["blobs/sha256/{hex}"]}}]"#
        );
        let blob = format!("blobs/sha256/{hex}");
        let archive = tar(&[
            E::File("manifest.json", manifest.as_bytes()),
            E::File(&blob, &layer),
        ]);
        let path = dir.join("img.tar");
        std::fs::write(&path, &archive).unwrap();
        let fs = open(&path, &|p| p == "etc/os-release", None).unwrap();
        assert_eq!(fs.layers(), 1);
        assert!(fs.read("etc/os-release").unwrap().starts_with(b"ID=debian"));

        // Same archive, tampered layer: refused.
        let mut bad = layer.clone();
        bad[600] ^= 1;
        let archive = tar(&[
            E::File("manifest.json", manifest.as_bytes()),
            E::File(&blob, &bad),
        ]);
        std::fs::write(&path, &archive).unwrap();
        let err = open(&path, &|_| true, None).unwrap_err().to_string();
        assert!(err.contains("digest"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

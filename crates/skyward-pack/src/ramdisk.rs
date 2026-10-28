use anyhow::{bail, Context, Result};
use cpio::{NewcBuilder, NewcReader};
use std::io::{Cursor, Read, Write};
use std::process::{Command, Stdio};

/// One cpio entry with the metadata the kernel restores when it unpacks the
/// archive into rootfs.
#[derive(Clone)]
pub struct Entry {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub nlink: u32,
    pub dev: (u32, u32),
    pub rdev: (u32, u32),
    pub data: Vec<u8>,
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// An initramfs held in memory, so entries keep their owners, modes and
/// device numbers exactly as the archive had them.
/// How the initramfs is compressed. A recovery for an old phone carries it
/// with gzip, as the stock one did, because that kernel reads no LZ4 framing;
/// a GKI phone's boot ramdisk is LZ4 legacy framed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Gzip,
    Lz4,
}

pub struct Ramdisk {
    pub entries: Vec<Entry>,
    pub compression: Compression,
}

impl Ramdisk {
    /// Unpack an LZ4 (legacy framing) compressed newc archive, as Android
    /// boot images carry.
    pub fn decode(compressed: &[u8]) -> Result<Self> {
        let mut cpio = Vec::new();
        let compression = match compressed.get(..2) {
            Some([0x1f, 0x8b]) => {
                flate2::read::GzDecoder::new(compressed).read_to_end(&mut cpio).context("gzip decode")?;
                Compression::Gzip
            }
            _ => {
                lz4_flex::frame::FrameDecoder::new(compressed).read_to_end(&mut cpio).context("lz4 decode")?;
                Compression::Lz4
            }
        };
        let mut entries = Vec::new();
        let mut rest = Cursor::new(cpio.as_slice());
        loop {
            let mut r = NewcReader::new(rest).context("cpio entry")?;
            if r.entry().is_trailer() {
                break;
            }
            let e = r.entry();
            let mut entry = Entry {
                name: e.name().to_string(),
                mode: e.mode(),
                uid: e.uid(),
                gid: e.gid(),
                mtime: e.mtime(),
                nlink: e.nlink(),
                dev: (e.dev_major(), e.dev_minor()),
                rdev: (e.rdev_major(), e.rdev_minor()),
                data: Vec::with_capacity(e.file_size() as usize),
            };
            r.read_to_end(&mut entry.data).with_context(|| format!("cpio data of {}", entry.name))?;
            entries.push(entry);
            rest = r.finish().context("cpio entry end")?;
        }
        Ok(Ramdisk { entries, compression })
    }

    /// Pack as a newc archive compressed the way AOSP packs boot ramdisks,
    /// with the reference `lz4` tool in legacy framing (the kernel's initramfs
    /// unpacker reads no other LZ4 framing).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut cpio = Vec::new();
        for (ino, e) in self.entries.iter().enumerate() {
            let size = u32::try_from(e.data.len()).with_context(|| format!("{} is too large", e.name))?;
            let mut w = NewcBuilder::new(&e.name)
                .ino(300_000 + ino as u32)
                .mode(e.mode)
                .uid(e.uid)
                .gid(e.gid)
                .mtime(e.mtime)
                .nlink(e.nlink)
                .dev_major(e.dev.0)
                .dev_minor(e.dev.1)
                .rdev_major(e.rdev.0)
                .rdev_minor(e.rdev.1)
                .write(&mut cpio, size);
            w.write_all(&e.data)?;
            w.finish()?;
        }
        cpio::newc::trailer(&mut cpio)?;
        match self.compression {
            Compression::Lz4 => lz4_legacy(&cpio),
            Compression::Gzip => {
                let mut out = Vec::new();
                let mut encoder = flate2::write::GzEncoder::new(&mut out, flate2::Compression::best());
                encoder.write_all(&cpio).context("gzip encode")?;
                encoder.finish().context("gzip encode")?;
                Ok(out)
            }
        }
    }

    pub fn find(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Replace a regular file's contents, keeping its owner and mode.
    pub fn replace(&mut self, name: &str, data: Vec<u8>) -> Result<()> {
        match self.entries.iter_mut().find(|e| e.name == name) {
            Some(e) if e.mode & S_IFMT == S_IFREG => {
                e.data = data;
                Ok(())
            }
            Some(_) => bail!("{name} is not a regular file"),
            None => bail!("{name} is not in the ramdisk"),
        }
    }

    /// Add a root-owned regular file, creating missing parent directories.
    pub fn add(&mut self, name: &str, mode: u32, data: Vec<u8>) -> Result<()> {
        if self.find(name).is_some() {
            bail!("{name} is already in the ramdisk");
        }
        let parts: Vec<&str> = name.split('/').collect();
        let mut parent = String::new();
        for part in &parts[..parts.len() - 1] {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(part);
            match self.find(&parent) {
                Some(e) if e.is_dir() => {}
                Some(_) => bail!("{parent} is not a directory"),
                None => self.entries.push(root_entry(&parent, S_IFDIR | 0o755, Vec::new())),
            }
        }
        self.entries.push(root_entry(name, S_IFREG | mode, data));
        Ok(())
    }
}

fn root_entry(name: &str, mode: u32, data: Vec<u8>) -> Entry {
    let nlink = if mode & S_IFMT == S_IFDIR { 2 } else { 1 };
    Entry { name: name.to_string(), mode, uid: 0, gid: 0, mtime: 0, nlink, dev: (0, 0), rdev: (0, 0), data }
}

fn lz4_legacy(input: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new("lz4")
        .args(["-l", "-12", "--favor-decSpeed", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("run lz4 (install it, e.g. `brew install lz4`)")?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let out = child.wait_with_output().context("lz4")?;
    writer.join().expect("lz4 writer thread").context("feed lz4")?;
    if !out.status.success() {
        bail!("lz4 exited with {}", out.status);
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_metadata() {
        let mut rd = Ramdisk { entries: Vec::new(), compression: Compression::Lz4 };
        rd.add("system/bin/recovery", 0o750, b"binary".to_vec()).unwrap();
        rd.entries.push(Entry {
            name: "dev/console".into(),
            mode: 0o020600,
            uid: 0,
            gid: 0,
            mtime: 0,
            nlink: 1,
            dev: (0, 0),
            rdev: (5, 1),
            data: Vec::new(),
        });
        let back = Ramdisk::decode(&rd.encode().unwrap()).unwrap();
        let names: Vec<&str> = back.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["system", "system/bin", "system/bin/recovery", "dev/console"]);
        let bin = back.find("system/bin/recovery").unwrap();
        assert_eq!((bin.mode, bin.data.as_slice()), (S_IFREG | 0o750, b"binary".as_slice()));
        assert_eq!(back.find("dev/console").unwrap().rdev, (5, 1));
        assert!(rd.add("system/bin/recovery", 0o644, Vec::new()).is_err());
    }
}

use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV3};
use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::Path;

const PAGE: usize = 4096;
/// Byte offsets of the fields this crate patches in a version 1/2 header.
const OFF_KERNEL_SIZE: usize = 8;
const OFF_RAMDISK_SIZE: usize = 16;
const OFF_SECOND_SIZE: usize = 24;
const OFF_PAGE_SIZE: usize = 36;
const OFF_HEADER_VERSION: usize = 40;
const OFF_DTBO_SIZE: usize = 1632;
const OFF_DTBO_OFFSET: usize = 1636;
const OFF_DTB_SIZE: usize = 1648;
const OFF_CMDLINE: usize = 64;
const CMDLINE_LEN: usize = 512;
const FDT_MAGIC: &[u8; 4] = b"\xd0\x0d\xfe\xed";

/// The parts of a version 1/2 image this crate keeps: the header page as it
/// was written, and the two device-tree sections that follow the ramdisk.
struct Legacy {
    header_page: Vec<u8>,
    dtbo: Vec<u8>,
    dtb: Vec<u8>,
    /// How far past the recovery dtbo the stock build put its dtb; kept so the
    /// rebuilt image lays the two out the way the bootloader expects.
    dtb_gap: usize,
}

/// A boot image split into its header, kernel and ramdisk.
pub struct BootImage {
    /// Set for a version 3 or 4 image.
    pub header: Option<HeaderV3>,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    legacy: Option<Legacy>,
}

fn section(bytes: &[u8], at: usize, len: usize, what: &str) -> Result<Vec<u8>> {
    let end = at + len;
    bytes.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

fn align(len: usize, page: usize) -> usize {
    len.div_ceil(page) * page
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    let raw = bytes.get(at..at + 4).ok_or_else(|| anyhow!("header ends before {at}"))?;
    Ok(u32::from_le_bytes(raw.try_into().expect("four bytes")))
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    let raw = bytes.get(at..at + 8).ok_or_else(|| anyhow!("header ends before {at}"))?;
    Ok(u64::from_le_bytes(raw.try_into().expect("eight bytes")))
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let version = u32_at(&bytes, OFF_HEADER_VERSION)?;
        if version <= 2 {
            return Self::read_legacy(&bytes, version);
        }
        let header = match Header::parse(&mut Cursor::new(&bytes)).with_context(|| format!("{}: header", path.display()))? {
            Header::V3(h) => h,
            Header::V0(h) => bail!("{}: header version {}", path.display(), h.header_version()),
        };
        let kernel = section(&bytes, HeaderV3::kernel_position(), header.kernel_size as usize, "kernel")?;
        let ramdisk = section(&bytes, header.ramdisk_position(), header.ramdisk_size as usize, "ramdisk")?;
        Ok(BootImage { header: Some(header), kernel, ramdisk, legacy: None })
    }

    /// A version 0/1/2 image, as a phone with its own recovery partition and no
    /// vendor_boot carries: kernel, ramdisk, the recovery dtbo and the dtb in
    /// one partition, located by the header's own fields.
    fn read_legacy(bytes: &[u8], version: u32) -> Result<Self> {
        let page = u32_at(bytes, OFF_PAGE_SIZE)? as usize;
        if page == 0 || !page.is_power_of_two() {
            bail!("header version {version} names a page size of {page}");
        }
        let kernel_size = u32_at(bytes, OFF_KERNEL_SIZE)? as usize;
        let ramdisk_size = u32_at(bytes, OFF_RAMDISK_SIZE)? as usize;
        let second_size = u32_at(bytes, OFF_SECOND_SIZE)? as usize;
        let kernel_at = page;
        let ramdisk_at = kernel_at + align(kernel_size, page);
        let second_at = ramdisk_at + align(ramdisk_size, page);

        let dtbo_size = u32_at(bytes, OFF_DTBO_SIZE)? as usize;
        let dtbo_field = u64_at(bytes, OFF_DTBO_OFFSET)? as usize;
        let dtbo_at = if dtbo_field != 0 { dtbo_field } else { second_at + align(second_size, page) };

        let kernel = section(bytes, kernel_at, kernel_size, "kernel")?;
        let ramdisk = section(bytes, ramdisk_at, ramdisk_size, "ramdisk")?;
        let dtbo = if dtbo_size > 0 { section(bytes, dtbo_at, dtbo_size, "recovery dtbo")? } else { Vec::new() };

        // The dtb follows the dtbo; where exactly is the stock build's choice,
        // so measure the gap it used and keep it.
        // The device tree blob is a whole section of its own, as long as the
        // header says: several DTBs for the panel and hardware variants, not
        // the first one's own length.
        let dtb_size = u32_at(bytes, OFF_DTB_SIZE).unwrap_or(0) as usize;
        let (dtb, dtb_gap) = {
            let from = dtbo_at + dtbo_size;
            let magic_at = (from..bytes.len().saturating_sub(8))
                .find(|&i| bytes.get(i..i + 4) == Some(FDT_MAGIC));
            match magic_at {
                Some(at) if dtb_size > 0 && at + dtb_size <= bytes.len() => (section(bytes, at, dtb_size, "dtb")?, at - from),
                _ => (Vec::new(), 0),
            }
        };

        let header_page = bytes.get(..page).ok_or_else(|| anyhow!("image is shorter than one page"))?.to_vec();
        Ok(BootImage {
            header: None,
            kernel,
            ramdisk,
            legacy: Some(Legacy { header_page, dtbo, dtb, dtb_gap }),
        })
    }

    /// Take the kernel and the device trees from `other`, keeping this
    /// image's ramdisk: a phone's own build carries the kernel that reads the
    /// filesystems its system is packed in, which the stock recovery's does
    /// not on a ported ROM.
    pub fn adopt_kernel(&mut self, other: BootImage) {
        self.kernel = other.kernel;
        if let (Some(mine), Some(theirs)) = (self.legacy.as_mut(), other.legacy.as_ref()) {
            mine.dtbo = theirs.dtbo.clone();
            mine.dtb = theirs.dtb.clone();
            mine.dtb_gap = theirs.dtb_gap;
            // The boot parameters a kernel is built for travel with it: the
            // stock recovery's name buildvariant=user and leave the recovery
            // enforcing, where a phone's own build names permissive and eng.
            let (from, to) = (OFF_CMDLINE, OFF_CMDLINE + CMDLINE_LEN);
            if theirs.header_page[from..to].iter().any(|b| *b != 0) {
                mine.header_page[from..to].copy_from_slice(&theirs.header_page[from..to]);
            }
        }
    }

    /// Leave this image's boot parameters out of what is taken from it: the
    /// kernel comes without the ones its own build named.
    pub fn forget_cmdline(&mut self) {
        if let Some(legacy) = self.legacy.as_mut() {
            legacy.header_page[OFF_CMDLINE..OFF_CMDLINE + CMDLINE_LEN].fill(0);
        }
    }

    /// The image with sizes taken from its parts.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match &self.legacy {
            Some(legacy) => self.to_bytes_legacy(legacy),
            None => self.to_bytes_v3(),
        }
    }

    fn to_bytes_legacy(&self, legacy: &Legacy) -> Result<Vec<u8>> {
        let page = u32_at(&legacy.header_page, OFF_PAGE_SIZE)? as usize;
        let mut page_bytes = legacy.header_page.clone();
        let put32 = |at: usize, value: usize, buf: &mut Vec<u8>| -> Result<()> {
            let v = u32::try_from(value).context("field does not fit 32 bits")?;
            buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
            Ok(())
        };
        put32(OFF_KERNEL_SIZE, self.kernel.len(), &mut page_bytes)?;
        put32(OFF_RAMDISK_SIZE, self.ramdisk.len(), &mut page_bytes)?;
        put32(OFF_SECOND_SIZE, 0, &mut page_bytes)?;
        put32(OFF_DTBO_SIZE, legacy.dtbo.len(), &mut page_bytes)?;
        put32(OFF_DTB_SIZE, legacy.dtb.len(), &mut page_bytes)?;

        let mut out = page_bytes;
        out.resize(align(out.len(), page), 0);
        out.extend_from_slice(&self.kernel);
        out.resize(align(out.len(), page), 0);
        out.extend_from_slice(&self.ramdisk);
        out.resize(align(out.len(), page), 0);
        let dtbo_at = out.len();
        out.extend_from_slice(&legacy.dtbo);
        out.resize(dtbo_at + legacy.dtbo.len() + legacy.dtb_gap, 0);
        out.extend_from_slice(&legacy.dtb);
        out.resize(align(out.len(), page), 0);

        // The header names where the dtbo sits, which the layout above moved.
        let at = u32::try_from(dtbo_at).context("dtbo offset")? as u64;
        out[OFF_DTBO_OFFSET..OFF_DTBO_OFFSET + 8].copy_from_slice(&at.to_le_bytes());
        Ok(out)
    }

    fn to_bytes_v3(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone().ok_or_else(|| anyhow!("not a version 3 or 4 image"))?;
        header.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
        header.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
        header.v4_signature_size = header.v4_signature_size.map(|_| 0);
        let mut out = Vec::new();
        Header::V3(header).write(&mut out).context("write header")?;
        out.resize(align(out.len(), PAGE), 0);
        out.extend_from_slice(&self.kernel);
        out.resize(align(out.len(), PAGE), 0);
        out.extend_from_slice(&self.ramdisk);
        out.resize(align(out.len(), PAGE), 0);
        Ok(out)
    }
}

//! Turning off what the bootloader checks before it starts anything. The
//! check reads a vbmeta image out of a partition of its own, and that image
//! says whether the partitions are verified at all: one written with both
//! flags set tells the bootloader to look at none of them, which is what
//! `fastboot --disable-verity --disable-verification` leaves behind.

use anyhow::{Context, Result};
use std::path::Path;

/// The unit a vbmeta image is laid out in, which is all a partition of it
/// needs: the header, and no descriptor, signature or key after it.
const BLOCK: usize = 4096;
const HEADER_LEN: usize = 256;

/// What the header calls the libavb version it needs.
const VERSION: [u32; 2] = [1, 0];

/// The two flags: the hash tree is not verified, and neither is anything
/// else.
const HASHTREE_DISABLED: u32 = 1 << 0;
const VERIFICATION_DISABLED: u32 = 1 << 1;

/// What the header credits itself to, as avbtool writes its own name there.
const RELEASE: &[u8] = b"skyward";

/// The partitions holding a vbmeta image of their own, which the bootloader
/// reads one after another.
const PARTITIONS: [&str; 3] = ["vbmeta", "vbmeta_system", "vbmeta_vendor"];

/// A vbmeta image that no partition is verified by: a header with no
/// descriptor, no key and no signature, and flags that say so.
pub fn disabled() -> Vec<u8> {
    let mut image = Vec::with_capacity(BLOCK);
    image.extend_from_slice(b"AVB0");
    for word in VERSION {
        image.extend_from_slice(&word.to_be_bytes());
    }
    // The two block sizes: the one holding the authentication block, which
    // there is none of, and the one holding the auxiliary block, which holds
    // no descriptor.
    image.extend_from_slice(&(HEADER_LEN as u64).to_be_bytes());
    image.extend_from_slice(&0u64.to_be_bytes());
    // No signing algorithm.
    image.extend_from_slice(&0u32.to_be_bytes());
    // The offsets and sizes of the hash, the signature, the public key, its
    // metadata and the descriptors: all empty.
    for _ in 0..11 {
        image.extend_from_slice(&0u64.to_be_bytes());
    }
    // The flags, which are the point of the image, then where the rollback
    // index is kept.
    image.extend_from_slice(&(HASHTREE_DISABLED | VERIFICATION_DISABLED).to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(RELEASE);
    image.resize(BLOCK, 0);
    image
}

/// Write that image into every partition of the phone that holds one, and
/// say which were written.
pub fn disable() -> Result<Vec<&'static str>> {
    let dir = Path::new(skyward_block::BY_NAME);
    let image = disabled();
    let mut written = Vec::new();
    let mut no_partition = true;
    for name in PARTITIONS {
        let path = dir.join(name);
        if !path.exists() {
            continue;
        }
        no_partition = false;
        std::fs::write(&path, &image).with_context(|| format!("write the vbmeta image into {name}"))?;
        written.push(name);
    }
    if no_partition {
        anyhow::bail!("the phone has no vbmeta partition to write");
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_says_no_partition_is_checked() {
        let image = disabled();
        assert_eq!(&image[..4], b"AVB0");
        assert_eq!(image.len(), BLOCK);
        // The flags sit at the end of the header's first four words of the
        // auxiliary block's description, after the eleven offsets.
        let flags = u32::from_be_bytes(image[120..124].try_into().expect("four bytes"));
        assert_eq!(flags, 3);
    }

    #[test]
    fn no_descriptor_is_written() {
        let image = disabled();
        assert!(image[HEADER_LEN..].iter().all(|&b| b == 0), "the auxiliary block is empty");
    }
}

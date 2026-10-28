//! The phone's key service of the older kind, which a phone whose secure
//! world speaks the hardware interface reaches over the other driver. The
//! newer kind, which this recovery uses where a phone has it, is in
//! [`crate::keymint`]; a phone that has only this one needs it before a
//! partition holding encrypted files can be read.
//!
//! Nothing here derives a key yet: what it does is the check that the older
//! kind answers at all, and what it says about itself.

// The calls and answers serve the phone's own driver and the host tests.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{Context, Result};
use skyward_binder::hidl::{self, Answer, Message};

/// The key service of the older kind, by the name it registers under.
pub const SERVICE: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";
const INSTANCE: &str = "default";

/// The method that tells how the secure world is built, as this kind
/// numbers its methods: the first one it declares.
const GET_HARDWARE_INFO: u32 = 1;

/// How much a hardware information answer holds before its names.
const INFORMATION_BYTES: usize = 4;

/// The phone's key service, as this program talks to it.
pub struct Keymaster<'a>(skyward_binder::driver::Handle<'a>);

impl<'a> Keymaster<'a> {
    /// Reach the running key service of the older kind through `hardware`.
    pub fn open(hardware: &'a skyward_binder::driver::Binder) -> Result<Keymaster<'a>> {
        let handle = hidl::find(hardware, SERVICE, INSTANCE)?.with_context(|| {
            format!("{SERVICE} is not running; the phone's key service has to be started first")
        })?;
        Ok(Keymaster(handle))
    }

    /// What the service says it serves, which changes nothing and needs no
    /// key: the call to make to see that it answers.
    pub fn serves(&self) -> Result<String> {
        hidl::describes(&self.0)
    }

    /// How the secure world is built, and what it calls itself: the whole
    /// of what this kind answers without a key.
    pub fn hardware_info(&self) -> Result<Information> {
        let reply = self
            .0
            .transact(GET_HARDWARE_INFO, &Message::call(SERVICE))
            .context("ask the key service how the secure world is built")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("ask the key service how the secure world is built")?;
        let level = read.i32().context("read the security level the key service reports")?;
        let name = read.pointed().context("read what the key service calls itself")?;
        let author = read.pointed().context("read who the key service credits")?;
        Ok(Information {
            level,
            name: text(name),
            author: text(author),
        })
    }
}

/// How the secure world is built, by the number the older kind gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Information {
    pub level: i32,
    pub name: String,
    pub author: String,
}

/// A name as the older kind hands it over: its bytes, with the ending that
/// marks where it stops.
fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// What a security level means, by its number.
pub fn level_name(level: i32) -> &'static str {
    match level {
        0 => "software",
        1 => "trusted environment",
        2 => "strong box",
        _ => "a level this recovery does not know",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_stops_where_the_ending_is() {
        assert_eq!(text(b"trusty\0rest"), "trusty");
        assert_eq!(text(b"trusty"), "trusty");
    }

    #[test]
    fn the_levels_are_named() {
        assert_eq!(level_name(1), "trusted environment");
        assert_eq!(level_name(9), "a level this recovery does not know");
    }

    #[test]
    fn the_information_is_as_long_as_its_level() {
        assert_eq!(INFORMATION_BYTES, 4);
    }
}

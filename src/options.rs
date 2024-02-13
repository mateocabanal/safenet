use crate::frame::{EncryptionType, FrameType, InitOptions};
use crate::APPSTATE;
use std::collections::HashMap;
use std::net::SocketAddr;
use thiserror::Error;

/// Metadata carried in every frame.
/// The metadata does not have a known size,
/// so it can vary in size.
/// Options are required to be sent in the frame.
/// As of now, options are not encrypted. However, options are planned to be encrypted.
#[derive(Debug, Clone, PartialEq)]
pub struct Options {
    pub(crate) frame_type: FrameType,
    pub(crate) ip_addr: Option<SocketAddr>,
    pub(crate) init_opts: Option<InitOptions>,
    pub(crate) map: HashMap<String, String>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            frame_type: FrameType::Data,
            ip_addr: APPSTATE
                .get()
                .unwrap()
                .read()
                .expect("could not acquire read handle on appstate")
                .server_addr,
            init_opts: None,
            map: HashMap::new(),
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Options {
    fn into(self) -> Vec<u8> {
        let header_as_string = format!("frame_type = {}\u{00ae}", self.frame_type as u8);
        let ip_addr_as_string = if let Some(addr) = self.ip_addr {
            format!("ip_addr = {}\u{00ae}", addr)
        } else {
            "".to_string()
        };

        let custom_headers = self
            .map
            .into_iter()
            .fold(String::new(), |mut output, (k, v)| {
                output += format!("{k} = {v}\u{00ae}").as_str();
                output
            });

        if self.frame_type == FrameType::Init {
            [
                header_as_string.into_bytes(),
                ip_addr_as_string.into_bytes(),
                self.init_opts.unwrap().into(),
                custom_headers.into_bytes(),
            ]
            .concat()
        } else {
            [
                header_as_string.into_bytes(),
                ip_addr_as_string.into_bytes(),
                custom_headers.into_bytes(),
            ]
            .concat()
        }
    }
}

// NOTE: What a mess...
// This has to be cleaned up
impl TryFrom<&[u8]> for Options {
    type Error = Box<dyn std::error::Error>;
    fn try_from(options_bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut current_opt_index = 0usize;
        let mut options_map = HashMap::new();

        log::trace!("options bytes: {:?}\x1b[38;2;108;190;237m", options_bytes);

        log::trace!(
            "\x1b[38;2;238;171;196mBEGIN OPTION PARSING LOOP!\x1b[1;0m\x1b[38;2;108;190;237m"
        );
        while let Some(option_slice) = options_bytes[current_opt_index..]
            .iter()
            .enumerate()
            .find(|(_, ascii_code)| **ascii_code == 174)
            .map(|(index, _)| &options_bytes[current_opt_index..current_opt_index + index])
        {
            //            log::trace!("\x1b[38;2;108;190;237m");
            #[cfg(test)]
            println!(
                "length of option, current_opt_index: {:?}, {}",
                option_slice, current_opt_index
            );

            let equal_sign_pos = option_slice
                .iter()
                .position(|ascii_code| *ascii_code == 61)
                .ok_or("could not find '=' in option")?;
            let header_key = &option_slice[..equal_sign_pos];
            let header_value = &option_slice[equal_sign_pos + 1..option_slice.len() - 1];

            let header_key_str = std::str::from_utf8(header_key)?.trim().to_string();

            let header_value_str = std::str::from_utf8(header_value)?.trim().to_string();

            log::trace!("header: {header_key_str} = {header_value_str}");

            options_map.insert(header_key_str, header_value_str);

            current_opt_index += option_slice.len() + 1;
        }
        log::trace!("\x1b[1;0m\x1b[38;2;238;171;196mEND OF OPTION PARSING LOOP!\x1b[1;0m\n");

        let frame_type = match options_map
            .get("frame_type")
            .ok_or(OptionError::MissingOpt("frame_type"))?
            .parse::<u8>()?
        {
            0 => FrameType::Init,
            1 => FrameType::Data,
            2u8..=u8::MAX => return Err("frame_type out of bounds".into()),
        };

        let init_opts = if frame_type == FrameType::Init {
            let enc_type = match options_map
                .get("encryption_type")
                .ok_or(OptionError::MissingOpt("encryption_type"))?
                .parse::<u8>()?
            {
                0 => EncryptionType::Legacy,
                1 => EncryptionType::Kyber,
                2 => EncryptionType::KyberDith,
                3u8..=u8::MAX => return Err("enc_type out of bounds".into()),
            };

            let status = options_map.get("status");

            // If not defined, it is off
            let nonce_secondary_key = options_map
                .get("nonce_secondary_key")
                .unwrap_or(&String::from("0"))
                .parse::<u8>()?;
            Some(
                InitOptions::new_with_enc_type(enc_type)
                    .status(status.unwrap_or(&String::from("0")).parse::<u8>()?)
                    .nonce_secondary_key(nonce_secondary_key == 1),
            )
        } else {
            None
        };
        let options = Options {
            frame_type,
            ip_addr: if let Some(ip_addr_str) = options_map.get("ip_addr") {
                if let Ok(ip_socket_addr) = ip_addr_str.parse::<SocketAddr>() {
                    Some(ip_socket_addr)
                } else {
                    None
                }
            } else {
                None
            },
            init_opts,
            map: options_map,
        };

        Ok(options)
    }
}

/// Options that might be present in any frame
impl Options {
    pub fn get_frame_type(&self) -> FrameType {
        self.frame_type
    }

    pub fn get_ip_addr(&self) -> Option<SocketAddr> {
        self.ip_addr
    }

    pub fn get_init_opts(&self) -> Option<InitOptions> {
        self.init_opts
    }

    pub fn get_map(&mut self) -> &mut HashMap<String, String> {
        &mut self.map
    }
}

#[derive(Debug, Error)]
pub enum OptionError<'a> {
    #[error("Missing option: {}", .0)]
    MissingOpt(&'a str),
}


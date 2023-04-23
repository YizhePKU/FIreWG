use alloc::{format, string::String};
use base64::Engine;
use boringtun::Tunn;

/// Decodes a base64-encoded string into 32 bytes of data.
fn decode_key(base64: &str) -> Result<[u8; 32], &'static str> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut buf = [0; 40]; // need a buffer slightly larger than 32 for decoding
    match b64.decode_slice(base64, &mut buf) {
        Ok(len) => {
            if len != 32 {
                Err("Data not 32 bytes")
            } else {
                // take the first 32 bytes of buf
                let data = <[u8; 32]>::try_from(&buf[..32]).unwrap();
                Ok(data)
            }
        }
        Err(_) => Err("Base64 string too long"),
    }
}

/// Create a point-to-point tunnel with a peer.
///
/// [`privkey`] is the base64-encoded private key of the local interface.
/// [`pubkey`] is the base64-encoded public key of the peer.
/// [`peer_id`] is a unique integer for the peer.
///
/// Typical usage is multiple [`Tunn`] instances with the same [`privkey`],
/// different [`pubkey`], and an incrementing [`peer_id`].
///
/// # Panics
///
/// Panic if [`peer_id`] cannot fit in a 24 bytes integer (which is 16M active peers).
/// Panic if [`privkey`] or [`pubkey`] is not base64-encoded 32 bytes of data.
///
/// NOTE: 64-bit Windows kernel has a default stack size of 24KB, which is not enough for Tunn::new().
/// Calling rsInit() with KeExpandKernelStackAndCalloutEx increases the stack size to about 70KB,
/// barely enough for a release build with optimizations.
pub fn make_tunn(privkey: &str, pubkey: &str, peer_id: u32) -> Tunn {
    if peer_id & 0xffffff != peer_id {
        panic!("Only 2^24 peers are supported at a time");
    }

    let static_private = x25519_dalek::StaticSecret::from(decode_key(privkey).unwrap());
    let peer_static_public = x25519_dalek::PublicKey::from(decode_key(pubkey).unwrap());
    // TODO: support persistent keepalive
    // The first 24 bits of index are used to identify a peer, and the rest 8 bits are for session rotations
    let tunn = Tunn::new(
        static_private,
        peer_static_public,
        None,
        None,
        peer_id << 8,
        None,
    )
    .unwrap();
    return tunn;
}

pub fn fmt_addr(addr: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

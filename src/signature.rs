use digest::MacError;
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn get_mac(secret: &[u8]) -> Hmac::<Sha256> {
    Hmac::<Sha256>::new_from_slice(secret)
        .expect("HMAC can take key of any size")
}

pub fn make_signature(bytes: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut mac = get_mac(secret);
    mac.update(bytes);
    let result = mac.finalize();
    result.into_bytes().to_vec()
}

pub fn verify_signature(
    bytes: &[u8],
    secret: &[u8],
    sig: &[u8]
) -> Result<(), MacError> {
    let mut mac = get_mac(secret);
    mac.update(bytes);
    mac.verify_slice(sig)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn signature_round_trip() {
        let bytes = b"abcde";
        let secret = b"12345";
        let sig = make_signature(bytes, secret);
        assert_eq!(verify_signature(bytes, secret, &sig).unwrap(), ());
    }

    #[test]
    fn verify_signature_error() {
        let bytes = b"abcde";
        let secret = b"12345";
        let sig = make_signature(bytes, secret);
        assert!(
            matches!(
                // truncate the signature to ensure mismatch
                verify_signature(bytes, secret, &sig[1..]).unwrap_err(),
                MacError
            )
        );
    }
}

use chacha20::{ChaCha20, cipher::NewStreamCipher};
use p256::{EncodedPoint, NistP256, ecdh::EphemeralSecret, elliptic_curve::{Curve, generic_array::typenum::Unsigned, sec1::UncompressedPointSize}};

mod client;
mod errors;

fn main() {
    println!("{}", <<ChaCha20 as NewStreamCipher>::KeySize as Unsigned>::USIZE);
    println!("{}", <<NistP256 as Curve>::FieldSize as Unsigned>::USIZE);
}

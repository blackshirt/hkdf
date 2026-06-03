module hkdf

import crypto
import encoding.hex

fn test_hkdf_derive_0() ! {
	// Basic test case with SHA-256

	// Hash = SHA-256
	// IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
	ikm := hex.decode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')!
	// salt = 0x000102030405060708090a0b0c (13 octets)
	salt := hex.decode('000102030405060708090a0b0c')!
	// info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
	info := hex.decode('f0f1f2f3f4f5f6f7f8f9')!
	// L    = 42
	length := 42

	// PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
	//       90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
	prk := hex.decode('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5')!
	okm :=
		hex.decode('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')!
	// OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
	//      2d2d0a90cf1a5a4c5db02d56ecc4c5bf
	//    34007208d5b887185865 (42 octets)

	h := new(crypto.Hash.sha256)!

	okmout := h.derive(salt, ikm, info, length)!
	assert okm == okmout
}

// Generated with https://www.lddgo.net/en/encrypt/hkdf
fn test_hkdf_derive_1() ! {
	// Digest alg: SHA3-384
	ikm := 'this is input keying material'.bytes()
	info := 'myinfo'.bytes()
	salt := 'my salt'.bytes()
	length := 32 // 256 / 8

	// derived key, with Skip Extract: No
	okm := '2ba9b938abf0c33c655e3e3c5623015cd13f76c196cc0e5af5f3b1880ac82998'

	d := new(.sha3_384)!
	out := d.derive(salt, ikm, info, length)!
	assert out.hex() == okm

	// test with skip extract yes:
	// out2 := d.expand(ikm, info, length)!
	// okm2 := 'bffe01d3a2b840ff1133c428a727ace40b7bcf6d21f955d51881a1071ef3832b'
	// assert out2.hex() == okm2 // True
}

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
	info := 'my info'.bytes()
	salt := 'my salt'.bytes()
	length := 32 // 256 / 8

	// derived key, with Skip Extract: No
	okm := '087d998a2b31a5826dede8d7baf81476f41ec9c1c8717c021ee457e806cccc0c'

	d := new(.sha3_384)!
	out := d.derive(salt, ikm, info, length)!
	assert out.hex() == okm

	// test with skip extract yes:
	// out2 := d.expand(ikm, info, length)!
	// okm2 := '24d3bf32f77c7bb3304900d58c671271ac9c319e8890089942d8dd91c444fcab'
	// assert out2.hex() == okm2 // True
}

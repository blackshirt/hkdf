module hkdf

import crypto
import encoding.hex

// see https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.1
fn test_hkdf_extract_expand_case_1() ! {
	// Basic test case with SHA-256

	// Hash = SHA-256
	// IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
	ikm := hex.decode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')!
	// salt = 0x000102030405060708090a0b0c (13 octets)
	salt := hex.decode('000102030405060708090a0b0c')!
	// info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
	info := hex.decode('f0f1f2f3f4f5f6f7f8f9')!
	// L    = 42
	l := 42

	// PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
	//       90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
	prk := hex.decode('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5')!
	okm := hex.decode('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')!
	// OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
	//      2d2d0a90cf1a5a4c5db02d56ecc4c5bf
	//    34007208d5b887185865 (42 octets)

	h := new(crypto.Hash.sha256)
	prkout := h.extract(salt, ikm)!

	assert prk == prkout

	okmout := h.expand(prkout, info, l)!
	assert okm == okmout
}

// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.2
fn test_hkdf_extract_expand_case_2() ! {
	/*
	Test with SHA-256 and longer inputs/outputs

   Hash = SHA-256
   IKM  = 0x000102030405060708090a0b0c0d0e0f
          101112131415161718191a1b1c1d1e1f
          202122232425262728292a2b2c2d2e2f
          303132333435363738393a3b3c3d3e3f
          404142434445464748494a4b4c4d4e4f (80 octets)
   salt = 0x606162636465666768696a6b6c6d6e6f
          707172737475767778797a7b7c7d7e7f
          808182838485868788898a8b8c8d8e8f
          909192939495969798999a9b9c9d9e9f
          a0a1a2a3a4a5a6a7a8a9aaabacadaeaf (80 octets)
   info = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
          c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
          d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
          e0e1e2e3e4e5e6e7e8e9eaebecedeeef
          f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff (80 octets)
   L    = 82

   PRK  = 0x06a6b88c5853361a06104c9ceb35b45c
          ef760014904671014a193f40c15fc244 (32 octets)
   OKM  = 0xb11e398dc80327a1c8e7f78c596a4934
          4f012eda2d4efad8a050cc4c19afa97c
          59045a99cac7827271cb41c65e590e09
          da3275600c2f09b8367793a9aca3db71
          cc30c58179ec3e87c14c01d5c1f3434f
          1d87 (82 octets)
	*/
	ikm := hex.decode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f')!

	salt := hex.decode('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf')!

	info := hex.decode('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')!

	l := 82

	prk := hex.decode('06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244')!
	okm := hex.decode('b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87')!

	h := new(crypto.Hash.sha256)
	prkout := h.extract(salt, ikm)!

	assert prk == prkout

	okmout := h.expand(prkout, info, l)!
	assert okm == okmout
}

// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.3
fn test_hkdf_extract_expand_case_3() ! {
	/*
	Test with SHA-256 and zero-length salt/info

   Hash = SHA-256
   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
   salt = (0 octets)
   info = (0 octets)
   L    = 42

   PRK  = 0x19ef24a32c717b167f33a91d6f648bdf
          96596776afdb6377ac434c1c293ccb04 (32 octets)
   OKM  = 0x8da4e775a563c18f715f802a063c5a31
          b8a11f5c5ee1879ec3454e5f3c738d2d
          9d201395faa4b61a96c8 (42 octets)
	*/
	ikm := hex.decode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')!

	salt := hex.decode('')!

	info := hex.decode('')!

	l := 42

	prk := hex.decode('19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04')!
	okm := hex.decode('8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8')!

	hasher := new(crypto.Hash.sha256)
	prkout := hasher.extract(salt, ikm)!

	assert prk == prkout

	okmout := hasher.expand(prkout, info, l)!
	assert okm == okmout
}

// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.4
fn test_hkdf_extract_expand_case_4() ! {
	/*
	Basic test case with SHA-1

   Hash = SHA-1
   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b (11 octets)
   salt = 0x000102030405060708090a0b0c (13 octets)
   info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
   L    = 42

   PRK  = 0x9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243 (20 octets)
   OKM  = 0x085a01ea1b10f36933068b56efa5ad81
          a4f14b822f5b091568a9cdd4f155fda2
          c22e422478d305f3f896 (42 octets)
	*/
	ikm := hex.decode('0b0b0b0b0b0b0b0b0b0b0b')!

	salt := hex.decode('000102030405060708090a0b0c')!

	info := hex.decode('f0f1f2f3f4f5f6f7f8f9')!

	l := 42

	prk := hex.decode('9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243')!
	okm := hex.decode('085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896')!

	kdf := new(crypto.Hash.sha1)
	prkout := kdf.extract(salt, ikm)!

	assert prk == prkout

	okmout := kdf.expand(prkout, info, l)!
	assert okm == okmout
}

// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.5
fn test_hkdf_extract_expand_case_5() ! {
	/*
	Test with SHA-1 and longer inputs/outputs

   Hash = SHA-1
   IKM  = 0x000102030405060708090a0b0c0d0e0f
          101112131415161718191a1b1c1d1e1f
          202122232425262728292a2b2c2d2e2f
          303132333435363738393a3b3c3d3e3f
          404142434445464748494a4b4c4d4e4f (80 octets)
   salt = 0x606162636465666768696a6b6c6d6e6f
          707172737475767778797a7b7c7d7e7f
          808182838485868788898a8b8c8d8e8f
          909192939495969798999a9b9c9d9e9f
          a0a1a2a3a4a5a6a7a8a9aaabacadaeaf (80 octets)
   info = 0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
          c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
          d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
          e0e1e2e3e4e5e6e7e8e9eaebecedeeef
          f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff (80 octets)
   L    = 82

   PRK  = 0x8adae09a2a307059478d309b26c4115a224cfaf6 (20 octets)
   OKM  = 0x0bd770a74d1160f7c9f12cd5912a06eb
          ff6adcae899d92191fe4305673ba2ffe
          8fa3f1a4e5ad79f3f334b3b202b2173c
          486ea37ce3d397ed034c7f9dfeb15c5e
          927336d0441f4c4300e2cff0d0900b52
          d3b4 (82 octets)
	*/
	ikm := hex.decode('0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f')!

	salt := hex.decode('0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf')!

	info := hex.decode('0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')!

	l := 82

	prk := hex.decode('0x8adae09a2a307059478d309b26c4115a224cfaf6')!
	okm := hex.decode('0x0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4')!

	hasher := new(crypto.Hash.sha1)
	prkout := hasher.extract(salt, ikm)!

	assert prk == prkout

	okmout := hasher.expand(prkout, info, l)!
	assert okm == okmout
}

// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.6
fn test_hkdf_extract_expand_case_6() ! {
	/*
	Test with SHA-1 and zero-length salt/info

   Hash = SHA-1
   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
   salt = (0 octets)
   info = (0 octets)
   L    = 42

   PRK  = 0xda8c8a73c7fa77288ec6f5e7c297786aa0d32d01 (20 octets)
   OKM  = 0x0ac1af7002b3d761d1e55298da9d0506
          b9ae52057220a306e07b6b87e8df21d0
          ea00033de03984d34918 (42 octets)
	*/
	ikm := hex.decode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')!

	salt := hex.decode('')!

	info := hex.decode('')!

	l := 42

	prk := hex.decode('da8c8a73c7fa77288ec6f5e7c297786aa0d32d01')!
	okm := hex.decode('0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918')!

	hasher := new(crypto.Hash.sha1)
	prkout := hasher.extract(salt, ikm)!

	assert prk == prkout

	okmout := hasher.expand(prkout, info, l)!
	assert okm == okmout
}

// https://datatracker.ietf.org/doc/html/rfc5869#appendix-A.7
fn test_hkdf_extract_expand_case_7() ! {
	/*
	Test with SHA-1, salt not provided (defaults to HashLen zero octets),
   zero-length info

   Hash = SHA-1
   IKM  = 0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c (22 octets)
   salt = not provided (defaults to HashLen zero octets)
   info = (0 octets)
   L    = 42

   PRK  = 0x2adccada18779e7c2077ad2eb19d3f3e731385dd (20 octets)
   OKM  = 0x2c91117204d745f3500d636a62f64f0a
          b3bae548aa53d423b0d1f27ebba6f5e5
          673a081d70cce7acfc48 (42 octets)
	*/
	ikm := hex.decode('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c')!

	salt := hex.decode('')!

	info := hex.decode('')!

	l := 42

	prk := hex.decode('2adccada18779e7c2077ad2eb19d3f3e731385dd')!
	okm := hex.decode('2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48')!

	hasher := new(crypto.Hash.sha1)
	prkout := hasher.extract(salt, ikm)!

	assert prk == prkout

	okmout := hasher.expand(prkout, info, l)!
	assert okm == okmout
}

const (
	keys = [
		[u8(0xb), 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb],
		'Jefe'.bytes(),
		[u8(0xAA), 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
			0xAA, 0xAA],
		[u8(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
			0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19],
		[u8(0x0c), 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
			0x0c, 0x0c],
		[u8(0xaa), 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa],
		[u8(0xaa), 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa],
	]
	data = ['Hi There'.bytes(), 'what do ya want for nothing?'.bytes(),
		[u8(0xDD), 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
			0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
			0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
			0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD],
		[u8(0xcd), 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
			0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
			0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
			0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd],
		'Test With Truncation'.bytes(), 'Test Using Larger Than Block-Size Key - Hash Key First'.bytes(),
		'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data'.bytes()]
)

fn test_hmac_new_sha256() {
	sha256_expected_results := [
		'492ce020fe2534a5789dc3848806c78f4f6711397f08e7e7a12ca5a4483c8aa6',
		'5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
		'7dda3cc169743a6484649f94f0eda0f9f2ff496a9733fb796ed5adb40a44c3c1',
		'82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b',
		'2282475faa2def6936685d9c06566f2d782307ace7a27ada2037e6285efcb008',
		'6953025ed96f0c09f80a96f78e6538dbe2e7b820e3dd970e7ddd39091b32352f',
		'6355ac22e890d0a3c8481a5ca4825bc884d3e7a1ff98a2fc2ac7d8e064c3b2e6',
	]
	// mut result := ''
	for i, key in hkdf.keys {
		h := new(crypto.Hash.sha256)

		out := h.hmac(key, hkdf.data[i])!
		result := out.hex()
		assert result == sha256_expected_results[i]
	}
}

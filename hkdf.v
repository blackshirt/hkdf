// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// This module implements HMAC-based Extract-and-Expand Key Derivation Function (HKDF) as defined in RFC 5869.
// HKDF is a cryptographic key derivation function (KDF) with the goal of expanding limited input
// keying material into one or more cryptographically strong secret keys.
module hkdf

import crypto
import crypto.hmac
import crypto.sha1
import crypto.sha256
import crypto.sha512

// Hkdf is a HMAC based Key Derivation Function backed by crypto.Hash
@[noinit]
pub struct Hkdf {
mut:
	// by default use .sha256 hash
	hash crypto.Hash = .sha256
}

// new creates a new instance of Hkdf with hash h
@[inline]
pub fn new(h crypto.Hash) &Hkdf {
	return &Hkdf{
		hash: h
	}
}

// expand expands pseudorandom key to build output keying material using underlying crypto.Hash
// prk was a pseudorandom key of at least HashLen octets (usually, the output from the extract step)
// info is optional context and application specific information (can be a zero-length string)
@[direct_array_access]
pub fn expand(h crypto.Hash, prk []u8, info []u8, length int) ![]u8 {
	k := new(h)
	return k.expand(prk, info, length)!
}

// Extract generates a pseudorandom key for use with Expand from an input secret and an optional independent salt.
@[direct_array_access]
pub fn extract(h crypto.Hash, salt []u8, ikm []u8) ![]u8 {
	k := new(h)
	return k.extract(salt, ikm)!
}

// hasher returns underlying crypto.Hash for current Hkdf k.
@[inline]
pub fn (k &Hkdf) hasher() crypto.Hash {
	return k.hash
}

// sum return sum of the data for Hkdf hash
@[direct_array_access]
pub fn (k &Hkdf) sum(data []u8) ![]u8 {
	match k.hash {
		.sha1 { return sha1.sum(data) }
		.sha256 { return sha256.sum256(data) }
		.sha384 { return sha512.sum384(data) }
		.sha512 { return sha512.sum512(data) }
		else { return error('unsupported sum hasher') }
	}
}

// size return size of the checksum underlying hash
@[inline]
pub fn (k &Hkdf) size() !int {
	match k.hash {
		.sha1 { return sha1.size }
		.sha256 { return sha256.size }
		.sha384 { return sha512.size384 }
		.sha512 { return sha512.size }
		else { return error('unsupported hash') }
	}
}

// hmac derives a new Keyed-Hash Message Authentication Code (HMAC) based
// on the supplied key and data with the underlying hkdf k.
pub fn (k &Hkdf) hmac(key []u8, data []u8) ![]u8 {
	return k.create_hmac(key, data)!
}

// create_hmac is internal routine to derive a new Keyed-Hash Message Authentication Code (HMAC)
// based on the supplied key and data with the underlying hkdf k.
@[direct_array_access; inline]
fn (k &Hkdf) create_hmac(key []u8, data []u8) ![]u8 {
	match k.hash {
		.sha1 {
			// NOTE: .sha1 is considerd as deprecated, use with care`!!!
			return hmac.new(key, data, sha1.sum, sha1.block_size)
		}
		.sha256 {
			return hmac.new(key, data, sha256.sum, sha256.block_size)
		}
		.sha384 {
			return hmac.new(key, data, sha512.sum384, sha512.block_size)
		}
		.sha512 {
			return hmac.new(key, data, sha512.sum512, sha512.block_size)
		}
		else {
			return error('unsupported hash')
		}
	}
}

// extract create pseudorandom key (prk) from input given. Its returns a hmac based hash with length (size)
// of Hashing checksum size
@[direct_array_access]
pub fn (k &Hkdf) extract(salt []u8, ikm []u8) ![]u8 {
	saltc := if salt.len == 0 {
		// use null hash.len bytes instead
		[]u8{len: k.size()!, init: u8(0x00)}
	} else {
		// non-null size salt, use original salt instead
		salt
	}
	// if ikm.len == 0, use hash.len zeros bytes
	ikmc := if ikm.len == 0 {
		// is it should to init to hash.len null arrays instead
		[]u8{len: k.size()!, init: u8(0x00)}
	} else {
		// use non-null length input key material
		ikm
	}
	return k.hmac(saltc, ikmc)!
}

// expand expands pseudorandom key to build output keying material.
// where length is the length of output keying material in octets (<= 255*HashLen)
// where HashLen denotes the length of the hash function output in octets
@[direct_array_access]
pub fn (k &Hkdf) expand(prk []u8, info []u8, length int) ![]u8 {
	hash_len := k.size()!
	if length > 255 * hash_len {
		return error('Cannot expand to more than 255 * ${hash_len}')
	}
	ceil := if length % hash_len == 0 { 0 } else { 1 }
	blk := length / hash_len + ceil
	mut okm := []u8{cap: length}
	mut ob := []u8{cap: blk}
	for i := 0; i < blk; i++ {
		ob << info
		ctr := i + 1
		ob << [u8(ctr)]
		ob = k.hmac(prk, ob)!

		okm << ob
	}
	return okm[..length]
}

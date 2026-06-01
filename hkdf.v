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

const supported_hash = [crypto.Hash.sha1, .sha256, .sha384, .sha512]

@[direct_array_access]
pub fn expand(h crypto.Hash, prk []u8, info []u8, length int) ![]u8 {
	k := new(h)!
	return k.expand(prk, info, length)!
}

// Extract generates a pseudorandom key for use with Expand from an input secret and an optional independent salt.
@[direct_array_access]
pub fn extract(h crypto.Hash, salt []u8, ikm []u8) ![]u8 {
	k := new(h)!
	return k.extract(salt, ikm)!
}

// HMAC: Keyed-Hashing for Message Authentication
//
// See https://datatracker.ietf.org/doc/html/rfc2104
interface HMAC {
	new(key []u8, data []u8, h crypto.Hash) ![]u8
}

interface HKDF {
	// hash_length returns the size of the underlying hash output
	hash_length() int

	// HKDF-Extract(salt, IKM) -> PRK
	//
	// Options:
	//  Hash     a hash function; HashLen denotes the length of the
	//         hash function output in octets
	//
	// Inputs:
	//  salt     optional salt value (a non-secret random value);
	//         if not provided, it is set to a string of HashLen zeros.
	// IKM      input keying material
	//
	// Output:
	//  PRK      a pseudorandom key (of HashLen octets)
	//
	// The output PRK is calculated as follows:
	//
	// PRK = HMAC-Hash(salt, IKM)
	extract(salt []u8, ikm []u8) ![]u8

	// HKDF-Expand(PRK, info, L) -> OKM
	//
	// Options:
	//    Hash   a hash function; HashLen denotes the length of the
	//           hash function output in octets
	// Inputs:
	//    PRK    a pseudorandom key of at least HashLen octets
	//           (usually, the output from the extract step)
	//    info   optional context and application specific information
	//           (can be a zero-length string)
	//    L      length of output keying material in octets
	//           (<= 255*HashLen)
	// Output:
	//   OKM     output keying material (of L octets)
	// The output OKM is calculated as follows:
	//
	//  N = ceil(L/HashLen)
	// T = T(1) | T(2) | T(3) | ... | T(N)
	// OKM = first L octets of T
	// where:
	// T(0) = empty string (zero length)
	// T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
	// T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
	// T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
	//...
	//(where the constant concatenated to the end of each T(n) is a
	// single octet.)
	expand(prk []u8, info []u8) ![]u8
}

@[noinit]
struct DefaultHKDF {
mut:
	h crypto.Hash = .sha256
}

pub fn new(h crypto.Hash) !&DefaultHKDF {
	if h !in supported_hash {
		return error('Unsupported of HKDF hash')
	}

	return &DefaultHKDF{
		h: h
	}
}

pub fn (d &DefaultHKDF) extract(salt []u8, ikm []u8) ![]u8 {
	new_salt := if salt.len == 0 {
		// use null hash.len bytes instead
		[]u8{len: d.hash_length(), init: u8(0x00)}
	} else {
		// non-null size salt, use original salt instead
		salt
	}
	// if ikm.len == 0, use hash.len zeros bytes
	new_ikm := if ikm.len == 0 {
		// is it should to init to hash.len null arrays instead
		[]u8{len: d.hash_length(), init: u8(0x00)}
	} else {
		// use non-null length input key material
		ikm
	}
	return d.create_hmac(new_salt, new_ikm)!
}

pub fn (d &DefaultHKDF) expand(prk []u8, info []u8, length int) ![]u8 {
	// check for length <= 255*HashLen
	if length > 255 * d.hash_length() {
		return error('Cannot expand to more than 255 * d.hash_length()')
	}
	ceil := if length % d.hash_length() == 0 { 0 } else { 1 }
	blk_size := length / d.hash_length() + ceil
	
	// output keying material buffer
	mut okm_buf := []u8{cap: length}
	// temporary buffer
	mut tmp_buf := []u8{cap: blk_size}
	for i := 0; i < blk_size; i++ {
		tmp_buf << info
		// counter
		tmp_buf << [u8(i + 1)]
		tmp_buf = d.create_hmac(prk, tmp_buf)!

		okm_buf << tmp_buf
	}
	// returns only desired length 
	return okm_buf[..length].clone()
}

fn (d &DefaultHKDF) hash_length() int {
	match d.h {
		.sha1 { return sha1.size }
		.sha256 { return sha256.size }
		.sha384 { return sha512.size384 }
		.sha512 { return sha512.size }
		else { panic('unsupported hash') }
	}
}

fn (d &DefaultHKDF) create_hmac(key []u8, data []u8) ![]u8 {
	match d.h {
		.sha1 {
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

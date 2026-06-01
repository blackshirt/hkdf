// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// This module implements HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
// as defined in RFC 5869. See https://datatracker.ietf.org/doc/html/rfc5869 for details.
// HKDF is a cryptographic key derivation function (KDF) with the goal of expanding limited input
// keying material into one or more cryptographically strong secret keys.
module hkdf

import crypto
import crypto.hmac
import crypto.sha1
import crypto.sha256
import crypto.sha512

// max_info_size is the limit size (on this library) of the info parameter input, in bytes.
// Under the specification, there is no formal byte-size limit for the info parameter.
// It can theoretically be any length, but we limit it to prevent memory exhaustion.
// Some crypto libraries limit it into 1024-bytes and or 2048-bytes size.
const max_info_size = 2048 // 2 KB

// supported_hash is a list of supported hash algorithms used across of HKDF operation.
const supported_hash = [crypto.Hash.sha1, .sha256, .sha384, .sha512]

// extract generates a pseudorandom key for use with expand operation.
// Its takes form an input secret and an optional independent salt.
// The hash algorithm used as a backend of operation supplied in h parameter.
pub fn extract(h crypto.Hash, salt []u8, ikm []u8, opt HKDFConfig) ![]u8 {
	k := new(h, opt)!
	return k.extract(salt, ikm)!
}

// expand takes and expands a fixed-length pseudorandom key prk into multiple cryptographically
// strong subkeys or keying material of any desired length. An underlying hash algorithm used to do
// the expand operation was supplied in h parameter. It also uses an optional info context
// to ensure the derived keys are strictly bound to their intended purpose.
pub fn expand(h crypto.Hash, prk []u8, info []u8, length int, opt HKDFConfig) ![]u8 {
	k := new(h, opt)!
	return k.expand(prk, info, length)!
}

// HKDF is a key derivation function (KDF) based on the HMAC message authentication code.
pub interface HKDF {
	// hash_length tells the output's size of the underlying hash algorithm backend
	// used on this HKDF instance.
	hash_length() int

	// extract performs HKDF-Extract(salt, IKM) -> PRK
	// Inputs:
	//  salt     optional salt value (a non-secret random value);
	//           if not provided, it is set to a string of HashLen zeros.
	//  IKM      input keying material
	//
	// Output:
	//  PRK      a pseudorandom key (of HashLen octets)
	extract(salt []u8, ikm []u8) ![]u8

	// expand performs HKDF-Expand(PRK, info, L) -> OKM
	// Inputs:
	//    PRK    a pseudorandom key of at least HashLen octets
	//           (usually, the output from the extract step)
	//    info   optional context and application specific information
	//           (can be a zero-length string)
	//    L      length of output keying material in octets
	//           (<= 255*HashLen)
	// Output:
	//   OKM     output keying material (of L octets)
	expand(prk []u8, info []u8, length int) ![]u8
}

// DefaultHKDF is a default implementation of HKDF interface.
@[noinit]
struct DefaultHKDF implements HKDF {
mut:
	// h is an underlying hash used on HKDF operation, set on creation
	h crypto.Hash = .sha256
	// xof_size is the size of output of Extendable-output function (XOF)-based hash.
	// Its used to support xof-based hash output.
	xof_size int
}

// HKDFConfig was a option opaque to drive the HKDF creation and or operation.
// Currently, only used for XOF-based hash backend.
@[params]
pub struct HKDFConfig {
pub mut:
	// for XOF-based hash
	xof_outlen int
}

// new creates a new default HKDF implementation with provided hash h
// Note: Some of the hash algorithm was considered as insecure and deprecated, likes a `.sha1`
// and should be used with care, or not fully completely used as a backend
pub fn new(h crypto.Hash, opt HKDFConfig) !&DefaultHKDF {
	if h !in supported_hash {
		return error('Unsupported of HKDF hash')
	}

	return &DefaultHKDF{
		h: h
	}
}

// extract performs HKDF-Extract operation defined in the standard.
// The extract operation essentially hashes the input material using HMAC
// with a designated (optional) salt value and produces cryptographically
// strong Pseudorandom Key (prk) bytes reduced into a fixed-length output.
@[direct_array_access]
pub fn (d &DefaultHKDF) extract(salt []u8, ikm []u8) ![]u8 {
	// if salt was zeros length, it is set to .hash_length zeros-bytes instead.
	// Otherwise, use the provided salt bytes as is.
	new_salt := if salt.len == 0 {
		[]u8{len: d.hash_length(), init: u8(0x00)}
	} else {
		salt
	}
	// like the salt, if ikm was zeros length, its set to hash_length zeros-bytes instead.
	// Otherwise, use the provided ikm bytes as is
	new_ikm := if ikm.len == 0 {
		[]u8{len: d.hash_length(), init: u8(0x00)}
	} else {
		ikm
	}
	// returns the output of a pseudorandom key (of hash_length octets)
	// calculated as PRK = HMAC-Hash(salt, IKM)
	return d.create_hmac(new_salt, new_ikm)!
}

// expand performs a HKDF-Expand operation defined in the standard.
// Its takes and expands a fixed-length pseudorandom key prk into multiple cryptographically
// strong subkeys or keying material of any desired length. It uses an optional info context
// to ensure the derived keys are strictly bound to their intended purpose.
@[direct_array_access]
pub fn (d &DefaultHKDF) expand(prk []u8, info []u8, length int) ![]u8 {
	// check for info length
	if info.len > max_info_size {
		return error('info length was exceed allowed library limit')
	}
	// check for length <= 255*HashLen
	if length > 255 * d.hash_length() {
		return error('Cannot expand to more than 255 * d.hash_length()')
	}
	// The output of keying material (OKM) is calculated as follows:
	//
	// N = ceil(L/HashLen)
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
	ceil := if length % d.hash_length() == 0 { 0 } else { 1 }
	n := length / d.hash_length() + ceil

	// output keying material buffer
	mut okm_buf := []u8{cap: length}
	// temporary buffer
	mut tmp_buf := []u8{cap: n}
	for i := 0; i < n; i++ {
		tmp_buf << info
		tmp_buf << [u8(i + 1)]
		tmp_buf = d.create_hmac(prk, tmp_buf)!

		okm_buf << tmp_buf
	}
	// returns only desired output length
	return okm_buf[..length].clone()
}

// hash_length tells the length of the output of underlying hash algorithm, in bytes,
// used by this implementation of HKDF d.
pub fn (d &DefaultHKDF) hash_length() int {
	match d.h {
		.sha1 { return sha1.size }
		.sha256 { return sha256.size }
		.sha384 { return sha512.size384 }
		.sha512 { return sha512.size }
		else { panic('unsupported hash') }
	}
}

// Helpers
//

// create_hmac builds HMAC output from the current key and data.
fn (d &DefaultHKDF) create_hmac(key []u8, data []u8) ![]u8 {
	match d.h {
		// NOTE: SHA1 was considered as a deprecated and marked as insecure.
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

// Copyright © 2025, 2026 blackshirt.
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
import crypto.sha3
import crypto.sha256
import crypto.sha512
import crypto.blake2b
import crypto.blake2s

// fixed_deprecated_hash is a list of considered deprecated hash algorithm.
// Its only for compatibility purposes, and should be avoided.
const fixed_deprecated_hash = [crypto.Hash.sha1]

// fixed_sha_hash is a list of supported fixed-output of SHA-2, SHA-3 and SHA-512 hash algorithm.
const fixed_sha_hash = [crypto.Hash.sha224, .sha256, .sha384, .sha3_224, .sha3_256, .sha3_384,
	.sha3_512, .sha512, .sha512_224, .sha512_256]

// fixed_other_hash is a list of another fixed-output of hash algorithm supported on the standard library.
// NOTE: Its currently only support for BLAKE2b and BLAKE2s
const fixed_other_hash = [crypto.Hash.blake2s_256, .blake2b_256, .blake2b_384, .blake2b_512]

// xof_supported_hash is a list of supported XOF-based digest algorithms.
const xof_supported_hash = [crypto.Hash.shake128, .shake256]

// max_info_size is the limit size (on this library) of the info parameter input, in bytes.
// Under the specification, there is no formal byte-size limit for the info parameter.
// It can theoretically be any length, but we limit it to prevent memory exhaustion.
// Some crypto libraries limit it into 1024-bytes and or 2048-bytes size.
const max_info_size = 2048 // 2 KB

// max_salt_size is a maximum size (on this library) for salt parameter input, in bytes.
// The specification does not dictates the limit of this parameter size.
// It can theoretically be any length, but we limit it to prevent memory exhaustion.
const max_salt_size = 4096

// min_xof_outsize is a minimum size of XOF-based digest output, in bytes.
const min_xof_outsize = 16

// max_xof_outsize is a maximum size of XOF-based digest output, in bytes
const max_xof_outsize = 4096

// extract generates a pseudorandom key for use with expand operation.
// Its takes form an input secret and an optional independent salt.
// The hash algorithm used as a backend of operation supplied in h parameter.
// NOTE: If you wish to use XOF-based digest, you should provide the correct option
// value of `xof_outsize` in the allowed current limit ranges, ie, 16-4096 bytes.
pub fn extract(h crypto.Hash, salt []u8, ikm []u8, opt HKDFConfig) ![]u8 {
	k := new(h, opt)!
	return k.extract(salt, ikm)!
}

// expand takes and expands a fixed-length pseudorandom key prk into multiple cryptographically
// strong subkeys or keying material of any desired length. An underlying hash algorithm used to do
// the expand operation was supplied in h parameter. It also uses an optional info context
// to ensure the derived keys are strictly bound to their intended purpose.
// NOTE: If you wish to use XOF-based digest, you should provide the correct option
// value of `xof_outsize` in the allowed current limit ranges, ie, 16-4096 bytes.
pub fn expand(h crypto.Hash, prk []u8, info []u8, length int, opt HKDFConfig) ![]u8 {
	k := new(h, opt)!
	return k.expand(prk, info, length)!
}

// derive performs an `extract then expand` steps of the HKDF operation to derive
// a new keying material with specified length. The hash algorithm used as a backend of
// operation supplied in h parameter.
// NOTE: If you wish to use XOF-based digest, you should provide the correct option
// value of `xof_outsize` in the allowed current limit ranges, ie, 16-4096 bytes.
pub fn derive(h crypto.Hash, salt []u8, ikm []u8, info []u8, length int, opt HKDFConfig) ![]u8 {
	k := new(h, opt)!
	return k.derive(salt, ikm, info, length)!
}

// HKDF is a key derivation function (KDF) based on the HMAC message authentication code.
pub interface HKDF {
	// derive derives and performs "Extract-then-Expand" of HKDF operation.
	// Its return derived key with specified length.
	//
	// Basically, its does two steps of `extract` and `expand` operations
	// defined in standard.
	// 1. extract performs HKDF-Extract(salt, IKM) -> PRK
	//    Inputs:
	//    salt     optional salt value (a non-secret random value);
	//             if not provided, it is set to a string of HashLen zeros.
	//    IKM      input keying material
	//
	//    Output:
	//    PRK      a pseudorandom key (of HashLen octets)
	//    ie, extract(salt []u8, ikm []u8) ![]u8
	//
	// 2. expand performs HKDF-Expand(PRK, info, L) -> OKM
	//    Inputs:
	//    PRK    a pseudorandom key of at least HashLen octets
	//           (usually, the output from the extract step)
	//    info   optional context and application specific information
	//           (can be a zero-length string)
	//    L      length of output keying material in octets
	//           (<= 255*HashLen)
	//    Output:
	//    OKM     output keying material (of L octets)
	//    ie, expand(prk []u8, info []u8, length int) ![]u8
	derive(salt []u8, ikm []u8, info []u8, length int) ![]u8
}

// DefaultHKDF is a default implementation of HKDF that supports for various
// range of digest algorithms availables on the standard library.
// Note: Support for an eXtensible Output Function (XOF)-based digest was an experimental.
@[noinit]
struct DefaultHKDF implements HKDF {
	// h is an underlying hash algorithm used on HKDF operation, set on creation.
	// Currently its support for fixed-output hash and experimental variable-length output size.
	// If you pass correct options for XOF-based digest, its turns the variable-length
	// output into fixed-one by storing the output size on the `xof_outsize` field.
	h crypto.Hash = .sha256
	// is_xof flag tells whether this instance has a XOF-based digest backend.
	// Its should be set into true when h represents XOF-based digest.
	// NOTE: this is experimental features, use with care and caution.
	is_xof bool
mut:
	// xof_outsize is the size of output of Extendable-output function (XOF)-based hash.
	// Its used to support XOF-based digest output, and ignored if h was not XOF-based digest.
	// The size can be changed on subsequent of HKDF operation to reflect variable-length output
	// by calling `.set_xof_outsize` on this instance.
	xof_outsize int = min_xof_outsize
}

// new creates a new default HKDF implementation with provided hash h
// Note: Some of the hash algorithm was considered as insecure and deprecated, likes a `.sha1`
// and should be used with care, or not fully completely used as a backend.
// NOTE: If you wish to use XOF-based digest, you should provide the correct option
// value of `xof_outsize` in the allowed current limit ranges, ie, 16-4096 bytes.
pub fn new(h crypto.Hash, opt HKDFConfig) !&DefaultHKDF {
	// the hash h should fall on one's of the supported list.
	if h !in fixed_deprecated_hash && h !in fixed_sha_hash && h !in fixed_other_hash
		&& h !in xof_supported_hash {
		return error('Unsupported of HKDF hash : ${h}')
	}
	// Is h was XOF-based digest ? if yes, set up the flags
	mut is_xof := false
	if h in xof_supported_hash { is_xof = true }
	xof_size := if is_xof {
		if opt.xof_outsize > max_xof_outsize || opt.xof_outsize < min_xof_outsize {
			return error('invalid xof output size, use value between ${min_xof_outsize} - ${max_xof_outsize} size')
		}
		// use provided options
		opt.xof_outsize
	} else {
		min_xof_outsize
	}

	return &DefaultHKDF{
		h:           h
		is_xof:      is_xof
		xof_outsize: xof_size
	}
}

// derive performs an `extract then expand` steps of the HKDF operation to derive
// a new keying material with specified length.
//
// @param salt: optional salt value (a non-secret random value).
//				if not provided, it is set to a string of hash length zeros
// @param ikm: 	input keying material
// @param info: optional context and application specific information
//           	(can be a zero-length string)
// @param length: length of output keying material in octets (<= 255*Hash length)
// Return a bytes of derived key as an output keying material.
pub fn (d &DefaultHKDF) derive(salt []u8, ikm []u8, info []u8, length int) ![]u8 {
	prk := d.extract(salt, ikm)!
	return d.expand(prk, info, length)!
}

// set_xof_outsize sets the internal size of underlying (XOF) digest output with new size.
// Its does nothing if d no has XOF-based digest as a hash backend.
pub fn (mut d DefaultHKDF) set_xof_outsize(size int) ! {
	// when d.h is not XOF-based digest, do nothing
	if d.is_xof {
		if size < min_xof_outsize {
			return error('size below the low limit of xof size')
		}
		if size > max_xof_outsize {
			return error('size exceed the limit of xof size')
		}
		// sets it up
		d.xof_outsize = size
	}
}

// extract performs HKDF-Extract operation defined in the standard.
// The extract operation essentially hashes the input material using HMAC
// with a designated (optional) salt value and produces cryptographically
// pseudorandom Key (PRK) bytes reduced into a fixed-length output.
@[direct_array_access]
pub fn (d &DefaultHKDF) extract(salt []u8, ikm []u8) ![]u8 {
	// check for salt length
	if salt.len > max_salt_size {
		return error('The salt length exceed the limit allowed')
	}
	// if salt was zeros length bytes, it would be set to .hash_length zeros-bytes instead.
	// Otherwise, use the provided salt bytes as is.
	new_salt := if salt.len == 0 {
		[]u8{len: d.hash_length(), init: u8(0x00)}
	} else {
		salt
	}
	// similar to the salt part, if ikm was zeros length bytes,
	// its would be set to hash_length zeros-bytes instead.
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
// Note: prk key should come from `.extract` step from previous operation.
@[direct_array_access]
pub fn (d &DefaultHKDF) expand(prk []u8, info []u8, length int) ![]u8 {
	// prk bytes should come from extract step or externally cryptographically secure key
	// supplied by the user. Its should be have non-null length.
	if prk.len == 0 {
		return error('expand with null prk length')
	}
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

// Helpers (internal routines) for DefaultHKDF
//

// hash_length tells the length of the output of underlying hash algorithm, in bytes,
// used by this implementation of HKDF d.
fn (d &DefaultHKDF) hash_length() int {
	match d.h {
		// SHA-1, for compatibility purposes
		.sha1 { return 20 } // 20
		// Fixed-output hash
		.sha224, .sha3_224, .sha512_224 { return 28 }
		.sha256, .sha3_256, .sha512_256, .blake2s_256, .blake2b_256 { return 32 }
		.sha384, .sha3_384, .blake2b_384 { return 48 }
		.sha512, .sha3_512, .blake2b_512 { return 64 }
		// for XOF-based digest, return internal size stored on the xof_outsize field.
		.shake128, .shake256 { return d.xof_outsize }
		else { panic('unsupported hash') }
	}
}

// create_hmac builds HMAC output from the current key and message data.
@[direct_array_access]
fn (d &DefaultHKDF) create_hmac(key []u8, data []u8) ![]u8 {
	match d.h {
		// NOTE: SHA1 was considered as a deprecated and marked as insecure.
		.sha1 {
			return hmac.new(key, data, sha1.sum, sha1.block_size)
		}
		// SHA-2
		.sha224 {
			return hmac.new(key, data, sha256.sum224, sha256.block_size)
		}
		.sha256 {
			return hmac.new(key, data, sha256.sum, sha256.block_size)
		}
		// SHA-512
		.sha384 {
			return hmac.new(key, data, sha512.sum384, sha512.block_size)
		}
		.sha512 {
			return hmac.new(key, data, sha512.sum512, sha512.block_size)
		}
		.sha512_224 {
			return hmac.new(key, data, sha512.sum512_224, sha512.block_size)
		}
		.sha512_256 {
			return hmac.new(key, data, sha512.sum512_256, sha512.block_size)
		}
		// SHA-3
		.sha3_224 {
			return hmac.new(key, data, sha3.sum224, sha3.rate_224)
		}
		.sha3_256 {
			return hmac.new(key, data, sha3.sum256, sha3.rate_256)
		}
		.sha3_384 {
			return hmac.new(key, data, sha3.sum384, sha3.rate_384)
		}
		.sha3_512 {
			return hmac.new(key, data, sha3.sum512, sha3.rate_512)
		}
		// NOTE: this code parts was not tested, and acts as an experimental
		// support for XOF-based digest. Its not recommended to use XOF-based digest
		// on hmac construction.
		.shake128 {
			cb := fn [d] (msg []u8) []u8 {
				xofout := sha3.shake128(msg, d.xof_outsize)
				return xof_callback(xofout)
			}
			return hmac.new(key, data, cb, sha3.xof_rate_128)
		}
		.shake256 {
			cb := fn [d] (msg []u8) []u8 {
				xofout := sha3.shake256(msg, d.xof_outsize)
				return xof_callback(xofout)
			}
			return hmac.new(key, data, cb, sha3.xof_rate_256)
		}
		// BLAKE2s-digest
		.blake2s_256 {
			return hmac.new(key, data, blake2s.sum256, blake2s.block_size)
		}
		// BLAKE2b-digest
		.blake2b_256 {
			return hmac.new(key, data, blake2b.sum256, blake2b.block_size)
		}
		.blake2b_384 {
			return hmac.new(key, data, blake2b.sum384, blake2b.block_size)
		}
		.blake2b_512 {
			return hmac.new(key, data, blake2b.sum512, blake2b.block_size)
		}
		else {
			return error('unsupported hash')
		}
	}
}

// HKDFConfig was an option opaque to drive the HKDF creation and or operation.
@[params]
pub struct HKDFConfig {
pub mut:
	// xof_outsize was a flag to be passed into `.new` HKDF constructor,
	// especially when you wish for XOF-based digest as a backend.
	// Its tells the size of the XOF-based output and changeable through
	// `.set_xof_outsize()` call.
	// By default, its set into current `min_xof_outsize` value, ie, 16-bytes size.
	xof_outsize int = min_xof_outsize
}

// little hack to allow XOF-based digest used in hkdf construction
@[direct_array_access; inline]
fn xof_callback(data []u8) []u8 {
	return data
}

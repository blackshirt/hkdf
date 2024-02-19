module hkdf

import io
import crypto
import crypto.hmac
import crypto.sha1
import crypto.sha256
import crypto.sha512

// this is essentialy hash based functionality
// The name of `Hash` already used as an enum in `crypto` module.
interface Digest {
	// size of output (in bytes) of this digest
	size() int
mut:
	write(b []u8) !int
	// checksumsum returns the `size()` checksum of digest with the data
	checksum() []u8
	reset()
}

fn new_digest(h crypto.Hash) !&Digest {
	match h {
		.sha256 {
			return sha256.new()
		}
		.sha384 {
			returnsha512.new384()
		}
		.sha512 {
			return sha512.new()
		}
		else {
			return error("unsuppprted hash")
		}
	}
}
	
// HMAC describes hash based message authentication code (MAC)
// Fundamentally its a Digest with `create_hmac` capabilityt
// besides embedded Digest interfaces
interface HMAC {
	Digest
	create_hmac(key []u8, info []u8) []u8
}

// HMAC based Key Derivation Function interface
interface HKDF {
	HMAC
	extract(salt []u8, keymaterial []u8) []u8
	expand(key []u8, info []u8, exp_length int) []u8 
}

	
// HMAC based Key Derivation Function with crypto.Hash
struct Hkdf {
	d Digest
	h crypto.Hash = .sha256
}

fn new_hkdf(h crypto.Hash) !&HKDF {
	return &Hkdf{
		d: new_digest(h)
		h: h
	}
}

fn (k Hkdf) hash() crypto.Hash {
	return k.h
}

fn (k Hkdf) write(b []u8) !int {
	return k.d
}
	
fn (k Hkdf) size() !int {
	match k.hash {
		.sha256 { return sha256.size }
		.sha384 { return sha512.size384 }
		.sha512 { return sha512.size }
		else { return error('unsupported hash') }
	}
}
			
pub fn new(h crypto.Hash) &Hkdf {
	return &Hkdf{
		hash: h
	}
}

pub fn (k Hkdf) hasher() crypto.Hash {
	return k.hash
}

// sum return sum of the data for Hkdf hash
pub fn (k Hkdf) sum(data []u8) ![]u8 {
	match k.hash {
		.sha256 { return sha256.sum256(data) }
		.sha384 { return sha512.sum384(data) }
		.sha512 { return sha512.sum512(data) }
		else { return error('unsupported sum hasher') }
	}
}

fn (k Hkdf) create_hmac(key []u8, data []u8) ![]u8 {
	match k.hash {
		.sha1 {
			// .sha1 is considerd as deprecated, so placed it in $if block,
			// used only for testing and debug purposes.
			// run with `$v -cg -stats test the_test.v`
			$if test {
				$if debug {
					blksize := sha1.block_size
					res := hmac.new(key, data, sha1.sum, blksize)
					return res
				}
			}
			return error('run it in test and debug mode')
		}
		.sha256 {
			blksize := sha256.block_size
			res := hmac.new(key, data, sha256.sum, blksize)
			return res
		}
		.sha384 {
			blksize := sha512.block_size
			res := hmac.new(key, data, sha512.sum384, blksize)
			return res
		}
		.sha512 {
			blksize := sha512.block_size
			res := hmac.new(key, data, sha512.sum512, blksize)
			return res
		}
		else {
			return error('unsupported hash')
		}
	}
}

// size return size of the checksum underlying hash
pub fn (k Hkdf) size() !int {
	match k.hash {
		.sha1 { return sha1.size }
		.sha256 { return sha256.size }
		.sha384 { return sha512.size384 }
		.sha512 { return sha512.size }
		else { return error('unsupported hash') }
	}
}

// hmac create new hmac
pub fn (k Hkdf) hmac(key []u8, data []u8) ![]u8 {
	return k.create_hmac(key, data)!
}

// extract create pseudorandom key (prk) from input given.
// its output is hmac based hash with length (size) of Hashing checksum size
pub fn (k Hkdf) extract(salt []u8, ikm []u8) ![]u8 {
	mut inp := ikm.clone()
	if inp.len == 0 {
		// is it should to init to hash.len null arrays instead
		inp = []u8{len: k.size()!, init: u8(0x00)}
	}

	mut slt := salt.clone()
	if slt.len == 0 {
		slt = []u8{len: k.size()!, init: u8(0x00)}
	}

	prk := k.hmac(slt, inp)!
	return prk
}

// // expand expand pseudorandom key to build output keying materi.
// where length is the length of output keying material in octets (<= 255*HashLen)
// where HashLen denotes the length of the hash function output in octets
pub fn (k Hkdf) expand(prk []u8, info []u8, length int) ![]u8 {
	hash_len := k.size()!
	if length > 255 * hash_len {
		return error('Cannot expand to more than 255 * ${hash_len}')
	}
	ceil := if length % hash_len == 0 { 0 } else { 1 }
	blk := length / hash_len + ceil
	mut okm := []u8{}
	mut ob := []u8{}
	for i := 0; i < blk; i++ {
		ob << info
		ctr := i + 1
		ob << [u8(ctr)]
		ob = k.hmac(prk, ob)!

		okm << ob
	}
	return okm[..length]
}

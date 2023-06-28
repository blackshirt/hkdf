module hkdf

import crypto
import crypto.hmac
import crypto.sha1
import crypto.sha256
import crypto.sha512

type HasherFn = crypto.Hash

pub fn (h HasherFn) hmac_new(key []u8, data []u8) ![]u8 {
	match h {
		.sha1 {
			blksize := sha1.block_size
			res := hmac.new(key, data, sha1.sum, blksize)
			return res
		}
		.sha256 {
			blksize := sha256.block_size
			res := hmac.new(key, data, sha256.sum, blksize)
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

fn (h HasherFn) size() !int {
	match h {
		.sha1 {
			return sha1.size
		}
		.sha256 {
			return sha256.size
		}
		.sha512 {
			return sha512.size
		}
		else {
			return error('unsupported hash')
		}
	}
}

fn hmac_new(key []u8, data []u8, hfn HasherFn) ![]u8 {
	return hfn.hmac_new(key, data)!
}

fn extract(slt []u8, ikm []u8, hfn HasherFn) ![]u8 {
	if ikm.len == 0 {
		return error('bad ikm')
	}

	mut salt := slt.clone()
	if salt.len == 0 {
		salt = []u8{len: hfn.size()!, init: u8(0x00)}
	}

	prk := hmac_new(salt, ikm, hfn)!
	return prk
}

pub fn expand(prk []u8, info []u8, length int, hfn HasherFn) ![]u8 {
	hash_len := hfn.size()!

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
		ob = hmac_new(prk, ob, hfn)!

		okm << ob
	}
	return okm[..length]
}

pub fn hkdf(salt []u8, ikm []u8, info []u8, length int, hfn HasherFn) ![]u8 {
	// Key derivation function
	prk := extract(salt, ikm, hfn)!
	return expand(prk, info, length, hfn)
}

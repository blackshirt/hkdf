module hkdf

import crypto
import crypto.hmac
import crypto.sha256

type HasherFn = crypto.Hash

fn (h HasherFn) hmac_new(key []u8, data []u8) ![]u8 {
	match h {
		.sha256 {
			blksize := sha256.block_size
			res := hmac.new(key, data, sha256.sum, blksize)
			return res
		}
		else {
			return error('unsupported hash')
		}
	}
}

fn (h HasherFn) size() !int {
	match h {
		.sha256 {
			return sha256.size
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

fn expand(prk []u8, info []u8, length int, hfn HasherFn) ![]u8 {
	hash_len := hfn.size()!

	if length > 255 * hash_len {
		return error('Cannot expand to more than 255 * ${hash_len}')
	}
	ceil := if length % hash_len == 0 { 0 } else { 1 }
	blocks_needed := length / hash_len + ceil
	mut okm := []u8{}
	mut output_block := []u8{}
	for i := 0; i < blocks_needed; i++ {
		output_block << info
		ctr := i + 1
		output_block << [u8(ctr)]
		output_block = hmac_new(prk, output_block, hfn)!

		okm << output_block
	}
	return okm[..length]
}

fn hkdf(salt []u8, ikm []u8, info []u8, length int, hfn HasherFn) ![]u8 {
	// Key derivation function
	prk := extract(salt, ikm, hfn)!
	return expand(prk, info, length, hfn)
}

module hkdf

import crypto
import crypto.hmac
import crypto.sha1
import crypto.sha256
import crypto.sha512
import encoding.binary

// Hasher is hashing function in standard library.
// see https://modules.vlang.io/crypto.html#Hash
// but for this purpose, its limited to sha based hash.
pub type Hasher = crypto.Hash

fn (h Hasher) hmac_new(key []u8, data []u8) ![]u8 {
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

fn (h Hasher) size() !int {
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

fn hmac_new(key []u8, data []u8, hashfn Hasher) ![]u8 {
	return hashfn.hmac_new(key, data)!
}

pub fn extract(slt []u8, ikm []u8, hashfn Hasher) ![]u8 {
	if ikm.len == 0 {
		return error('bad ikm')
	}

	mut salt := slt.clone()
	if salt.len == 0 {
		salt = []u8{len: hashfn.size()!, init: u8(0x00)}
	}

	prk := hmac_new(salt, ikm, hashfn)!
	return prk
}

// L is the length of output keying material in octets (<= 255*HashLen)
// where HashLen denotes the length of the hash function output in octets
pub fn expand(prk []u8, info []u8, length int, hashfn Hasher) ![]u8 {
	hash_len := hashfn.size()!

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
		ob = hmac_new(prk, ob, hashfn)!

		okm << ob
	}
	return okm[..length]
}

pub fn hkdf(salt []u8, ikm []u8, info []u8, length int, hashfn Hasher) ![]u8 {
	// Key derivation function
	prk := extract(salt, ikm, hashfn)!
	return expand(prk, info, length, hashfn)
}

// RFC8446 7.1.  Key Schedule
// https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
//
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//      HKDF-Expand(Secret, HkdfLabel, Length)
//

// Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)

fn hkdf_expand_label(secret []u8, label string, context []u8, length int, hashfn Hasher) ![]u8 {
	outlabel := 'tls13 ' + label
	hl := HKDFLabel{
		length: length
		label: outlabel
		context: context
	}
	info := hl.encode()!
	res := expand(secret, info, length, hashfn)!
	return res
}

// struct {
//   	uint16 length = Length;
//     	opaque label<7..255> = "tls13 " + Label;
//   	opaque context<0..255> = Context;
// } HkdfLabel;

struct HKDFLabel {
	length  int    // u16
	label   string // ascii string
	context []u8   // < 255 len
}

fn (hl HKDFLabel) encode() ![]u8 {
	mut out := []u8{}
	mut l := []u8{len: 2}
	binary.big_endian_put_u16(mut l, u16(hl.length))
	out << l

	label_length := hl.label.bytes().len // fit in one byte
	out << u8(label_length)
	out << hl.label.bytes()

	out << u8(hl.context.len)
	out << hl.context

	return out
}

// Derive-Secret(Secret, Label, Messages) =
//     HKDF-Expand-Label(Secret, Label,  Transcript-Hash(Messages), Hash.length)
//
fn hkdf_derive_secret(secret []u8, label string, msg []u8, hashfn Hasher) ![]u8 {
	context := hashfn.hmac_new(secret, msg)!
	length := context.len

	res := hkdf_expand_label(secret, label, context, length, hashfn)!
	return res
}

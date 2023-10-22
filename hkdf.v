module hkdf

import math
import crypto
import crypto.hmac
import crypto.sha1
import crypto.sha256
import crypto.sha512
import encoding.binary
import blackshirt.buffer

// HMAC based Key Derivation Function with crypto.Hash
struct Hkdf {
	hash crypto.Hash = .sha256
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

// expand expand pseudorandom key to build output keying materi.
// where length is the length of output keying material in octets (<= 255*HashLen)
// where HashLen denotes the length of the hash function output in octets
pub fn (k Hkdf) expand_with_salt(salt []u8, ikm []u8, info []u8, length int) ![]u8 {
	prk := k.extract(salt, ikm)!
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

// actually Hkdf.expand() == Hkdf.expand_with_salt()
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

// struct {
//      uint16 length = Length;
//      opaque label<7..255> = 'tls13 ' + Label;
//      opaque context<0..255> = Context;
// } HkdfLabel;
//
// With common hash functions, any label longer than 12 characters
// requires an additional iteration of the hash function to compute.
// The labels in this specification have all been chosen to fit within
// this limit.

const (
	max_hkdf_label_length   = 255
	max_hkdf_context_length = 255
)

struct HkdfLabel {
	length  int    // u16
	label   string // ascii string
	context []u8   // < 255 len
}

// This add support for HKDF-Expand-Label and other machinery for TLS 1.3
// from RFC8446 Section 7.1 Key Schedule and others.
// see https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//      HKDF-Expand(Secret, HkdfLabel, Length)
//
pub fn (k Hkdf) expand_label(secret []u8, label string, context []u8, length int) ![]u8 {
	lbl := new_hkdf_label(label, context, length)!
	hkdflabel := lbl.encode()!
	out := k.expand(secret, hkdflabel, length)!
	return out
}

// Derive-Secret(Secret, Label, Messages) =
//     HKDF-Expand-Label(Secret, Label,  Transcript-Hash(Messages), Hash.length)
pub fn (k Hkdf) derive_secret(secret []u8, label string, messages []u8) ![]u8 {
	trc_hash := k.sum(messages)!
	out := k.expand_label(secret, label, trc_hash, k.size()!)!
	return out
}

fn (hl HkdfLabel) verify() ! {
	if !hl.label.is_ascii() {
		return error('HkdfLabel.label contains non-ascii string')
	}
	if hl.label.len > hkdf.max_hkdf_label_length {
		return error('label.len exceed limit')
	}
	if hl.context.len > hkdf.max_hkdf_context_length {
		return error('hkdf.context.len exceed limit')
	}

	if hl.length > math.max_u16 {
		return error('hl.length exceed limit')
	}
}

// new_hkdf_label create new HkdfLabel
pub fn new_hkdf_label(label string, context []u8, length int) !HkdfLabel {
	hl := HkdfLabel{
		length: length
		label: label
		context: context
	}
	hl.verify()!
	return hl
}

fn (hl HkdfLabel) encode() ![]u8 {
	hl.verify()!
	mut out := []u8{}

	// writes hkdf length
	mut ln := []u8{len: 2}
	binary.big_endian_put_u16(mut ln, u16(hl.length))
	out << ln

	// writes label length
	label_length := hl.label.bytes().len // should fit in one byte
	out << u8(label_length)
	out << hl.label.bytes()

	out << u8(hl.context.len)
	out << hl.context

	return out
}

fn HkdfLabel.decode(b []u8) !HkdfLabel {
	mut r := buffer.new_reader(b)
	// read two bytes length
	length := r.read_u16()!
	// one byte label length
	label_len := r.read_byte()!
	// read label contents
	label := r.read_at_least(int(label_len))!
	// one byte context len
	ctx_len := r.read_byte()!
	// read context bytes
	ctx := r.read_at_least(int(ctx_len))!

	hklabel := new_hkdf_label(label.str(), ctx, int(length))!
	return hklabel
}

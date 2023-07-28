module hkdf

import math
import crypto
import crypto.hmac
import crypto.sha1
import crypto.sha256
import crypto.sha512
import encoding.binary
import buffer

// Hasher is hashing function in standard library.
// see https://modules.vlang.io/crypto.html#Hash
// but for this purpose, its limited to sha based hash.
//
pub type Hasher = crypto.Hash

// HMAC based Key Derivation Function
pub struct Hkdf {
	hasher Hasher = .sha256
}

pub fn new(h Hasher) &Hkdf {
	return &Hkdf{h}
}

pub fn (h Hkdf) hasher() Hasher {
	return h.hasher
}

// hmac create new hmac
pub fn (h Hkdf) hmac(key []u8, data []u8) ![]u8 {
	return h.hasher.create_hmac(key, data)!
}

pub fn (h Hkdf) extract(salt []u8, ikm []u8) ![]u8 {
	mut inp := ikm.clone()
	if inp.len == 0 {
		// is it should to init to hash.len null arrays instead
		inp = []u8{len: h.hasher.size()!, init: u8(0x00)}
	}

	mut slt := salt.clone()
	if slt.len == 0 {
		slt = []u8{len: h.hasher.size()!, init: u8(0x00)}
	}

	prk := h.hmac(slt, inp)!
	return prk
}

// L is the length of output keying material in octets (<= 255*HashLen)
// where HashLen denotes the length of the hash function output in octets
pub fn (h Hkdf) expand(prk []u8, info []u8, length int) ![]u8 {
	hash_len := h.hasher.size()!

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
		ob = h.hmac(prk, ob)!

		okm << ob
	}
	return okm[..length]
}

// Support for HKDF-Expand-Label and other machinery for TLS 1.3
// from RFC8446 Section 7.1 Key Schedule and others.
// see https://datatracker.ietf.org/doc/html/rfc8446#section-7.1

// HKDF-Expand-Label(Secret, Label, Context, Length) =
//      HKDF-Expand(Secret, HkdfLabel, Length)
pub fn (h Hkdf) expand_label(secret []u8, label string, context []u8, length int) ![]u8 {
	lbl := new_hkdf_label(label, context, length)!
	hkdflabel := lbl.encode()!
	out := h.expand(secret, hkdflabel, length)!
	return out
}

// Derive-Secret(Secret, Label, Messages) =
//     HKDF-Expand-Label(Secret, Label,  Transcript-Hash(Messages), Hash.length)
pub fn (h Hkdf) derive_secret(secret []u8, label string, messages []u8) ![]u8 {
	trc_hash := h.hasher.sum(messages)!
	out := h.expand_label(secret, label, trc_hash, h.hasher.size()!)!
	return out
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
	length  int // u16
	prefix  string = 'tls13 '
	label   string // ascii string
	context []u8   // < 255 len
}

fn (hl HkdfLabel) verify() ! {
	if !hl.label.is_ascii() {
		return error('HkdfLabel.label contains non-ascii string')
	}
	if hl.context.len > hkdf.max_hkdf_context_length {
		return error('hkdf.context.len exceed limit')
	}
	label := hl.prefix + hl.label
	if label.len > hkdf.max_hkdf_label_length {
		return error('label.len exceed limit')
	}
	if hl.length > math.max_u16 {
		return error('hl.length exceed limit')
	}
}

fn new_hkdf_label(label string, context []u8, length int) !HkdfLabel {
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
	label := hl.prefix + hl.label

	// writes hkdf length
	mut ln := []u8{len: 2}
	binary.big_endian_put_u16(mut ln, u16(hl.length))
	out << ln

	// writes label length
	label_length := label.bytes().len // should fit in one byte
	out << u8(label_length)
	out << label.bytes()

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

// Hasher
pub fn (h Hasher) sum(data []u8) ![]u8 {
	match h {
		.sha256 {
			return sha256.sum256(data)
		}
		.sha512 {
			return sha512.sum512(data)
		}
		else {
			return error('unsupported sum hasher')
		}
	}
}

fn (h Hasher) create_hmac(key []u8, data []u8) ![]u8 {
	match h {
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

pub fn (h Hasher) size() !int {
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

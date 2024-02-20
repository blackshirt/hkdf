module hkdf

import io
import crypto
import crypto.hmac
import crypto.sha1
import crypto.sha256
import crypto.sha512
import crypto.internal.subtle

const ipad = []u8{len: 256, init: 0x36} // TODO is 256 enough??

const opad = []u8{len: 256, init: 0x5C}
const npad = []u8{len: 256, init: 0}
	
// Digest represents hash based object.
// The name of `Hash` already used as an enum in `crypto` module.
interface Digest {
	// id returns identity of this Digest, for comparable thing.
	// FIX: builtin standard cryptographic hash not implemented `id()` parts
	id() crypto.Hash
	// block_size return size of the Digest block operates on.
	// Is this makes sense with non-block based Digest ? is there any guide on this topic ?
	block_size() int 
	// size returns fhe size of output (in bytes) of this Digest produced
	size() int
mut:
	// write updates internal states of the digest with data `b`
	write(b []u8) !int
	// checksum returns `size()` bytes of this digest checksum
	checksum() []u8
	// reset resets underlying digest to default state
	reset()
}

fn new_digest(h crypto.Hash, key []u8, size int) !&Digest {
	// many standard hash module in crypto modules accepts differents params
	// and implemented in non interchangeable way
	match h {
		.sha256 {
			return sha256.new()
		}
		.sha384 {
			return sha512.new384()
		}
		.sha512 {
			return sha512.new()
		}
		.blake2b_256 {
			// accepts key, bytes
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
	// digest returns underlying Digest
	digest() Digest
	// create_hmac build new hmac message from key and info bytes
	create_hmac(key []u8, data []u8) ![]u8
}

struct Hmac {
	d Digest
}
	
fn new_hmac(d Digest) !&HMAC {
	m := &Hmac{
		d: d
	}
	return m
}

fn (m Hmac) digest() Digest {
	return m.d
}
	
fn (m Hmac) create_hmac(key []u8, data []u8) ![]u8 {
	// copied from `crypto.hmac.new` for sake of comparability
	mut b_key := []u8{}
	blocksize := m.d.block_size()
	if key.len <= blocksize {
		b_key = key.clone() // 
	} else {
		// replaces hash_func with Digest based
		// first, we reset it before usage
		m.d.reset()
		_ := m.d.write(key) !
		b_key = m.d.checksum()
		// b_key = hash_func(key)
	}
	if b_key.len < blocksize {
		b_key << npad[..blocksize - b_key.len]
	}
	mut inner := []u8{}
	for i, b in ipad[..blocksize] {
		inner << b_key[i] ^ b
	}
	inner << data
	// inner_hash := hash_func(inner)
	m.d.reset()
	_ := m.d.write(inner) !
	inner_hash := m.d.checksum()
		
	mut outer := []u8{cap: b_key.len}
	for i, b in opad[..blocksize] {
		outer << b_key[i] ^ b
	}
	outer << inner_hash
	// digest := hash_func(outer)
	m.d.reset()
	_ := m.d.write(outer) !
	digest := m.d.checksum()
		
	return digest
}
	
// HMAC based Key Derivation Function (HKDF) interface
interface HKDF {
	hmac() HMAC
	extract(salt []u8, keymaterial []u8) []u8
	expand(key []u8, data []u8, exp_length int) []u8 
}

// HMAC based Key Derivation Function with crypto.Hash
struct Hkdf {
	m HMAC
}

fn new_hkdf(d Digest) !&HKDF {
	return &Hkdf{
		m: new_hmac(d)!
	}
}

fn (k Hkdf) hmac() HMAC {
	return k.m
}

fn (k Hkdf) extract(salt_ []u8, keym_ []u8) ![]u8 {
	d := k.m.digest()
	mut keymaterial := []u8{}
	if keym_.len == 0 {
		keymaterial << []u8{len: d.size()}
	} else {
		keymaterial << keym_
	}

	mut salt := []u8{}
	if salt_.len == 0 {
		salt << []u8{len: d.size()}
	} else {
		// use provided salt_ params
		salt << salt_
	}

	prk := k.m.create_hmac(salt, keymaterial)!
	return prk	
}

fn (k Hkdf) expand(key []u8, info []u8, exp_length int) ![]u8 {
	hash_len := k.m.digest().size()!
	if exp_length > 255 * hash_len {
		return error('Cannot expand to more than 255 * ${hash_len}')
	}
	ceil := if exp_length % hash_len == 0 { 0 } else { 1 }
	blk := exp_length / hash_len + ceil
	// output keying material
	mut okm := []u8{} 
	mut ob := []u8{}
	for i := 0; i < blk; i++ {
		ob << info
		ctr := i + 1
		ob << [u8(ctr)]
		ob = k.m.create_hmac(prk, ob)!

		okm << ob
	}
	return okm[..exp_length]	
}

/*
	
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
*/

# module hkdf


# hkdf
 HMAC-based Extract-and-Expand Key Derivation Function (HKDF) in pure V Language.
 See [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) for more detail.

## Contents
- [new](#new)
- [Hkdf](#Hkdf)
  - [hasher](#hasher)
  - [sum](#sum)
  - [size](#size)
  - [hmac](#hmac)
  - [extract](#extract)
  - [expand](#expand)

## new
```v
fn new(h crypto.Hash) &Hkdf
```


[[Return to contents]](#Contents)

## Hkdf
## hasher
```v
fn (k Hkdf) hasher() crypto.Hash
```


[[Return to contents]](#Contents)

## sum
```v
fn (k Hkdf) sum(data []u8) ![]u8
```

sum return sum of the data for Hkdf hash

[[Return to contents]](#Contents)

## size
```v
fn (k Hkdf) size() !int
```

size return size of the checksum underlying hash

[[Return to contents]](#Contents)

## hmac
```v
fn (k Hkdf) hmac(key []u8, data []u8) ![]u8
```

hmac create new hmac

[[Return to contents]](#Contents)

## extract
```v
fn (k Hkdf) extract(salt []u8, ikm []u8) ![]u8
```

extract create pseudorandom key (prk) from input given.  
its output is hmac based hash with length (size) of Hashing checksum size

[[Return to contents]](#Contents)

## expand
```v
fn (k Hkdf) expand(prk []u8, info []u8, length int) ![]u8
```

// expand expand pseudorandom key to build output keying materi.  
where length is the length of output keying material in octets (<= 255*HashLen) where HashLen denotes the length of the hash function output in octets

[[Return to contents]](#Contents)

#### Powered by vdoc. Generated on: 22 Oct 2023 12:39:55

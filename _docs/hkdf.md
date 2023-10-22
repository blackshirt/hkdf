# module hkdf


# hkdf
 HMAC-based Extract-and-Expand Key Derivation Function (HKDF) in pure V Language.
 See [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) for more detail.


## Contents
- [new](#new)
- [new_hkdf_label](#new_hkdf_label)
- [Hkdf](#Hkdf)
  - [hasher](#hasher)
  - [sum](#sum)
  - [size](#size)
  - [hmac](#hmac)
  - [extract](#extract)
  - [expand_with_salt](#expand_with_salt)
  - [expand](#expand)
  - [expand_label](#expand_label)
  - [derive_secret](#derive_secret)

## new
```v
fn new(h crypto.Hash) &Hkdf
```


[[Return to contents]](#Contents)

## new_hkdf_label
```v
fn new_hkdf_label(label string, context []u8, length int) !HkdfLabel
```

new_hkdf_label create new HkdfLabel

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

## expand_with_salt
```v
fn (k Hkdf) expand_with_salt(salt []u8, ikm []u8, info []u8, length int) ![]u8
```

expand expand pseudorandom key to build output keying materi.  
where length is the length of output keying material in octets (<= 255*HashLen) where HashLen denotes the length of the hash function output in octets

[[Return to contents]](#Contents)

## expand
```v
fn (k Hkdf) expand(prk []u8, info []u8, length int) ![]u8
```

actually Hkdf.expand() == Hkdf.expand_with_salt()

[[Return to contents]](#Contents)

## expand_label
```v
fn (k Hkdf) expand_label(secret []u8, label string, context []u8, length int) ![]u8
```

This add support for HKDF-Expand-Label and other machinery for TLS 1.3
from RFC8446 Section 7.1 Key Schedule and others.  
see https://datatracker.ietf.org/doc/html/rfc8446#section-7.1 HKDF-Expand-Label(Secret, Label, Context, Length) =      HKDF-Expand(Secret, HkdfLabel, Length)


[[Return to contents]](#Contents)

## derive_secret
```v
fn (k Hkdf) derive_secret(secret []u8, label string, messages []u8) ![]u8
```

Derive-Secret(Secret, Label, Messages) =     HKDF-Expand-Label(Secret, Label,  Transcript-Hash(Messages), Hash.length)

[[Return to contents]](#Contents)

#### Powered by vdoc. Generated on: 22 Oct 2023 07:25:33

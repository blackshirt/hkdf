# hkdf

 HMAC-based Extract-and-Expand Key Derivation Function (HKDF) in pure V Language.
 See [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) for more detail.

## Features
The default HKDF implementation on this module in the form of `DefaultHKDF` has:
- Supports for wide range of fixed-sized hash algorithms as a backend, backed by hash algorihtm 
on the standard library, ie, SHA-2, SHA-3 and SHA-512. 
Its also support SHA-1 for compatibility purposes.
- Experimental supports for hash algorithm based on the an eXtensible Output Function (XOF)
construct, ie, SHAKE128 and SHAKE256, that was availables on the standard library.
This construct was commonly was not recommended, and its availables as experimental things.
Use with cares.
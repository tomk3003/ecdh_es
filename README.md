# ecdh_es

C implemetation of the decryption algorithm used by the Perl module

[Crypt::ECDH_ES](https://metacpan.org/pod/Crypt::ECDH_ES)

## Used cryptography implementations

* [curve25519-donna](https://code.google.com/archive/p/curve25519-donna/)
* [sha256/hmac_sha256](https://github.com/h5p9sl/hmac_sha256/)
* [aes_cbc](https://github.com/kokke/tiny-AES-c)

## Build

  `gcc src/ecdh_es_decrypt.c -o ecdh_es_decrypt.c`

## Usage

  `ecdh_es_decrypt <private_key_filename> <encrypted_hexstring>`

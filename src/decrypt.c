#include <stdio.h>
#include <string.h>

#define DEBUG

#include "curve25519-donna.c"
#include "aes.c"
#include "hmac_sha256.c"
#include "sha256.c"

const unsigned KEY_LENGTH     = 32;
const unsigned HEX_LENGTH     = 64;


void phex (const char * txt, const uint8_t * in, const size_t size) {
    printf("%s: ", txt);
    int i;
    for (i = 0; i < size; i++) {
        printf("%02X", in[i]);
    }
    printf("\n");
}


uint8_t key_from_file (const char * fname, char * key) {

    FILE *fp = fopen(fname, "r");
    if (fp == NULL) {
        printf("Error: could not open file %s", fname);
        return 1;
    }

    unsigned char key_hex [HEX_LENGTH + 1], *pkh_pos = key_hex;
    fgets(key_hex, HEX_LENGTH + 1, fp);
    fclose(fp);

    if ( strlen(key_hex) != HEX_LENGTH ) {
        printf("key length not %d (%d bytes in hex)\n", HEX_LENGTH, KEY_LENGTH);
        return 1;
    }

    int i;
 	for (i = 0; i < KEY_LENGTH; i++) {
        sscanf(pkh_pos, "%2hx", &key[i]);
        pkh_pos += 2;
    }

    return 0;
}


uint8_t parse_packed_data (char * data, char * public_key, char * mac, char * ciphertext) {

    unsigned char * in_pos = data;

    unsigned char option_count;
    sscanf(in_pos, "%2hx", &option_count);
    in_pos += 2 + option_count * 2;

    unsigned char public_size;
    sscanf(in_pos, "%2hx", &public_size);
    in_pos += 2;
    if ( public_size != KEY_LENGTH ) {
        printf("invalid public key length %d in encrypted value\n", public_size);
        return 1;
    }

    int i;
    unsigned char pkey [KEY_LENGTH + 1];
 	for (i = 0; i < KEY_LENGTH; i++) {
        sscanf(in_pos, "%2hx", &pkey[i]);
        in_pos += 2;
    }
    public_key = pkey;
    phex("public_key", public_key, KEY_LENGTH);

    const unsigned MAC_LENGTH = 32;
    unsigned short mac_size;
    sscanf(in_pos, "%4hx", &mac_size);
    printf("mac_size_hex: %04X\n", mac_size);
    printf("mac_size: %d\n", mac_size);
    in_pos += 4;

    if ( mac_size != MAC_LENGTH ) {
        printf("invalid mac size %d in encrypted value\n", mac_size);
        return 1;
    }

    unsigned char lmac [MAC_LENGTH + 1];
 	for (i = 0; i < MAC_LENGTH; i++) {
        sscanf(in_pos, "%2hx", &lmac[i]);
        in_pos += 2;
    }
    mac = lmac;
    phex("mac", mac, MAC_LENGTH);

    uint32_t cipher_size;
    sscanf(in_pos, "%8lx", &cipher_size);
    printf("cipher_size_hex: %08X\n", cipher_size);
    printf("cipher_size: %d\n", cipher_size);
    in_pos += 8;

    unsigned char ctext [cipher_size + 1];
 	for (i = 0; i < cipher_size; i++) {
        sscanf(in_pos, "%2hx", &ctext[i]);
        in_pos += 2;
    }
    ciphertext = ctext;
    phex("ciphertext", ciphertext, cipher_size);

    return 0;
}


int main(int argc, char **argv) {

    if ( argc != 3 ) {
        printf("usage: decrypt <private_key_file> <crypted_hex>\n");
        return 1;
    }

    unsigned char private_key [KEY_LENGTH + 1];
    uint8_t err = key_from_file(argv[1], private_key);
    if ( err > 0 ) exit(err);
#ifdef DEBUG
    phex("private_key", private_key, KEY_LENGTH);
#endif

    unsigned char * public_key;
    unsigned char * mac;
    unsigned char * ciphertext;
    err = parse_packed_data(argv[2], public_key, mac, ciphertext);
    if ( err > 0 ) exit(err);


    const unsigned SHARED_SIZE = 32;
    uint8_t shared [SHARED_SIZE];
    curve25519_donna(shared, private_key, public_key);
    phex("shared", shared, SHARED_SIZE);

    SHA256_HASH shared_sha256;
    Sha256Calculate(shared, SHARED_SIZE, &shared_sha256);

    const unsigned PART_SIZE = 16;
    uint8_t encrypt_key [PART_SIZE];
    uint8_t sign_key [PART_SIZE];
    int i;
 	for (i = 0; i < PART_SIZE; i++) {
        encrypt_key[i] = shared_sha256.bytes[i];
    }
 	for (i = 0; i < PART_SIZE; i++) {
        sign_key[i] = shared_sha256.bytes[i + PART_SIZE];
    }

    phex("encrypt_key", encrypt_key, PART_SIZE);
    phex("sign_key", sign_key, PART_SIZE);

    SHA256_HASH public_sha256;
    Sha256Calculate(public_key, KEY_LENGTH, &public_sha256);

    phex("public_sha256", public_sha256.bytes, 32);
    uint8_t iv [16];
 	for (i = 0; i < 16; i++) {
        iv[i] = public_sha256.bytes[i];
    }
    phex("iv", iv, 16);

    // TODO: check MAC!

    struct AES_ctx ctx;
    int cipher_size = sizeof &ciphertext;
    AES_init_ctx_iv(&ctx, encrypt_key, iv);
    AES_CBC_decrypt_buffer(&ctx, &ciphertext, cipher_size);
    phex("ciphertext", &ciphertext, cipher_size);
    uint8_t pad_size = ciphertext[cipher_size-1];
 	for (i = cipher_size - pad_size; i < cipher_size; i++) {
        ciphertext[i] = 0;
    }
    phex("ciphertext no padding", ciphertext, cipher_size);
    printf("decrypted: %s", ciphertext);

    return 0;
}

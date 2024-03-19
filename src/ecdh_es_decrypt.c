#include <stdio.h>
#include <string.h>

#ifdef DEBUG
#define DPRINTF 1
#else
#define DPRINTF 0
#endif

#define dprintf(fmt, ...) \
    do { if (DPRINTF) printf(fmt, __VA_ARGS__); } while (0)

#include "curve25519-donna.c"
#include "aes.c"
#include "hmac_sha256.c"
#include "sha256.c"

const unsigned KEY_LENGTH     = 32;
const unsigned HEX_LENGTH     = 64;


void phex (const char * txt, const uint8_t * in, const size_t size) {
#ifdef DEBUG
    printf("%s: ", txt);
    int i;
    for (i = 0; i < size; i++) {
        printf("%02X", in[i]);
    }
    printf("\n");
#endif
}


uint8_t key_from_file (const char * fname, uint8_t * key) {

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
        sscanf(pkh_pos, "%2hhx", &key[i]);
        pkh_pos += 2;
    }

    return 0;
}


int parse_packed_data (char * data, uint8_t ** public_key, uint8_t ** mac, uint8_t ** ciphertext) {

    unsigned char * in_pos = data;
    dprintf("parsing data: >>%s<<\n", data);

    uint8_t option_count;
    sscanf(in_pos, "%2hhx", &option_count);
    in_pos += 2 + option_count * 2;
    dprintf("option_count: %d\n", option_count);

    uint8_t public_size;
    sscanf(in_pos, "%2hhx", &public_size);
    in_pos += 2;
    if ( public_size != KEY_LENGTH ) {
        printf("invalid public key length %d in encrypted value\n", public_size);
        return 0;
    }
    dprintf("public_size: %d\n", public_size);

    int i;
    *public_key = malloc((KEY_LENGTH + 1));
 	for (i = 0; i < KEY_LENGTH; i++) {
        sscanf(in_pos, "%2hhx", &(*public_key)[i]);
        in_pos += 2;
    }
    phex("public_key", *public_key, KEY_LENGTH);

    const uint16_t MAC_LENGTH = 32;
    uint16_t mac_size;
    sscanf(in_pos, "%4hhx", &mac_size);
    dprintf("mac_size_hex: %04X\n", mac_size);
    dprintf("mac_size: %d\n", mac_size);
    in_pos += 4;

    if ( mac_size != MAC_LENGTH ) {
        printf("invalid mac size %d in encrypted value\n", mac_size);
        return 0;
    }

    *mac = malloc(MAC_LENGTH + 1);
 	for (i = 0; i < MAC_LENGTH; i++) {
        sscanf(in_pos, "%2hhx", &(*mac)[i]);
        in_pos += 2;
    }
    phex("mac", *mac, MAC_LENGTH);

    long unsigned int cipher_size;
    sscanf(in_pos, "%8lx", &cipher_size);
    dprintf("cipher_size_hex: %08lX\n", cipher_size);
    dprintf("cipher_size: %ld\n", cipher_size);
    in_pos += 8;

    *ciphertext = malloc(cipher_size + 1);
 	for (i = 0; i < cipher_size; i++) {
        sscanf(in_pos, "%2hhx", &(*ciphertext)[i]);
        in_pos += 2;
    }
    phex("ciphertext", *ciphertext, cipher_size);

    return cipher_size;
}


int main(int argc, char **argv) {

    if ( argc != 3 ) {
        printf("usage: decrypt <private_key_file> <crypted_hex>\n");
        return 1;
    }

    // private key from file
    uint8_t private_key [KEY_LENGTH + 1];
    uint8_t err = key_from_file(argv[1], private_key);
    if ( err > 0 ) exit(err);
    phex("private_key", private_key, KEY_LENGTH);

    // unpack encrypted hex string from argv[2]
    uint8_t *public_key;
    uint8_t * mac;
    uint8_t * ciphertext;
    int cipher_size = parse_packed_data(argv[2], &public_key, &mac, &ciphertext);
    if ( cipher_size == 0 ) return 1;
    phex("public_key", public_key, KEY_LENGTH);

    // generate shared key
    const unsigned SHARED_SIZE = 32;
    uint8_t shared [SHARED_SIZE];
    curve25519_donna(shared, private_key, public_key);
    phex("shared", shared, SHARED_SIZE);

    // take sha256 of shared key and split
    // into encrypt_key and sign_key (16 bytes each)
    SHA256_HASH shared_sha256;
    Sha256Calculate(shared, SHARED_SIZE, &shared_sha256);

    const unsigned PART_SIZE = 16;
    uint8_t encrypt_key [PART_SIZE];
    uint8_t sign_key [PART_SIZE];
    memcpy(encrypt_key, shared_sha256.bytes, PART_SIZE);
    memcpy(sign_key, &shared_sha256.bytes[PART_SIZE], PART_SIZE);
    phex("encrypt_key", encrypt_key, PART_SIZE);
    phex("sign_key", sign_key, PART_SIZE);

    // take sha256 from public key and use first 16 bytes as iv
    SHA256_HASH public_sha256;
    Sha256Calculate(public_key, KEY_LENGTH, &public_sha256);

    phex("public_sha256", public_sha256.bytes, 32);
    uint8_t iv [16];
    memcpy(iv, public_sha256.bytes, 16);
    phex("iv", iv, 16);

    int data_size = 16 + cipher_size;
    uint8_t calc_data[data_size];
    memcpy(calc_data, iv, 16);
    memcpy(calc_data+16, ciphertext, cipher_size);
    uint8_t calc_mac[32];
    phex("calc_data", calc_data, data_size);

    hmac_sha256(sign_key, PART_SIZE, calc_data, data_size, calc_mac, 32);
    phex("calc_mac", calc_mac, 32);
    if ( memcmp(mac, calc_mac, 32) ) {
        printf("MAC is incorrect\n");
        return 1;
    }

    // decrypt ciphertext with encrypt_key and iv
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, encrypt_key, iv);
    AES_CBC_decrypt_buffer(&ctx, ciphertext, cipher_size);
    phex("ciphertext", ciphertext, cipher_size);

    // remove padding given in last character
    uint8_t pad_size = ciphertext[cipher_size-1];
    uint8_t pad_start = cipher_size - pad_size;
 	if ( pad_size != ciphertext[pad_start] ) {
 	    printf("incorrect padding in ciphertext\n");
 	    return 1;
 	}
 	memset(&ciphertext[pad_start], 0, pad_size);
    phex("ciphertext no padding", ciphertext, cipher_size);
    printf("%s", ciphertext);

    return 0;
}

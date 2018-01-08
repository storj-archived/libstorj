/**
 * Based on bip39 from trezor-crypto
 *
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "crypto.h"
#include "utils.h"
#include "bip39.h"
#include "bip39_english.h"

int mnemonic_generate(int strength, char **buffer)
{
    if (strength % 32 || strength < 128 || strength > 256) {
        return 0;
    }
    uint8_t data[32];
    random_buffer(data, 32);

    return mnemonic_from_data(data, strength / 8, buffer);
}

const uint16_t *mnemonic_generate_indexes(int strength)
{
    if (strength % 32 || strength < 128 || strength > 256) {
        return 0;
    }
    uint8_t data[32];
    random_buffer(data, 32);
    return mnemonic_from_data_indexes(data, strength / 8);
}

int mnemonic_from_data(const uint8_t *data, int len, char **buffer)
{
    if (len % 4 || len < 16 || len > 32) {
        return 0;
    }

    uint8_t bits[32 + 1];

    sha256_of_str(data, len, bits);
    // checksum
    bits[len] = bits[0];
    // data
    memcpy(bits, data, len);

    int mlen = len * 3 / 4;
    static char mnemo[24 * 10];

    int i, j, idx;
    char *p = mnemo;
    for (i = 0; i < mlen; i++) {
        idx = 0;
        for (j = 0; j < 11; j++) {
            idx <<= 1;
            idx += (bits[(i * 11 + j) / 8] &
                    (1 << (7 - ((i * 11 + j) % 8)))) > 0;
        }
        strcpy(p, wordlist[idx]);
        p += strlen(wordlist[idx]);
        *p = (i < mlen - 1) ? ' ' : 0;
        p++;
    }

    *buffer = calloc(strlen(mnemo) + 1, sizeof(char));
    if (!*buffer) {
        return 0;
    }

    strcpy(*buffer, mnemo);

    return 1;
}

const uint16_t *mnemonic_from_data_indexes(const uint8_t *data, int len)
{
    if (len % 4 || len < 16 || len > 32) {
        return 0;
    }

    uint8_t bits[32 + 1];

    sha256_of_str(data, len, bits);
    // checksum
    bits[len] = bits[0];
    // data
    memcpy(bits, data, len);

    int mlen = len * 3 / 4;
    static uint16_t mnemo[24];

    int i, j, idx;
    for (i = 0; i < mlen; i++) {
        idx = 0;
        for (j = 0; j < 11; j++) {
            idx <<= 1;
            idx += (bits[(i * 11 + j) / 8] &
                    (1 << (7 - ((i * 11 + j) % 8)))) > 0;
        }
        mnemo[i] = idx;
    }

    return mnemo;
}

// if doesn't return 1 then it failed.
bool mnemonic_check(const char *mnemonic)
{
    if (!mnemonic) {
        return 0;
    }

    uint32_t i, n;

    i = 0; n = 0;
    while (mnemonic[i]) {
        if (mnemonic[i] == ' ') {
            n++;
        }
        i++;
    }
    n++;
    // check number of words
    if (n != 12 && n != 15 && n != 18 && n != 21 && n != 24) {
        return 0;
    }

    char current_word[10];
    uint32_t j, k, ki, bi;
    uint8_t bits[32 + 1];
    memset(bits, 0, sizeof(bits));
    i = 0; bi = 0;
    while (mnemonic[i]) {
        j = 0;
        while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
            if (j >= sizeof(current_word) - 1) {
                return 0;
            }
            current_word[j] = mnemonic[i];
            i++; j++;
        }
        current_word[j] = 0;
        if (mnemonic[i] != 0) i++;
        k = 0;
        for (;;) {
            if (!wordlist[k]) { // word not found
                return 0;
            }
            // word found on index k
            if (strcmp(current_word, wordlist[k]) == 0) {
                for (ki = 0; ki < 11; ki++) {
                    if (k & (1 << (10 - ki))) {
                        bits[bi / 8] |= 1 << (7 - (bi % 8));
                    }
                    bi++;
                }
                break;
            }
            k++;
        }
    }
    if (bi != n * 11) {
        return 0;
    }
    bits[32] = bits[n * 4 / 3];
    sha256_of_str(bits, n * 4 / 3, bits);
    return bits[0] >> (8 - n/3) == bits[32] >> (8 - n/3); // compare CS number bits

}

int mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                     char **buffer)
{
    // If mnemonic is NULL, assume empty string
    if (!mnemonic) {
        mnemonic = "";
    }

    int passphraselen = strlen(passphrase);

    // We can't exceed a password of 256 bytes
    if (passphraselen > 256) {
        passphraselen = 256;
    }

    uint8_t *seed = calloc(SHA512_DIGEST_SIZE + 1, sizeof(char));
    uint8_t *salt = calloc(8 + 256, sizeof(char));
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, passphrase, passphraselen);

    pbkdf2_hmac_sha512 (
        strlen(mnemonic),
        (uint8_t *)mnemonic,
        BIP39_PBKDF2_ROUNDS,
        strlen((char *)salt), salt,
        SHA512_DIGEST_SIZE, seed);

    char *sha512_str = hex2str(SHA512_DIGEST_SIZE, seed);
    if (!sha512_str) {
        return 0;
    }

    memcpy(*buffer, sha512_str, SHA512_DIGEST_SIZE*2);

    memset_zero(sha512_str, SHA512_DIGEST_SIZE * 2 + 1);
    memset_zero(seed, SHA512_DIGEST_SIZE + 1);
    memset_zero(salt, 8 + 256);

    free(seed);
    free(salt);
    free(sha512_str);

    return 1;
}

const char * const *mnemonic_wordlist(void)
{
    return wordlist;
}

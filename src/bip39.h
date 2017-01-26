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

#ifndef STORJ_BIP39_H
#define STORJ_BIP39_H

#include <stdbool.h>
#include <stdint.h>

#define BIP39_PBKDF2_ROUNDS 2048

/**
 * @brief Generate a mnemonic string
 *
 * @param[in] strength Strength in bits of the mnemonic
 * @param[out] buffer character array of the mnemonic
 * @return A non-zero error value on failure and 0 on success.
 */
int mnemonic_generate(int strength, char **buffer);

const uint16_t *mnemonic_generate_indexes(int strength); // strength in bits

int mnemonic_from_data(const uint8_t *data, int len, char **buffer);

const uint16_t *mnemonic_from_data_indexes(const uint8_t *data, int len);

bool mnemonic_check(const char *mnemonic);

/**
 * @brief Generate seed from Mnemonic
 *
 * @param[in] mnemonic Character array of the mnemonic
 * @param[in] passphrase Optional password added as salt for hashing
 * @param[out] buffer Character array of sha512 hash of the mnemonic
 * @return A non-zero error value on failure and 0 on success.
 */
int mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                     char **buffer);

const char * const *mnemonic_wordlist(void);

#endif /* STORJ_BIP39_H */

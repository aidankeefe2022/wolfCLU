/* clu_crypto_flags.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef _WOLFSSL_CLU_CRYPTO_FLAGS_H_
#define _WOLFSSL_CLU_CRYPTO_FLAGS_H_

#include <wolfclu/clu_header_main.h>
#include <wolfcli/cli.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Cipher selection for the enc/encrypt/decrypt commands.
 *
 * The cipher names a flag of its own -- "enc -aes-256-cbc" -- rather than
 * being the argument of a -alg flag. That is how openssl spells it and what
 * the enc tests drive; it also sidesteps the framework rejecting any flag
 * argument that starts with '-'.
 *
 * Each flag takes no argument and carries the older wolfCLU size-last
 * spelling ("-aes-cbc-256") as an alt name, so both orders keep working.
 * They are all members of one exactly-one-of group, so a command line naming
 * no cipher, or two, is turned away by the parser rather than by hand.
 *
 * The flags are defined in src_framework_change/crypto/clu_crypto_flags.c and
 * are listed in the enc command's flag table in clu_crypto_setup.c. The build
 * guards below are repeated in both of those places and have to stay in step
 * with them: a cipher declared here but missing from the command's table is
 * one the parser will not recognize. */

#ifndef NO_AES
extern WOLFCLI_FLAG aes128CbcFlag;      /* -aes-128-cbc, -aes-cbc-128 */
extern WOLFCLI_FLAG aes192CbcFlag;      /* -aes-192-cbc, -aes-cbc-192 */
extern WOLFCLI_FLAG aes256CbcFlag;      /* -aes-256-cbc, -aes-cbc-256 */
#endif

/* wolfCLU_parseAlgo() only offers ctr when WOLFSSL_AES_COUNTER is set, and the
 * EVP ctr ciphers are not usable before wolfSSL 5.9.0 */
#if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER) && \
    LIBWOLFSSL_VERSION_HEX >= 0x05009000
extern WOLFCLI_FLAG aes128CtrFlag;      /* -aes-128-ctr, -aes-ctr-128 */
extern WOLFCLI_FLAG aes192CtrFlag;      /* -aes-192-ctr, -aes-ctr-192 */
extern WOLFCLI_FLAG aes256CtrFlag;      /* -aes-256-ctr, -aes-ctr-256 */
#endif

#ifndef NO_DES3
extern WOLFCLI_FLAG des3Cbc56Flag;      /* -3des-cbc-56,  -3des-56-cbc  */
extern WOLFCLI_FLAG des3Cbc112Flag;     /* -3des-cbc-112, -3des-112-cbc */
extern WOLFCLI_FLAG des3Cbc168Flag;     /* -3des-cbc-168, -3des-168-cbc */
#endif

#ifdef HAVE_CAMELLIA
extern WOLFCLI_FLAG camellia128CbcFlag; /* -camellia-128-cbc, -camellia-cbc-128 */
extern WOLFCLI_FLAG camellia192CbcFlag; /* -camellia-192-cbc, -camellia-cbc-192 */
extern WOLFCLI_FLAG camellia256CbcFlag; /* -camellia-256-cbc, -camellia-cbc-256 */
#endif

/* Name of the cipher flag that was set, in the spelling wolfCLU_getAlgo()
 * parses, or NULL when no cipher was named.
 *
 * A flag that was matched by its alt name still reports the canonical name,
 * so either spelling on the command line ends up at the same string here. */
const char* wolfCLU_getAlgFlagName(void);

#ifdef __cplusplus
}
#endif

#endif /* _WOLFSSL_CLU_CRYPTO_FLAGS_H_ */

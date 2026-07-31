/* clu_crypto_flags.c
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

/* The cipher selection flags for the enc/encrypt/decrypt commands. See
 * wolfclu/clu_crypto_flags.h for what they are and how they are spelled;
 * clu_crypto_setup.c lists them in the commands' flag table. */

#include <wolfclu/clu_crypto_flags.h>

#if defined(NO_AES) && defined(NO_DES3) && !defined(HAVE_CAMELLIA)

/* Nothing to pick from in this build, and C has no empty array to declare for
 * it. Every enc/dec run then fails at "no cipher was named", which is the
 * truth for such a build. */
const char* wolfCLU_getAlgFlagName(void)
{
    return NULL;
}

#else

/* Every cipher flag takes no argument, and for those the parser writes a found
 * marker through .value and refuses a NULL one. They all share this byte:
 * which cipher was picked is read back from the flags themselves, in
 * wolfCLU_getAlgFlagName, never from here. */
static char algFlagSeen;

/* defined below, once the flags it covers exist */
static WOLFCLI_FLAG_GROUP algGroup;

#ifndef NO_AES
WOLFCLI_FLAG aes128CbcFlag = {
    .flag = "-aes-128-cbc",
    .shortHelp = "Process the data with AES 128 bit CBC",
    .longHelp = "Process the data with AES 128 bit CBC. Also accepted as "
                "-aes-cbc-128",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-aes-cbc-128"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};

WOLFCLI_FLAG aes192CbcFlag = {
    .flag = "-aes-192-cbc",
    .shortHelp = "Process the data with AES 192 bit CBC",
    .longHelp = "Process the data with AES 192 bit CBC. Also accepted as "
                "-aes-cbc-192",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-aes-cbc-192"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};

WOLFCLI_FLAG aes256CbcFlag = {
    .flag = "-aes-256-cbc",
    .shortHelp = "Process the data with AES 256 bit CBC",
    .longHelp = "Process the data with AES 256 bit CBC. Also accepted as "
                "-aes-cbc-256",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-aes-cbc-256"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};
#endif /* !NO_AES */

#if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER) && \
    LIBWOLFSSL_VERSION_HEX >= 0x05009000
WOLFCLI_FLAG aes128CtrFlag = {
    .flag = "-aes-128-ctr",
    .shortHelp = "Process the data with AES 128 bit CTR",
    .longHelp = "Process the data with AES 128 bit CTR. Also accepted as "
                "-aes-ctr-128",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-aes-ctr-128"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};

WOLFCLI_FLAG aes192CtrFlag = {
    .flag = "-aes-192-ctr",
    .shortHelp = "Process the data with AES 192 bit CTR",
    .longHelp = "Process the data with AES 192 bit CTR. Also accepted as "
                "-aes-ctr-192",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-aes-ctr-192"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};

WOLFCLI_FLAG aes256CtrFlag = {
    .flag = "-aes-256-ctr",
    .shortHelp = "Process the data with AES 256 bit CTR",
    .longHelp = "Process the data with AES 256 bit CTR. Also accepted as "
                "-aes-ctr-256",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-aes-ctr-256"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};
#endif /* AES CTR */

/* 3DES is the one family whose canonical name puts the size last:
 * "3des-cbc-56" is the only spelling wolfCLU has ever documented. */
#ifndef NO_DES3
WOLFCLI_FLAG des3Cbc56Flag = {
    .flag = "-3des-cbc-56",
    .shortHelp = "Process the data with 3DES 56 bit CBC",
    .longHelp = "Process the data with 3DES 56 bit CBC. Also accepted as "
                "-3des-56-cbc",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-3des-56-cbc"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};

WOLFCLI_FLAG des3Cbc112Flag = {
    .flag = "-3des-cbc-112",
    .shortHelp = "Process the data with 3DES 112 bit CBC",
    .longHelp = "Process the data with 3DES 112 bit CBC. Also accepted as "
                "-3des-112-cbc",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-3des-112-cbc"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};

WOLFCLI_FLAG des3Cbc168Flag = {
    .flag = "-3des-cbc-168",
    .shortHelp = "Process the data with 3DES 168 bit CBC",
    .longHelp = "Process the data with 3DES 168 bit CBC. Also accepted as "
                "-3des-168-cbc",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-3des-168-cbc"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};
#endif /* !NO_DES3 */

#ifdef HAVE_CAMELLIA
WOLFCLI_FLAG camellia128CbcFlag = {
    .flag = "-camellia-128-cbc",
    .shortHelp = "Process the data with Camellia 128 bit CBC",
    .longHelp = "Process the data with Camellia 128 bit CBC. Also accepted as "
                "-camellia-cbc-128",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-camellia-cbc-128"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};

WOLFCLI_FLAG camellia192CbcFlag = {
    .flag = "-camellia-192-cbc",
    .shortHelp = "Process the data with Camellia 192 bit CBC",
    .longHelp = "Process the data with Camellia 192 bit CBC. Also accepted as "
                "-camellia-cbc-192",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-camellia-cbc-192"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};

WOLFCLI_FLAG camellia256CbcFlag = {
    .flag = "-camellia-256-cbc",
    .shortHelp = "Process the data with Camellia 256 bit CBC",
    .longHelp = "Process the data with Camellia 256 bit CBC. Also accepted as "
                "-camellia-cbc-256",
    .value = &algFlagSeen,
    .optionalArgs.altNames = {(const char*[]){"-camellia-cbc-256"}, 1},
    .optionalArgs.groups = {(WOLFCLI_FLAG_GROUP *[]){&algGroup}, 1},
};
#endif /* HAVE_CAMELLIA */

/* The group's membership, and what wolfCLU_getAlgFlagName walks. */
static WOLFCLI_FLAG* algFlags[] = {
#ifndef NO_AES
    &aes128CbcFlag,
    &aes192CbcFlag,
    &aes256CbcFlag,
#endif
#if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER) && \
    LIBWOLFSSL_VERSION_HEX >= 0x05009000
    &aes128CtrFlag,
    &aes192CtrFlag,
    &aes256CtrFlag,
#endif
#ifndef NO_DES3
    &des3Cbc56Flag,
    &des3Cbc112Flag,
    &des3Cbc168Flag,
#endif
#ifdef HAVE_CAMELLIA
    &camellia128CbcFlag,
    &camellia192CbcFlag,
    &camellia256CbcFlag,
#endif
};

/* The framework truncates its own member list well before it can hold every
 * cipher, so the description points at the help menu rather than repeating
 * them. */
static WOLFCLI_FLAG_GROUP algGroup = {
    .name = "Cipher group",
    .groupDescription = "Name the cipher with its own flag, for example "
        "-aes-256-cbc. Run with -h for the ciphers this build has.",
    .flags = algFlags,
    .flagsSz = sizeof(algFlags) / sizeof(*algFlags),
    .maxSet = 1,
    .minSet = 1,
};

const char* wolfCLU_getAlgFlagName(void)
{
    unsigned int i;

    for (i = 0; i < sizeof(algFlags) / sizeof(*algFlags); i++) {
        if (algFlags[i]->found == WOLFCLI_FLAG_FOUND) {
            return algFlags[i]->flag;
        }
    }

    return NULL;
}

#endif /* any cipher compiled in */

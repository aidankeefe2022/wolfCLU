
#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfcli/cli.h>
#include<wolfclu/clu_arg_handlers.h>
#include <wolfclu/clu_crypto_flags.h>

static char* inFile = NULL;
static char* outFile = NULL;
static WOLFSSL_EVP_MD* hashType = NULL;

/* wolfCLU_handleCopyString writes through a {capacity, buffer pointer} pair,
 * so each of these keeps the backing array separate from the descriptor the
 * handler is handed. */
static char ivBuf[500];
static struct {
    unsigned int cap;
    char* data;
} ivString = {sizeof(ivBuf) - 1, ivBuf};

static char keyBuf[500];
static struct {
    unsigned int cap;
    char* data;
} keyString = {sizeof(keyBuf) - 1, keyBuf};

/* -inkey names a file to read the key from, so it stores a plain string
 * (wolfCLI_handleString) rather than sharing keyString's {cap, buffer}
 * descriptor -- the decoded key lands in keyBuf only after the file is read. */
static char* keyFileName = NULL;

static struct passwordStruct {
    int passwordSz;
    char password[256];
} passwordArg = {0};

/* copy-string view of passwordArg.password, used by -pwd */
static struct {
    unsigned int cap;
    char* data;
} passwordCopyArg = {sizeof(passwordArg.password) - 1, passwordArg.password};

static byte isBase64 = 0;
static byte isPkbVerion2 = 0;
static byte noSalt = 0;

static WOLFCLI_FLAG inFlag;
static WOLFCLI_FLAG hashFlag;
static WOLFCLI_FLAG outFlag;
static WOLFCLI_FLAG ivFlag;
static WOLFCLI_FLAG keyFlag;
static WOLFCLI_FLAG keyFileFlag;
static WOLFCLI_FLAG pwdFlag;
static WOLFCLI_FLAG passwordFlag;
static WOLFCLI_FLAG saltFlag;
static WOLFCLI_FLAG base64Flag;

/* C89 has no compound literals, so the membership arrays the groups and the
 * flags point at are named here rather than written inline. */
static WOLFCLI_FLAG* passwordGroupFlags[] = {
    &pwdFlag, &keyFileFlag, &keyFlag, &passwordFlag
};

static WOLFCLI_FLAG* ivSaltGroupFlags[] = { &ivFlag, &saltFlag };

static WOLFCLI_FLAG_GROUP passwordMutualExclusionGroup = {
    /*name=*/"Password/Key group",
    /*groupDescription=*/"Must set one of these flags",
    /*flags=*/passwordGroupFlags,
    /*flagsSz=*/sizeof(passwordGroupFlags) / sizeof(*passwordGroupFlags),
    /*minSet=*/1,
    /*maxSet=*/1,
    /*priv=*/{0}
};

static WOLFCLI_FLAG_GROUP ivSaltMutex = {
    /*name=*/"Iv/NoSalt group",
    /*groupDescription=*/"Can only set one of these flags",
    /*flags=*/ivSaltGroupFlags,
    /*flagsSz=*/sizeof(ivSaltGroupFlags) / sizeof(*ivSaltGroupFlags),
    /*minSet=*/0,
    /*maxSet=*/1,
    /*priv=*/{0}
};

static WOLFCLI_FLAG_GROUP* passwordGroupOnly[] = {
    &passwordMutualExclusionGroup
};
static WOLFCLI_FLAG_GROUP* ivSaltGroupOnly[] = { &ivSaltMutex };
static WOLFCLI_FLAG* ivFlagOnly[] = { &ivFlag };

static const char* pwdAltNames[] = { "-k" };
static const char* keyAltNames[] = { "--key" };
static const char* ivAltNames[]  = { "--iv" };

static const char keyLongHelp[] =
"hex key input: \n\
    -inkey -> <file with key> \n\
";

static const char hashLongHelp[] =
"Hash alg for creating digest of message \n\
    Algs: \n\
        ├─ sha \n\
        ├─ sha224 \n\
        ├─ sha265 \n\
        ├─ sha384 \n\
        └─ sha512";

static int handlePasswordArg(const char* arg, void* out);

static WOLFCLI_FLAG kdfVersionFlag = {
    /*flag=*/"-pbkdf2",
    /*shortHelp=*/"Use kdf version 2",
    /*longHelp=*/"Use kdf version 2",
    /*value=*/&isPkbVerion2,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{0}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG base64Flag = {
    /*flag=*/"-base64",
    /*shortHelp=*/"Decode base64 input before enc/dec",
    /*longHelp=*/"Decode base64 input before enc/dec",
    /*value=*/&isBase64,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{0}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG saltFlag = {
    /*flag=*/"-nosalt",
    /*shortHelp=*/"Do not salt the hash",
    /*longHelp=*/"Do not salt the hash",
    /*value=*/&noSalt,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{ivSaltGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG passwordFlag = {
    /*flag=*/"-pass",
    /*shortHelp=*/"password input [stdin|pass:<password>]",
    /*longHelp=*/"password input: [stdin|pass:<password>]",
    /*value=*/NULL,
    /*argHandler=*/handlePasswordArg,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{0},
        /*groups=*/{passwordGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG pwdFlag = {
    /*flag=*/"-pwd",
    /*shortHelp=*/"password input",
    /*longHelp=*/"password input",
    /*value=*/&passwordCopyArg,
    /*argHandler=*/wolfCLU_handleCopyString,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{pwdAltNames, 1},
        /*groups=*/{passwordGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG keyFileFlag = {
    /*flag=*/"-inkey",
    /*shortHelp=*/"File with hex key",
    /*longHelp=*/"File with hex key",
    /*value=*/&keyFileName,
    /*argHandler=*/wolfCLI_handleString,
    /*optionalArgs=*/{
        /*dependsOn=*/{ivFlagOnly, 1},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{0},
        /*groups=*/{passwordGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};


static WOLFCLI_FLAG keyFlag = {
    /*flag=*/"-key",
    /*shortHelp=*/"hex key input",
    /*longHelp=*/keyLongHelp,
    /*value=*/&keyString,
    /*argHandler=*/wolfCLU_handleCopyString,
    /*optionalArgs=*/{
        /*dependsOn=*/{ivFlagOnly, 1},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{keyAltNames, 1},
        /*groups=*/{passwordGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG ivFlag = {
    /*flag=*/"-iv",
    /*shortHelp=*/"hex iv input",
    /*longHelp=*/"hex iv input",
    /*value=*/&ivString,
    /*argHandler=*/wolfCLU_handleCopyString,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{ivAltNames, 1},
        /*groups=*/{ivSaltGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG hashFlag = {
    /*flag=*/"-hash",
    /*shortHelp=*/"Hash alg for creating digest of message",
    /*longHelp=*/hashLongHelp,
    /*value=*/&hashType,
    /*argHandler=*/wolfCLU_handleGetHash,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{0},
        /*groups=*/{0}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG inFlag = {
    /*flag=*/"-in",
    /*shortHelp=*/"Input File to process",
    /*longHelp=*/"Input File to process",
    /*value=*/&inFile,
    /*argHandler=*/wolfCLI_handleString,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{0},
        /*groups=*/{0}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG outFlag = {
    /*flag=*/"-out",
    /*shortHelp=*/"Input File to process",
    /*longHelp=*/"Input File to process",
    /*value=*/&outFile,
    /*argHandler=*/wolfCLI_handleString,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{0},
        /*groups=*/{0}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static int handlePasswordArg(const char* arg, void* out)
{
    (void)out;
    passwordArg.passwordSz = 256;
    if (wolfCLU_GetPassword(passwordArg.password, &passwordArg.passwordSz,
            (char*)arg) == WOLFCLU_SUCCESS) {
        return WOLFCLI_SUCCESS;
    }

    return WOLFCLU_FATAL_ERROR;
}

/* The cipher flags come from clu_crypto_flags.c. Every one of them has to be
 * named here or the parser will not recognize it, so the build guards below
 * have to match the ones the flags are declared under in
 * wolfclu/clu_crypto_flags.h. */
static WOLFCLI_FLAG* decryptFlags[] = {
    &inFlag,
    &outFlag,
    &hashFlag,
    &ivFlag,
    &keyFlag,
    &keyFileFlag,
    &passwordFlag,
    &pwdFlag,
    &saltFlag,
    &base64Flag,
    &kdfVersionFlag,
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

/* Decode a hex key string into the caller-provided keyOut buffer.
 *
 * Wraps wolfCLU_hexToBin so the caller's pre-allocated key buffer is not
 * replaced by hexToBin's internal allocation (which would leak the original
 * and, on hexToBin failure, leave the caller pointing at a freed buffer).
 *
 * Returns WOLFCLU_SUCCESS on success, WOLFCLU_FATAL_ERROR on length mismatch
 * or hex decode failure, MEMORY_E on allocation failure. */
static int wolfCLU_loadHexKeyInto(byte* keyOut, int keyBytes,
                                   const char* hex, word32 hexLen)
{
    byte*  tmp = NULL;
    word32 tmpSz = 0;
    char*  hexCopy;
    int    ret;

    if (hexLen != (word32)keyBytes * 2) {
        WOLFCLU_LOG(WOLFCLU_L0, "Length of key provided was: %u.",
                (unsigned int)(hexLen * 4));
        WOLFCLU_LOG(WOLFCLU_L0, "Length of key expected was: %d.",
                keyBytes * 8);
        WOLFCLU_LOG(WOLFCLU_E0,
                "Invalid Key. Must match algorithm key size.");
        return WOLFCLU_FATAL_ERROR;
    }

    hexCopy = (char*)XMALLOC(hexLen + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (hexCopy == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(hexCopy, hex, hexLen);
    hexCopy[hexLen] = '\0';

    ret = wolfCLU_hexToBin(hexCopy, &tmp, &tmpSz,
                           NULL, NULL, NULL,
                           NULL, NULL, NULL,
                           NULL, NULL, NULL);
    wolfCLU_ForceZero(hexCopy, hexLen);
    XFREE(hexCopy, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret != WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_E0,
                "failed during conversion of Key, ret = %d", ret);
        /* On failure wolfCLU_hexToBin frees its own internal buffer; do not
         * touch tmp here. Propagate MEMORY_E unchanged so callers (and the
         * documented contract above) can distinguish allocation failure
         * from a generic decode error. */
        return (ret == MEMORY_E) ? MEMORY_E : WOLFCLU_FATAL_ERROR;
    }

    XMEMCPY(keyOut, tmp, keyBytes);
    wolfCLU_ForceZero(tmp, tmpSz);
    /* tmp was allocated by wolfCLU_hexToBin with a NULL heap hint
     * (see src/tools/clu_hex_to_bin.c); free it with the same hint. */
    XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return WOLFCLU_SUCCESS;
}

/* Decode a hex IV string into the caller-provided ivOut buffer.
 *
 * Like wolfCLU_loadHexKeyInto, the hex text is copied out before decoding, so
 * `hex` may alias `ivOut` (the -iv handler leaves the hex text sitting in the
 * same buffer the decoded IV has to end up in).
 *
 * Returns WOLFCLU_SUCCESS on success, WOLFCLU_FATAL_ERROR on a block-length
 * mismatch or hex decode failure, MEMORY_E on allocation failure. */
static int wolfCLU_loadHexIvInto(byte* ivOut, int block,
                                  const char* hex, word32 hexLen)
{
    byte*  tmp = NULL;
    word32 tmpSz = 0;
    char*  hexCopy;
    int    ret;

    hexCopy = (char*)XMALLOC(hexLen + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (hexCopy == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(hexCopy, hex, hexLen);
    hexCopy[hexLen] = '\0';

    ret = wolfCLU_hexToBin(hexCopy, &tmp, &tmpSz,
                           NULL, NULL, NULL,
                           NULL, NULL, NULL,
                           NULL, NULL, NULL);
    wolfCLU_ForceZero(hexCopy, hexLen);
    XFREE(hexCopy, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret != WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_E0,
                "failed during conversion of IV, ret = %d", ret);
        /* wolfCLU_hexToBin frees its own buffer on failure; tmp is not ours. */
        return (ret == MEMORY_E) ? MEMORY_E : WOLFCLU_FATAL_ERROR;
    }

    if ((int)tmpSz != block) {
        WOLFCLU_LOG(WOLFCLU_E0,
                "IV length mismatch: expected %d bytes, got %u",
                block, (unsigned int)tmpSz);
        wolfCLU_ForceZero(tmp, tmpSz);
        XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return WOLFCLU_FATAL_ERROR;
    }

    XMEMCPY(ivOut, tmp, tmpSz);
    wolfCLU_ForceZero(tmp, tmpSz);
    /* Allocated by wolfCLU_hexToBin with a NULL heap hint; match it. */
    XFREE(tmp, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return WOLFCLU_SUCCESS;
}

/* Prompt for a filename on stdin with validation.
 * Returns WOLFCLU_SUCCESS on success, WOLFCLU_FATAL_ERROR on EOF/read error.
 * buf is filled with the stripped, non-empty filename on success. */
static int wolfCLU_readFilename(char* buf, int bufSz, const char* prompt)
{
    while (1) {
        WOLFCLU_LOG(WOLFCLU_L0, "%s", prompt);
        if (fgets(buf, bufSz, stdin) == NULL) {
            wolfCLU_LogError("failed to read file name");
            return WOLFCLU_FATAL_ERROR;
        }
        /* If no newline, line was too long: flush remainder and re-prompt */
        if (strchr(buf, '\n') == NULL) {
            int ch;
            do {
                ch = getchar();
            } while (ch != '\n' && ch != EOF);
            wolfCLU_LogError("input too long, please try again");
            continue;
        }
        buf[strcspn(buf, "\r\n")] = '\0';
        if (buf[0] == '\0') {
            wolfCLU_LogError("empty input, please enter a file name");
            continue;
        }
        return WOLFCLU_SUCCESS;
    }
}


static int commonEntry(char isEncrypt)
{
    int ret = WOLFCLU_FATAL_ERROR;
    const WOLFSSL_EVP_CIPHER* cphr = NULL;
    int keyType = WOLFCLU_KEYTYPE_NONE;
    char inNameBuf[256];


    int alg;
    char* mode;
    int keySize;
    int block;
    /* wolfCLU_getAlgo() reads the name out of an argv style array, so build one
     * whose third entry is the cipher flag's name */
    char* algArgv[3];
    const char* algName = wolfCLU_getAlgFlagName();

    if (algName == NULL) {
        wolfCLU_LogError("no cipher was named");
        return WOLFCLU_FATAL_ERROR;
    }

    algArgv[0] = (char*)"";
    algArgv[1] = (char*)"";
    algArgv[2] = (char*)algName;

    /* gets blocksize, algorithm, mode, and key size from name argument */
    block = wolfCLU_getAlgo(3, algArgv, &alg, &mode, &keySize);
    if (block < 0) {
        wolfCLU_LogError("unable to find algorithm to use");
        return WOLFCLU_FATAL_ERROR;
    }

    cphr = wolfCLU_CipherTypeFromAlgo(alg);

    if (keyFileFlag.found) {
        WOLFSSL_BIO* keyBio = NULL;
        byte* fileBuf = NULL;
        int   fileLen = 0;
        int   keyBytes = (keySize + 7) / 8;
        int   isHex = 1;
        int   i;

        if (keyFileName == NULL) {
            wolfCLU_LogError("no key file passed in..");
            XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLI_FATAL_ERROR;
        }

        /* -inkey is "input file for key" (matches the help text and
         * openssl convention). The argument must name a real file;
         * use -key for a hex key on the command line. */
        keyBio = wolfSSL_BIO_new_file(keyFileName, "rb");
        if (keyBio == NULL) {
            wolfCLU_LogError("could not open key file '%s'", keyFileName);
            XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLI_FATAL_ERROR;
        }

        fileLen = wolfSSL_BIO_get_len(keyBio);
        if (fileLen <= 0) {
            wolfCLU_LogError("key file '%s' is empty or unreadable",
                    keyFileName);
            wolfSSL_BIO_free(keyBio);
            XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLI_FATAL_ERROR;
        }

        fileBuf = (byte*)XMALLOC(fileLen, HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (fileBuf == NULL) {
            wolfSSL_BIO_free(keyBio);
            XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLI_FATAL_ERROR;
        }

        if (wolfSSL_BIO_read(keyBio, fileBuf, fileLen) != fileLen) {
            wolfCLU_LogError("failed to read key file '%s'", keyFileName);
            wolfCLU_ForceZero(fileBuf, fileLen);
            XFREE(fileBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_BIO_free(keyBio);
            XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLU_FATAL_ERROR;
        }
        wolfSSL_BIO_free(keyBio);

        /* Decide hex vs raw by inspecting every byte. Whitespace
         * (\r \n space tab) is allowed inside hex files as a
         * separator; any non-hex non-whitespace byte means the
         * file is raw binary. fileLen is left unmodified so a
         * raw-binary key whose last byte is 0x09/0x0A/0x0D/0x20
         * still round-trips correctly. */
        for (i = 0; i < fileLen; i++) {
            byte c = fileBuf[i];
            if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                continue;
            }
            if (!wolfCLU_isHexDigit(c)) {
                isHex = 0;
                break;
            }
        }

        if (isHex) {
            char* hexKeyString;
            int   j = 0;

            hexKeyString = (char*)XMALLOC(fileLen + 1, HEAP_HINT,
                    DYNAMIC_TYPE_TMP_BUFFER);
            /* Copy out hex characters, skipping any embedded
             * whitespace so block-formatted hex files work. */
            for (i = 0; i < fileLen; i++) {
                byte c = fileBuf[i];
                if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                    continue;
                }
                hexKeyString[j++] = (char)c;
            }
            hexKeyString[j] = '\0';

            ret = wolfCLU_loadHexKeyInto((byte*)keyBuf, keyBytes,
                    hexKeyString, (word32)j);
            wolfCLU_ForceZero(hexKeyString, j);
            XFREE(hexKeyString, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            wolfCLU_ForceZero(fileBuf, fileLen);
            XFREE(fileBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (ret != WOLFCLU_SUCCESS) {
                XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                return ret;
            }
        }
        else {
            /* Raw binary key. Length must match the algorithm. */
            if (fileLen != keyBytes) {
                WOLFCLU_LOG(WOLFCLU_L0,
                        "Length of key provided was: %d bits.",
                        fileLen * 8);
                WOLFCLU_LOG(WOLFCLU_L0,
                        "Length of key expected was: %d bits.",
                        keySize);
                WOLFCLU_LOG(WOLFCLU_E0,
                        "Invalid Key. Must match algorithm key size.");
                wolfCLU_ForceZero(fileBuf, fileLen);
                XFREE(fileBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                return WOLFCLU_FATAL_ERROR;
            }
            XMEMCPY(keyBuf, fileBuf, fileLen);
            wolfCLU_ForceZero(fileBuf, fileLen);
            XFREE(fileBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
    else if (keyFlag.found) {
        /* -key carries the key as hex on the command line. The arg handler
         * only copied the hex text into keyBuf; decode it in place now that
         * the algorithm (and so the expected key length) is known. */
        ret = wolfCLU_loadHexKeyInto((byte*)keyBuf, (keySize + 7) / 8,
                keyBuf, (word32)XSTRLEN(keyBuf));
        if (ret != WOLFCLU_SUCCESS) {
            XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    }

    if (ivFlag.found) {
        /* Same story as -key: ivBuf still holds hex text at this point. */
        ret = wolfCLU_loadHexIvInto((byte*)ivBuf, block, ivBuf,
                (word32)XSTRLEN(ivBuf));
        if (ret != WOLFCLU_SUCCESS) {
            XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
    }

    if (keyFileFlag.found || keyFlag.found) {
        keyType = WOLFCLU_KEYTYPE_USER;

    }
    else {
        keyType = WOLFCLU_KEYTYPE_PASSWORD;
    }

    if (inFile == NULL) {
        ret = wolfCLU_readFilename(inNameBuf, sizeof(inNameBuf),
                "Please enter a name for the input file: ");
        if (ret != WOLFCLU_SUCCESS) {
            XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            return WOLFCLU_FATAL_ERROR;
        }
        inFile = inNameBuf;
    }

    if (cphr != NULL) {
        if (mode == NULL) {
            wolfCLU_LogError("mode was null");
        }
        /* keySz is the algorithm's key length in bytes (keySize is in bits),
         * and the PBKDF version must match what -encrypt used: version 1
         * (EVP_BytesToKey) unless -pbkdf2 was given. */
        ret = wolfCLU_evp_crypto(cphr, mode,
                (byte*)passwordArg.password, (byte*)keyBuf,
                (keySize + 7) / 8, inFile, outFile, NULL,
                (byte*)ivBuf, 0, isEncrypt,
                isPkbVerion2 ? WOLFCLU_PBKDF2 : WOLFCLU_PBKDF1,
                hashType == NULL ? wolfSSL_EVP_sha256() : hashType, 0,
                isBase64, noSalt, keyType);
    }
    else {
        char outNameBuf[256];
        if (outFile == NULL) {
            ret = wolfCLU_readFilename(outNameBuf, sizeof(outNameBuf),
                    "Please enter a name for the output file: ");
            if (ret != WOLFCLU_SUCCESS) {
                XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
                return WOLFCLU_FATAL_ERROR;
            }
            outFile = outNameBuf;
        }
        if (isEncrypt) {
            /* wolfCLU_encrypt's trailing params are (ivCheck, inputHex), not
             * (keyType, ...). ivCheck == 0 is what makes it generate a random
             * IV and stretch the password into the key, mirroring the
             * keyType == WOLFCLU_KEYTYPE_PASSWORD branch of wolfCLU_decrypt;
             * passing a non-zero keyType there skipped derivation entirely and
             * encrypted with an all-zero key/IV. No flag feeds hex input on
             * this path, so inputHex is always 0. */
            ret = wolfCLU_encrypt(alg, mode, (byte*)passwordArg.password,
                    (byte*)keyBuf, keySize, inFile, outFile,
                    (byte*)ivBuf, block,
                    keyType == WOLFCLU_KEYTYPE_USER, 0);
        }
        else {
            ret = wolfCLU_decrypt(alg, mode, (byte*)passwordArg.password,
                    (byte*)keyBuf, keySize, inFile, outFile,
                    (byte*)ivBuf, block, keyType);
        }
    }
    XFREE(mode, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

static int encryptEntry(void)
{
    return commonEntry(1);
}

static int decryptEntry(void)
{
    return commonEntry(0);
}

WOLFCLI_COMMAND decryptCommand;

static const char encryptLongHelp[] =
"Encrypts a file using a cipher and a password or key. The algorithm must\n\
match the one used for encryption. For AES and 3DES (EVP path),\n\
password-based decryption extracts the salt from the file and derives key\n\
and IV from the password and salt. For legacy non-EVP ciphers (e.g.\n\
Camellia), salt and IV are read from the file header.\n\
\n\
Name the cipher with a flag of its own, for example -aes-256-cbc. The flag\n\
list below carries every cipher this build has, each with the older\n\
size-last spelling it also answers to.";

static const char decryptLongHelp[] =
"Decrypts a file using a cipher and a password or key. The algorithm must\n\
match the one used for encryption. For AES and 3DES (EVP path),\n\
password-based decryption extracts the salt from the file and derives key\n\
and IV from the password and salt. For legacy non-EVP ciphers (e.g.\n\
Camellia), salt and IV are read from the file header. For explicit keys\n\
and IVs, you must provide the same values used during encryption.\n\
\n\
Name the cipher with a flag of its own, for example -aes-256-cbc. The flag\n\
list below carries every cipher this build has, each with the older\n\
size-last spelling it also answers to.";

static const char* encryptAltNames[] = { "enc", "-enc", "-encrypt" };
static const char* decryptAltNames[] = { "dec", "-dec", "-d", "-decrypt" };

static WOLFCLI_COMMAND* encryptSubCommands[] = { &decryptCommand };

WOLFCLI_COMMAND encryptCommand = {
    /*name=*/"encrypt",
    /*shortHelp=*/"Encrypt input file with provided algorithm",
    /*longHelp=*/encryptLongHelp,
    /*commandEntry=*/encryptEntry,
    /*commandCleanup=*/NULL,
    /*flags=*/{
        /*flags=*/decryptFlags,
        /*flagsSz=*/sizeof(decryptFlags) / sizeof(*decryptFlags)
    },
    /*commands=*/{
        /*commands=*/encryptSubCommands,
        /*commandsSz=*/sizeof(encryptSubCommands) / sizeof(*encryptSubCommands)
    },
    /*altNames=*/{
        /*altNames=*/encryptAltNames,
        /*altNamesSz=*/sizeof(encryptAltNames) / sizeof(*encryptAltNames)
    },
    /*priv=*/{0}
};

WOLFCLI_COMMAND decryptCommand = {
    /*name=*/"decrypt",
    /*shortHelp=*/"Decrypt input file with provided algorithm",
    /*longHelp=*/decryptLongHelp,
    /*commandEntry=*/decryptEntry,
    /*commandCleanup=*/NULL,
    /*flags=*/{
        /*flags=*/decryptFlags,
        /*flagsSz=*/sizeof(decryptFlags) / sizeof(*decryptFlags)
    },
    /*commands=*/{0},
    /*altNames=*/{
        /*altNames=*/decryptAltNames,
        /*altNamesSz=*/sizeof(decryptAltNames) / sizeof(*decryptAltNames)
    },
    /*priv=*/{0}
};

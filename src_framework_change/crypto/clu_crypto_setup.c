
#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfcli/cli.h>
#include<wolfclu/clu_arg_handlers.h>

static char* inFile = NULL;
static char* outFile = NULL;
static WOLFSSL_EVP_MD* hashType = NULL;
static char* decEncAlgString;

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
static WOLFCLI_FLAG algFlag;
static WOLFCLI_FLAG outFlag;
static WOLFCLI_FLAG ivFlag;
static WOLFCLI_FLAG keyFlag;
static WOLFCLI_FLAG keyFileFlag;
static WOLFCLI_FLAG pwdFlag;
static WOLFCLI_FLAG passwordFlag;
static WOLFCLI_FLAG saltFlag;
static WOLFCLI_FLAG base64Flag;

static WOLFCLI_FLAG_GROUP passwordMutualExclusionGroup = {
    .name = "Password/Key group",
    .groupDescription = "Must set one of these flags",
    .flags = (WOLFCLI_FLAG *[]){&pwdFlag, &keyFileFlag, &keyFlag, &passwordFlag},
    .flagsSz = 4,
    .maxSet = 1,
    .minSet = 1,
};

static WOLFCLI_FLAG_GROUP ivSaltMutex= {
    .name = "Iv/NoSalt group",
    .groupDescription = "Can only set one of these flags",
    .flags = (WOLFCLI_FLAG *[]){&ivFlag, &saltFlag},
    .flagsSz = 2,
    .maxSet = 1,
    .minSet = 0,
};

static int handlePasswordArg(const char* arg, void* out);

static WOLFCLI_FLAG kdfVersionFlag= {
    .flag = "-pbkdf2",
    .shortHelp = "Use kdf version 2",
    .longHelp = "Use kdf version 2",
    .value    = &isPkbVerion2
};

static WOLFCLI_FLAG base64Flag = {
    .flag = "-base64",
    .shortHelp = "Decode base64 input before enc/dec",
    .longHelp = "Decode base64 input before enc/dec",
    .value    = &isBase64
};

static WOLFCLI_FLAG saltFlag = {
    .flag = "-nosalt",
    .shortHelp = "Do not salt the hash",
    .longHelp = "Do not salt the hash",
    .value    = &noSalt,
    .optionalArgs.groups = {
        .groups = (WOLFCLI_FLAG_GROUP *[]){&ivSaltMutex},
        .groupsSz = 1
    }
};

static WOLFCLI_FLAG passwordFlag = {
    .flag = "-pass",
    .shortHelp = "password input [stdin|pass:<password>]",
    .longHelp = "password input: [stdin|pass:<password>]",
    .argHandler = handlePasswordArg,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
    .optionalArgs.groups = {
        .groups = (WOLFCLI_FLAG_GROUP *[]){&passwordMutualExclusionGroup},
        .groupsSz = 1
    },
};

static WOLFCLI_FLAG pwdFlag = {
    .flag = "-pwd",
    .shortHelp = "password input",
    .longHelp = "password input",
    .argHandler = wolfCLU_handleCopyString,
    .value = &passwordCopyArg,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
    .optionalArgs.altNames =
    {
        .altNames = (const char*[]){"-k"},
        .altNamesSz = 1,
    },
    .optionalArgs.groups = {
        .groups = (WOLFCLI_FLAG_GROUP *[]){&passwordMutualExclusionGroup},
        .groupsSz = 1
    },
};

static WOLFCLI_FLAG keyFileFlag = {
    .flag = "-inkey",
    .shortHelp = "File with hex key",
    .longHelp = "File with hex key",
    .value = &keyFileName,
    .argHandler = wolfCLI_handleString,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
    .optionalArgs.groups = {
        .groups = (WOLFCLI_FLAG_GROUP *[]){&passwordMutualExclusionGroup},
        .groupsSz = 1
    },
    .optionalArgs.dependsOn = {
        .flags = (WOLFCLI_FLAG *[]){&ivFlag},
        .flagsSz = 1,
    }
};


static WOLFCLI_FLAG keyFlag = {
    .flag = "-key",
    .shortHelp = "hex key input",
    .longHelp =
"hex key input: \n\
    -inkey -> <file with key> \n\
",
    .value = &keyString,
    .argHandler = wolfCLU_handleCopyString,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
    .optionalArgs.groups = {
        .groups = (WOLFCLI_FLAG_GROUP *[]){&passwordMutualExclusionGroup},
        .groupsSz = 1
    },
    .optionalArgs.dependsOn = {
        .flags = (WOLFCLI_FLAG *[]){&ivFlag},
        .flagsSz = 1,
    }
};

static WOLFCLI_FLAG ivFlag = {
    .flag = "-iv",
    .shortHelp = "hex iv input",
    .longHelp = "hex iv input",
    .value = &ivString,
    .argHandler = wolfCLU_handleCopyString,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
    .optionalArgs.groups = {
        .groups = (WOLFCLI_FLAG_GROUP *[]){&ivSaltMutex},
        .groupsSz = 1
    }
};

static WOLFCLI_FLAG hashFlag = {
    .flag = "-hash",
    .shortHelp = "Hash alg for creating digest of message",
    .longHelp =
"Hash alg for creating digest of message \n\
    Algs: \n\
        ├─ sha \n\
        ├─ sha224 \n\
        ├─ sha265 \n\
        ├─ sha384 \n\
        └─ sha512",
    .value = &hashType,
    .argHandler = wolfCLU_handleGetHash,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
};

static const char algLongHelp[] = (
"Algorothm to used to process data \n\
    Algorithms: \n"
#ifndef NO_AES
"       ├─aes-cbc-128\n"
"       ├─aes-cbc-192\n"
"       └─aes-cbc-256\n"
#endif
#if defined(WOLFSSL_AES_COUNTER) && \
    LIBWOLFSSL_VERSION_HEX >= 0x05009000
"       ├─aes-ctr-128\n"
"       ├─aes-ctr-192\n"
"       └─aes-ctr-256\n"
#endif
#ifndef NO_DES3
"       ├─3des-cbc-56\n"
"       ├─3des-cbc-112\n"
"       └─3des-cbc-168\n"
#endif
#ifdef HAVE_CAMELLIA
"       ├─camellia-cbc-128\n"
"       ├─camellia-cbc-192\n"
"       └─camellia-cbc-256\n"
#endif
        );

static WOLFCLI_FLAG algFlag = {
    .flag = "-alg",
    .shortHelp = "Algorothm to used to process data",
    .longHelp = algLongHelp,
    .value = &decEncAlgString,
    .argHandler = wolfCLI_handleString,
    .optionalArgs =
    {
        .modes = WOLFCLI_FLAG_REQUIRED | WOLFCLI_FLAG_HAS_ARG,
    },
};

static WOLFCLI_FLAG inFlag = {
    .flag = "-in",
    .shortHelp = "Input File to process",
    .longHelp = "Input File to process",
    .argHandler = wolfCLI_handleString,
    .value = &inFile,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
};

static WOLFCLI_FLAG outFlag = {
    .flag = "-out",
    .shortHelp = "Input File to process",
    .longHelp = "Input File to process",
    .argHandler = wolfCLI_handleString,
    .value = &outFile,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
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

static WOLFCLI_FLAG* decryptFlags[] = {
    &inFlag,
    &outFlag,
    &algFlag,
    &hashFlag,
    &ivFlag,
    &keyFlag,
    &keyFileFlag,
    &passwordFlag,
    &pwdFlag,
    &saltFlag,
    &base64Flag,
    &kdfVersionFlag,
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


    int alg;
    char* mode;
    int keySize;
    int block;
    /* gets blocksize, algorithm, mode, and key size from name argument */
    block = wolfCLU_getAlgo(3, (char *[]){(char*)"", (char*)"", decEncAlgString},
            &alg, &mode, &keySize);
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

    if (cphr != NULL) {
        if (mode == NULL) {
            wolfCLU_LogError("mdoe was null");
        }
        /* keySz is the algorithm's key length in bytes (keySize is in bits),
         * and the PBKDF version must match what -encrypt used: version 1
         * (EVP_BytesToKey) unless -pbkdf2 was given. */
        ret = wolfCLU_evp_crypto(cphr, mode,
                (byte*)passwordArg.password, (byte*)keyBuf,
                (keySize + 7) / 8, inFile, outFile, NULL,
                (byte*)ivBuf, 0, 0,
                isPkbVerion2 ? WOLFCLU_PBKDF2 : WOLFCLU_PBKDF1,
                hashType == NULL ? wolfSSL_EVP_sha256() : hashType, isEncrypt,
                isBase64, noSalt, keyType);
    }
    else {
        /* backing store for an output file name read from stdin when -out is omitted */
        char outNameBuf[256];
        /* The legacy (non-EVP) path writes straight to a file rather than
         * defaulting to stdout, so an output name is mandatory. Prompt for
         * one when -out was omitted, matching wolfCLU_setup's behavior. */
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
            ret = wolfCLU_encrypt(alg, mode, (byte*)passwordArg.password,
                    (byte*)keyBuf, keySize, inFile, outFile,
                    (byte*)ivBuf, block, keyType, ivFlag.found ||
                    keyFlag.found);
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

WOLFCLI_COMMAND encryptCommand = {
    .name = "encrypt",
    .shortHelp = "Encrypt input file with provided algorithm",
    .longHelp =(
"Encrypts a file using a cipher and a password or key. The algorithm must\n\
match the one used for encryption. For AES and 3DES (EVP path),\n\
password-based decryption extracts the salt from the file and derives key\n\
and IV from the password and salt. For legacy non-EVP ciphers (e.g.\n\
Camellia), salt and IV are read from the file header."),
    .commandEntry = encryptEntry,
    .flags =  {
        .flags = decryptFlags,
        .flagsSz = sizeof(decryptFlags) / sizeof(*decryptFlags),
    },
};

WOLFCLI_COMMAND decryptCommand = {
    .name = "decrypt",
    .shortHelp = "Decrypt input file with provided algorithm",
    .longHelp =(
"Decrypts a file using a cipher and a password or key. The algorithm must\n\
match the one used for encryption. For AES and 3DES (EVP path),\n\
password-based decryption extracts the salt from the file and derives key\n\
and IV from the password and salt. For legacy non-EVP ciphers (e.g.\n\
Camellia), salt and IV are read from the file header. For explicit keys\n\
and IVs, you must provide the same values used during encryption."),
    .commandEntry = decryptEntry,
    .flags =  {
        .flags = decryptFlags,
        .flagsSz = sizeof(decryptFlags) / sizeof(*decryptFlags),
    },
};



#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfcli/cli.h>
#include<wolfclu/clu_arg_handlers.h>
#include <wolfclu/clu_crypto_flags.h>

#include <limits.h>

/* Windows opens stdout in text mode, expanding every 0x0A byte to 0x0D 0x0A.
 * That corrupts raw binary random output, so stdout is switched to binary
 * mode below before writing. */
#if defined(_WIN32)
    #include <io.h>
    #include <fcntl.h>
#endif

/* Fallback for RNG configs that leave RNG_MAX_BLOCK_LEN undefined. If a
 * build's real per-call limit is smaller, wc_RNG_GenerateBlock fails
 * cleanly. */
#ifndef RNG_MAX_BLOCK_LEN
    #define RNG_MAX_BLOCK_LEN (0x10000)
#endif

static WOLFSSL_BIO* outBio = NULL;

/* -out only records the path here; the file is opened in randEntry once the
 * byte count has validated, so a bad count never truncates an existing
 * file. */
static const char* outFile = NULL;

static char isHex = 0;
static char isBase64 = 0;

static unsigned int numBytesArg = 0;

static int cleanup(void)
{
    if (outBio != NULL) {
        wolfSSL_BIO_free(outBio);
        outBio = NULL;
    }
    return WOLFCLI_SUCCESS;
}


static WOLFCLI_FLAG hexFlag;
static WOLFCLI_FLAG base64Flag;
static WOLFCLI_FLAG outFlag;
static WOLFCLI_FLAG numBytesFlag;

/* C89 has no compound literals, so the group's membership array and the one
 * element array the flags point back at it with are named here. */
static WOLFCLI_FLAG* hexBase64GroupFlags[] = { &hexFlag, &base64Flag };

static WOLFCLI_FLAG_GROUP hexBase64Mutex = {
    /*name=*/"hex/base64",
    /*groupDescription=*/
        "At most one of -hex or -base64, raw bytes otherwise",
    /*flags=*/hexBase64GroupFlags,
    /*flagsSz=*/sizeof(hexBase64GroupFlags) / sizeof(*hexBase64GroupFlags),
    /*minSet=*/0,
    /*maxSet=*/1,
    /*priv=*/{0}
};

static WOLFCLI_FLAG_GROUP* hexFlagGroups[] = { &hexBase64Mutex };
static WOLFCLI_FLAG hexFlag = {
    /*flag=*/"-hex",
    /*shortHelp=*/"Output number as hex",
    /*longHelp=*/"Output number as hex",
    /*value=*/&isHex,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{hexFlagGroups, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG_GROUP* base64FlagGroups[] = { &hexBase64Mutex };
static WOLFCLI_FLAG base64Flag = {
    /*flag=*/"-base64",
    /*shortHelp=*/"Output number as base64",
    /*longHelp=*/"Output number as base64",
    /*value=*/&isBase64,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{base64FlagGroups, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG outFlag = {
    /*flag=*/"-out",
    /*shortHelp=*/"Output file with rand bytes defaults to stdout",
    /*longHelp=*/"Output file with rand bytes defaults to stdout",
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

static WOLFCLI_FLAG numBytesFlag = {
    /*flag=*/"Number of Bytes",
    /*shortHelp=*/"Number of pseudorandom bytes to generate last argument",
    /*longHelp=*/"Number of pseudorandom bytes to generate last argument",
    /*value=*/&numBytesArg,
    /*argHandler=*/wolfCLI_handleUInt,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_REQUIRED | WOLFCLI_FLAG_IS_POS_ARG_LAST,
        /*altNames=*/{0},
        /*groups=*/{0}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static int randEntry(void)
{
    int    ret       = WOLFCLI_SUCCESS;
    byte*  rngBlock  = NULL;
    char   outIsStdout = 0;

    if (numBytesArg == 0) {
        wolfCLU_LogError("Expected a positive <num bytes> count");
        ret = WOLFCLI_FATAL_ERROR;
    }

    /* Both encodings are handed back to the caller in a signed int length, and
     * hex doubles the size while base64 grows it by ~4/3, so cap the request
     * before burning a large malloc and RNG fill on it. Raw output is
     * uncapped. */
    if (ret == WOLFCLI_SUCCESS && (isHex || isBase64) &&
            numBytesArg > (unsigned int)(INT_MAX / 2)) {
        wolfCLU_LogError("requested size too large for encoded output");
        ret = WOLFCLI_FATAL_ERROR;
    }

    if (ret == WOLFCLI_SUCCESS && outFile != NULL) {
        outBio = wolfSSL_BIO_new_file(outFile, "wb");
        if (outBio == NULL) {
            wolfCLU_LogError("Could not write to file: %s", outFile);
            ret = WOLFCLI_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLI_SUCCESS && outBio == NULL) {
        outIsStdout = 1;
#if defined(_WIN32)
        /* Raw bytes have to pass through untranslated; otherwise a random
         * 0x0A becomes 0x0D 0x0A and `rand N` emits more than N bytes. */
        (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
        outBio = wolfSSL_BIO_new_fp(stdout, BIO_NOCLOSE);
        if (outBio == NULL) {
            wolfCLU_LogError("Could not open stdout");
            ret = WOLFCLI_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLI_SUCCESS) {
        rngBlock = (byte*)XMALLOC(numBytesArg, HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (rngBlock == NULL) {
            wolfCLU_LogError("Error malloc'ing for random bytes");
            ret = WOLFCLI_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLI_SUCCESS) {
        WC_RNG rng;

        if (wc_InitRng(&rng) != 0) {
            wolfCLU_LogError("Unable to initialize RNG");
            ret = WOLFCLI_FATAL_ERROR;
        }
        else {
            /* wc_RNG_GenerateBlock rejects requests larger than the DRBG
             * per-call max (RNG_MAX_BLOCK_LEN), so fill in chunks. */
            unsigned int generated = 0;

            while (ret == WOLFCLI_SUCCESS && generated < numBytesArg) {
                word32 chunk = (word32)(numBytesArg - generated);

                if (chunk > RNG_MAX_BLOCK_LEN) {
                    chunk = RNG_MAX_BLOCK_LEN;
                }
                if (wc_RNG_GenerateBlock(&rng, rngBlock + generated, chunk)
                        != 0) {
                    wolfCLU_LogError("Unable to generate RNG block");
                    ret = WOLFCLI_FATAL_ERROR;
                }
                else {
                    generated += (unsigned int)chunk;
                }
            }
            wc_FreeRng(&rng);
        }
    }

    if (ret == WOLFCLI_SUCCESS) {
        if (isBase64) {
            ret = wolfCLU_WriteBase64(outBio, rngBlock, (int)numBytesArg);
        }
        else if (isHex) {
            ret = wolfCLU_WriteHex(outBio, rngBlock, (int)numBytesArg);
        }
        else if (wolfSSL_BIO_write(outBio, rngBlock, (int)numBytesArg)
                != (int)numBytesArg) {
            wolfCLU_LogError("Error writing out RNG data");
            ret = WOLFCLI_FATAL_ERROR;
        }
    }

    /* Trailing newline so the next shell prompt isn't on the same line as the
     * output. Raw bytes are left exactly as generated, and Base64_Encode
     * already terminates its output with one. */
    if (ret == WOLFCLI_SUCCESS && outIsStdout && isHex) {
        (void)wolfSSL_BIO_write(outBio, "\n", 1);
    }

    if (rngBlock != NULL) {
        wolfCLU_ForceZero(rngBlock, numBytesArg);
        XFREE(rngBlock, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

static WOLFCLI_FLAG* flags[] = {
    &hexFlag,
    &base64Flag,
    &outFlag,
    &numBytesFlag,
};

WOLFCLI_COMMAND randCommand = {
    /*name=*/"rand",
    /*shortHelp=*/
"Generates the requested number of pseudorandom bytes and writes them to a\n\
file or to standard output.",
    /*longHelp=*/
"Generates the requested number of pseudorandom bytes and writes them to a\n\
file or to standard output. The bytes are written raw unless -hex or\n\
-base64 asks for an encoding.",
    /*commandEntry=*/randEntry,
    /*commandCleanup=*/cleanup,
    /*flags=*/{
        /*flags=*/flags,
        /*flagsSz=*/sizeof(flags) / sizeof(*flags)
    },
    /*commands=*/{0},
    /*altNames=*/{0},
    /*priv=*/{0}
};


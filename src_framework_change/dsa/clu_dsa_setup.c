#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_arg_handlers.h>
#include <wolfclu/clu_log.h>
#include <wolfcli/cli.h>

#ifndef NO_DSA

/* Needs Cleanup */
static WOLFSSL_BIO* outFile = NULL;
static byte* in = NULL;
static int   inSz = 0;
/* Needs Cleanup */

static WOLFCLI_FLAG inFlag;
static WOLFCLI_FLAG outFlag;
static WOLFCLI_FLAG genkeyFlag;
static WOLFCLI_FLAG noOutFlag;

static char genkeyArg = 0;
static char noOutArg  = 0;

static int cleanup(void)
{
    wolfSSL_BIO_free(outFile);
    if (in != NULL)
        XFREE(in, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return WOLFCLI_SUCCESS;
}

static int handleInput(const char* arg, void* out)
{
    int ret = WOLFCLU_SUCCESS;
    DerBuffer* pDer = NULL;
    (void)out;

    WOLFSSL_BIO* bioIn = NULL;
    if (wolfCLU_handleInFile(arg, &bioIn) != WOLFCLI_SUCCESS) {
        bioIn = wolfSSL_BIO_new_fp(stdin, BIO_NOCLOSE);
        if (bioIn == NULL) {
            return WOLFCLI_FATAL_ERROR;
        }
    }

    inSz = wolfSSL_BIO_get_len(bioIn);
    if (inSz > 0) {
        in = (byte*)XMALLOC(inSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (in == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_read(bioIn, in, inSz) <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS &&
                wc_PemToDer(in, inSz, DSA_PARAM_TYPE, &pDer, NULL, NULL,
                    NULL) != 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        /* der should always be smaller then pem but check just in case */
        if (ret == WOLFCLU_SUCCESS && (word32)inSz < pDer->length) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            inSz = pDer->length;
            XMEMCPY(in, pDer->buffer, pDer->length);
        }

        if (pDer != NULL)
            wc_FreeDer(&pDer);
    }
    else {
        wolfCLU_LogError("Input was empty");
        ret = WOLFCLI_FATAL_ERROR;
    }
    wolfSSL_BIO_free(bioIn);
    return ret;
}



static WOLFCLI_FLAG inFlag = {
    .flag = "-in",
    .shortHelp = "File with DSA parameters PEM format",
    .longHelp = "File with DSA parameters PEM format",
    .argHandler = handleInput,
    .value = &in,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG | WOLFCLI_FLAG_REQUIRED,
};

static WOLFCLI_FLAG outFlag = {
    .flag = "-out",
    .shortHelp = "File to output Params/Key to (default stdout)",
    .longHelp  = "File to output Params/Key to (default stdout)",
    .argHandler = wolfCLU_handleOutFile,
    .value = &outFile,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
};

static WOLFCLI_FLAG genkeyFlag = {
    .flag = "-genkey",
    .shortHelp = "Generate DSA key using params",
    .longHelp = "Generate DSA key using params",
    .value = &genkeyArg,
};

static WOLFCLI_FLAG noOutFlag = {
    .flag = "-noout",
    .shortHelp = "Do not print out DSA parameters",
    .longHelp  = "Do not print out DSA parameters",
    .value     = &noOutArg,
};

static WOLFCLI_FLAG* flags[] = {
    &inFlag,
    &outFlag,
    &genkeyFlag,
    &noOutFlag,
};

static WOLFCLI_FLAG* genParamsFlags[] = {
    &outFlag,
    &genkeyFlag,
    &noOutFlag,
};

static int genParamsGeneral(word32 modSz, DsaKey* dsa, WC_RNG* rng)
{
    int ret = WOLFCLU_SUCCESS;

    /* default to stdout, -noout only gates the params print not the whole
     * output, -genkey still needs somewhere to write the key */
    if (outFile == NULL) {
        outFile = wolfSSL_BIO_new_fp(stdout, BIO_NOCLOSE);
        if (outFile == NULL) {
            wolfCLU_LogError("Could not open stdout");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && modSz != 0) {
        ret = wolfCLU_DSA_CreateParams(dsa, rng, modSz);
    }

    if (ret == WOLFCLU_SUCCESS && !noOutArg) {
        ret = wolfCLU_DSA_PrintParams(dsa, outFile);
    }

    if (ret == WOLFCLU_SUCCESS && genkeyArg) {
        ret = wolfCLU_DSA_Genkey(outFile, rng, dsa);
    }

    return ret == WOLFCLU_SUCCESS ? WOLFCLI_SUCCESS : WOLFCLI_FATAL_ERROR;
}

/* Stand up the rng and key every entry point needs, decode the params from
 * -in when they were given, then hand off to genParamsGeneral. A modSz of 0
 * means no numbits subcommand was named so nothing is generated. */
static int runParams(word32 modSz)
{
    int ret = WOLFCLI_SUCCESS;
    word32 idx      = 0;
    WC_RNG rng      = {0};
    DsaKey dsa      = {0};
    char rngInit    = 0;
    char dsaInit    = 0;

    if (wc_InitRng(&rng) != 0) {
        wolfCLU_LogError("Unable to initialize rng");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        rngInit = 1;
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wc_InitDsaKey(&dsa) != 0) {
            wolfCLU_LogError("Unable to initialize dsa");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            dsaInit = 1;
        }
    }

    if (ret == WOLFCLU_SUCCESS && in != NULL) {
        if (wc_DsaParamsDecode(in, &idx, &dsa, (word32)inSz) != 0) {
            wolfCLU_LogError("Unable to decode input params");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = genParamsGeneral(modSz, &dsa, &rng);
    }

    if (dsaInit)
        wc_FreeDsaKey(&dsa);
    if (rngInit)
        wc_FreeRng(&rng);

    return ret == WOLFCLU_SUCCESS ? WOLFCLI_SUCCESS : WOLFCLI_FATAL_ERROR;
}

static int bit3072Entry(void)
{
    return runParams(3072);
}

static int bit2048Entry(void)
{
    return runParams(2048);
}

static int bit1024Entry(void)
{
    return runParams(1024);
}

static WOLFCLI_COMMAND bit3072 = {
    .name = "3072",
    .shortHelp = "Create a DSA params with 3072 bits",
    .longHelp  = "Create a DSA params with 3072 bits",
    .commandCleanup = cleanup,
    .commandEntry   = bit3072Entry,
    .flags = {
        .flags = genParamsFlags,
        .flagsSz = sizeof(genParamsFlags) / sizeof(*genParamsFlags)
    },
};

static WOLFCLI_COMMAND bit2048 = {
    .name = "2048",
    .shortHelp = "Create a DSA params with 2048 bits",
    .longHelp  = "Create a DSA params with 2048 bits",
    .commandCleanup = cleanup,
    .commandEntry   = bit2048Entry,
    .flags = {
        .flags = genParamsFlags,
        .flagsSz = sizeof(genParamsFlags) / sizeof(*genParamsFlags)
    },
};

static WOLFCLI_COMMAND bit1024 = {
    .name = "1024",
    .shortHelp = "Create a DSA params with 1024 bits",
    .longHelp  = "Create a DSA params with 1024 bits",
    .commandCleanup = cleanup,
    .commandEntry   = bit1024Entry,
    .flags = {
        .flags = genParamsFlags,
        .flagsSz = sizeof(genParamsFlags) / sizeof(*genParamsFlags)
    },
};

static int dsaEntry(void)
{
    /* with no numbits subcommand there is nothing to generate, so the params
     * have to come in over -in */
    if (in == NULL) {
        wolfCLU_LogError("No DSA parameters to read, pass -in or a numbits "
                "subcommand");
        return WOLFCLI_FATAL_ERROR;
    }

    return runParams(0);
}

WOLFCLI_COMMAND dsaCommand = {
    .name = "dsaparam",
    .shortHelp = "Generates or reads DSA parameters and keys",
    .longHelp = (
"Generates DSA parameters and keys, or reads and displays existing DSA\n\
parameters. The number of bits is a subcommand rather than a trailing\n\
positional argument, so params are generated with 'dsaparam 2048' and the\n\
sizes on offer are the ones listed under SUB COMMANDS below.\n\
\n\
Without a size subcommand nothing is generated and the params have to be\n\
read from -in. -in belongs to dsaparam itself rather than to a size, so\n\
it has to come before the subcommand; the other flags work on either\n\
side of it."),
    .flags = {
        .flags = flags,
        .flagsSz = sizeof(flags) / sizeof(*flags)
    },
    .commands = {
        .commands = (WOLFCLI_COMMAND *[]){&bit1024,&bit2048,&bit3072},
        .commandsSz = 3
    },
    .commandEntry = dsaEntry,
    .commandCleanup = cleanup
};

#else /* NO_DSA */

static int dsaEntry(void)
{
    wolfCLU_LogError("DSA support not compiled into wolfSSL");
    return WOLFCLI_FATAL_ERROR;
}

WOLFCLI_COMMAND dsaCommand = {
    .name = "dsaparam",
    .shortHelp = "Generates or reads DSA parameters and keys",
    .longHelp = "DSA support not compiled into wolfSSL",
    .commandEntry = dsaEntry,
};

#endif /* !NO_DSA */

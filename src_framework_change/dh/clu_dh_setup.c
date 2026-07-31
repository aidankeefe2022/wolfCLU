#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_arg_handlers.h>
#include <wolfclu/clu_log.h>
#include <wolfcli/cli.h>

/* Needs Cleanup */
static WOLFSSL_BIO* outFile = NULL;
static byte* in = NULL;
static int   inSz = 0;
/* Needs Cleanup */

static WOLFCLI_FLAG inFlag;
static WOLFCLI_FLAG outFlag;
static WOLFCLI_FLAG genkeyFlag;
static WOLFCLI_FLAG checkFlag;
static WOLFCLI_FLAG noOutFlag;

static char genkeyArg = 0;
static char checkArg  = 0;
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
    int ret = WOLFCLI_SUCCESS;
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
                wc_PemToDer(in, inSz, DH_PARAM_TYPE, &pDer, NULL, NULL,
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
    .shortHelp = "Input file with dh params",
    .longHelp = "Input file with dh params",
    .argHandler = handleInput,
    .value = &in,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG | WOLFCLI_FLAG_REQUIRED,
};

static WOLFCLI_FLAG outFlag = {
    .flag = "-out",
    .shortHelp = "Output file with DH params/key defaults to stdout",
    .longHelp = "Output file with DH params/key defaults to stdout",
    .argHandler = wolfCLU_handleOutFile,
    .value = &outFile,
    .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG,
};

static WOLFCLI_FLAG genkeyFlag = {
    .flag = "-genkey",
    .shortHelp = "Generate DH key using params",
    .longHelp = "Generate DH key using params",
    .value = &genkeyArg,
};

static WOLFCLI_FLAG checkFlag = {
    .flag = "-check",
    .shortHelp = "Check if parameters are valid",
    .longHelp = "Check if parameters are valid",
    .value    = &checkArg,
};

static WOLFCLI_FLAG noOutFlag = {
    .flag = "-noout",
    .shortHelp = "Do not print out DH parameters",
    .longHelp  = "Do not print out DH parameters",
    .value     = &noOutArg,
};

static WOLFCLI_FLAG* flags[] = {
    &inFlag,
    &outFlag,
    &genkeyFlag,
    &checkFlag,
    &noOutFlag,
};

static WOLFCLI_FLAG* genKeyFlags[] = {
    &outFlag,
    &genkeyFlag,
    &checkFlag,
    &noOutFlag,
};

static int genKeyGeneral(int modSz, DhKey* dh, WC_RNG* rng)
{
    int ret = WOLFCLI_SUCCESS;

    /* default to stdout, -noout only gates the params print not the whole
     * output, -genkey still needs somewhere to write the key */
    if (outFile == NULL) {
        outFile = wolfSSL_BIO_new_fp(stdout, BIO_NOCLOSE);
        if (outFile == NULL) {
            wolfCLU_LogError("Could not open stdout");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (modSz != 0) {
        ret = wolfCLU_DH_CreateParams(dh, rng, modSz);
    }

    if (ret == WOLFCLU_SUCCESS && !noOutArg) {
        wolfCLU_DH_PrintParams(dh, outFile);
    }

    if (ret == WOLFCLU_SUCCESS && checkArg) {
        ret = wolfCLU_DH_Check(dh);
    }

    if (ret == WOLFCLU_SUCCESS && genkeyArg) {
        ret = wolfCLU_DH_Genkey(outFile, rng, dh);
    }

    return ret == WOLFCLU_SUCCESS ? WOLFCLI_SUCCESS : WOLFCLI_FATAL_ERROR;
}

static int bit4096Entry(void)
{
    int ret = WOLFCLI_SUCCESS;
    int modSz = 4096;
    WC_RNG rng      = {0};
    DhKey  dh       = {0};
    char rngInit    = 0;
    char dhInit    = 0;

    if (wc_InitRng(&rng) != 0) {
        wolfCLU_LogError("Unable to initialize rng");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        rngInit = 1;
    }

    if (wc_InitDhKey(&dh) != 0) {
        wolfCLU_LogError("Unable to initialize dh");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        dhInit = 1;
    }

    ret = genKeyGeneral(modSz, &dh, &rng);

    if (rngInit)
        wc_FreeRng(&rng);
    if (dhInit)
        wc_FreeDhKey(&dh);
    return ret;
}
static int bit2048Entry(void)
{
    int ret = WOLFCLI_SUCCESS;
    int modSz = 2048;
    WC_RNG rng      = {0};
    DhKey  dh       = {0};
    char rngInit    = 0;
    char dhInit    = 0;

    if (wc_InitRng(&rng) != 0) {
        wolfCLU_LogError("Unable to initialize rng");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        rngInit = 1;
    }

    if (wc_InitDhKey(&dh) != 0) {
        wolfCLU_LogError("Unable to initialize dh");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        dhInit = 1;
    }

    ret = genKeyGeneral(modSz, &dh, &rng);

    if (rngInit)
        wc_FreeRng(&rng);
    if (dhInit)
        wc_FreeDhKey(&dh);
    return ret;
}

static int bit1024Entry(void)
{
    int ret = WOLFCLI_SUCCESS;
    int modSz = 1024;
    WC_RNG rng      = {0};
    DhKey  dh       = {0};
    char rngInit    = 0;
    char dhInit    = 0;

    if (wc_InitRng(&rng) != 0) {
        wolfCLU_LogError("Unable to initialize rng");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        rngInit = 1;
    }

    if (wc_InitDhKey(&dh) != 0) {
        wolfCLU_LogError("Unable to initialize dh");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        dhInit = 1;
    }

    ret = genKeyGeneral(modSz, &dh, &rng);

    if (rngInit)
        wc_FreeRng(&rng);
    if (dhInit)
        wc_FreeDhKey(&dh);
    return ret;
}

static WOLFCLI_COMMAND bit4096 = {
    .name = "4096",
    .shortHelp = "Create a DH params with 4096 bits",
    .longHelp  = "Create a DH params with 4096 bits",
    .commandCleanup = cleanup,
    .commandEntry   = bit4096Entry,
    .flags = {
        .flags = genKeyFlags,
        .flagsSz = sizeof(genKeyFlags) / sizeof(*genKeyFlags)
    },
};

static WOLFCLI_COMMAND bit2048 = {
    .name = "2048",
    .shortHelp = "Create a DH params with 2048 bits",
    .longHelp  = "Create a DH params with 2048 bits",
    .commandCleanup = cleanup,
    .commandEntry   = bit2048Entry,
    .flags = {
        .flags = genKeyFlags,
        .flagsSz = sizeof(genKeyFlags) / sizeof(*genKeyFlags)
    },
};

static WOLFCLI_COMMAND bit1024 = {
    .name = "1024",
    .shortHelp = "Create a DH params with 1024 bits",
    .longHelp  = "Create a DH params with 1024 bits",
    .commandCleanup = cleanup,
    .commandEntry   = bit1024Entry,
    .flags = {
        .flags = genKeyFlags,
        .flagsSz = sizeof(genKeyFlags) / sizeof(*genKeyFlags)
    },
};

static int dhEntry(void)
{
    int ret = WOLFCLU_SUCCESS;

    word32 idx = 0;
    WC_RNG rng      = {0};
    DhKey  dh       = {0};
    char rngInit    = 0;
    char dhInit    = 0;

    if (wc_InitRng(&rng) != 0) {
        wolfCLU_LogError("Unable to initialize rng");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        rngInit = 1;
    }

    if (wc_InitDhKey(&dh) != 0) {
        wolfCLU_LogError("Unable to initialize dh");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        dhInit = 1;
    }

    if (in != NULL) {
        if (ret == WOLFCLU_SUCCESS &&
                wc_DhKeyDecode(in, &idx, &dh, (int)inSz) != 0) {
            wolfCLU_LogError("Unable to decode input params");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    ret = genKeyGeneral(0, &dh, &rng);

    if (rngInit)
        wc_FreeRng(&rng);
    if (dhInit)
        wc_FreeDhKey(&dh);

    return ret;
}

WOLFCLI_COMMAND dhCommand = {
    .name = "dhparam",
    .shortHelp = "Generates or reads DH parameters and keys",
    .longHelp = (
"Generates Diffie-Hellman parameters and keys, or reads and displays\n\
existing DH parameters. The number of bits is a subcommand rather than a\n\
trailing positional argument, so params are generated with 'dhparam 2048'\n\
and the sizes on offer are the ones listed under SUB COMMANDS below.\n\
\n\
Without a size subcommand nothing is generated and the params are read\n\
from -in instead. -in belongs to dhparam itself rather than to a size, so\n\
it has to come before the subcommand; the other flags work on either\n\
side of it."),
    .flags = {
        .flags = flags,
        .flagsSz = sizeof(flags) / sizeof(*flags)
    },
    .commands = {
        .commands = (WOLFCLI_COMMAND *[]){&bit1024,&bit2048,&bit4096},
        .commandsSz = 3
    },
    .commandEntry = dhEntry,
    .commandCleanup = cleanup
};




#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_arg_handlers.h>
#include <wolfclu/clu_log.h>
#include <wolfcli/cli.h>

struct hash_algoritms {
    char hash_md5;
    char hash_sha256;
    char hash_sha1;
    char hash_sha384;
    char hash_sha512;
    char hash_base64enc;
    char hash_base64dec;
} hash_algs = {0};

static word32 hash_blake2b = 0;

static WOLFSSL_BIO* bioIn  = NULL;
static WOLFSSL_BIO* bioOut = NULL;

static int cleanup(void)
{
    if (bioIn != NULL) {
        wolfSSL_BIO_free(bioIn);
    }
    if (bioOut != NULL) {
        wolfSSL_BIO_free(bioOut);
    }
    return WOLFCLI_SUCCESS;
}

static WOLFCLI_FLAG base64encFlag;
static WOLFCLI_FLAG base64decFlag;
static WOLFCLI_FLAG md5Flag;
static WOLFCLI_FLAG blake2bFlag;
static WOLFCLI_FLAG shaFlag;
static WOLFCLI_FLAG sha256Flag;
static WOLFCLI_FLAG sha384Flag;
static WOLFCLI_FLAG sha512Flag;

/* C89 has no compound literals, so the group membership arrays the flags and
 * the group point at are named rather than written inline. */
static WOLFCLI_FLAG* hashGroupFlags[] = {
    &md5Flag,
    &blake2bFlag,
    &shaFlag,
    &sha256Flag,
    &sha384Flag,
    &sha512Flag,
    &base64decFlag,
    &base64encFlag
};

static WOLFCLI_FLAG_GROUP hashGroup = {
    /*name=*/"Hash algoritm group",
    /*groupDescription=*/"Must pick one hash alg",
    /*flags=*/hashGroupFlags,
    /*flagsSz=*/sizeof(hashGroupFlags) / sizeof(*hashGroupFlags),
    /*minSet=*/1,
    /*maxSet=*/1,
    /*priv=*/{0}
};

static WOLFCLI_FLAG_GROUP* hashGroupOnly[] = { &hashGroup };

static const char* shaAltNames[] = { "-sha1" };

/* The initializers below are positional, so their field order has to follow
 * struct WOLFCLI_FLAG in wolfcli/cli.h. */

static WOLFCLI_FLAG inFlag = {
    /*flag=*/"-in",
    /*shortHelp=*/"Input file to process defaults to stdin",
    /*longHelp=*/"Input file to process defaults to stdin",
    /*value=*/&bioIn,
    /*argHandler=*/wolfCLU_handleInFile,
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
    /*shortHelp=*/"Output file to process defaults to stdout",
    /*longHelp=*/"Output file to process defaults to stdout",
    /*value=*/&bioOut,
    /*argHandler=*/wolfCLU_handleOutFile,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{0},
        /*groups=*/{0}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG md5Flag = {
    /*flag=*/"-md5",
    /*shortHelp=*/"Use the md5 algoritm to hash message",
    /*longHelp=*/"Use the md5 algoritm to hash message",
    /*value=*/&hash_algs.hash_md5,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{hashGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

/* -blake2b is the one alg flag that takes an argument, the digest size */
static WOLFCLI_FLAG blake2bFlag = {
    /*flag=*/"-blake2b",
    /*shortHelp=*/"Use the blake2b algoritm to hash message",
    /*longHelp=*/"Use the blake2b algoritm to hash message",
    /*value=*/&hash_blake2b,
    /*argHandler=*/wolfCLI_handleUInt,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{0},
        /*groups=*/{hashGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG shaFlag = {
    /*flag=*/"-sha",
    /*shortHelp=*/"Use the sha1 algoritm to hash message",
    /*longHelp=*/"Use the sha1 algoritm to hash message",
    /*value=*/&hash_algs.hash_sha1,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{shaAltNames, 1},
        /*groups=*/{hashGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG sha256Flag = {
    /*flag=*/"-sha256",
    /*shortHelp=*/"Use the sha256 algoritm to hash message",
    /*longHelp=*/"Use the sha256 algoritm to hash message",
    /*value=*/&hash_algs.hash_sha256,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{hashGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG sha384Flag = {
    /*flag=*/"-sha384",
    /*shortHelp=*/"Use the sha384 algoritm to hash message",
    /*longHelp=*/"Use the sha384 algoritm to hash message",
    /*value=*/&hash_algs.hash_sha384,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{hashGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG sha512Flag = {
    /*flag=*/"-sha512",
    /*shortHelp=*/"Use the sha512 algoritm to hash message",
    /*longHelp=*/"Use the sha512 algoritm to hash message",
    /*value=*/&hash_algs.hash_sha512,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{hashGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG base64encFlag = {
    /*flag=*/"-base64enc",
    /*shortHelp=*/"Base 64 encode message",
    /*longHelp=*/"Base 64 encode message",
    /*value=*/&hash_algs.hash_base64enc,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{hashGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

static WOLFCLI_FLAG base64decFlag = {
    /*flag=*/"-base64dec",
    /*shortHelp=*/"Base 64 decode message",
    /*longHelp=*/"Base 64 decode message",
    /*value=*/&hash_algs.hash_base64dec,
    /*argHandler=*/NULL,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/0,
        /*altNames=*/{0},
        /*groups=*/{hashGroupOnly, 1}
    },
    /*found=*/WOLFCLI_FLAG_NOT_FOUND
};

WOLFCLI_FLAG* flags[] = {
    &outFlag,
    &inFlag,
    &md5Flag,
    &blake2bFlag,
    &shaFlag,
    &sha256Flag,
    &sha384Flag,
    &sha512Flag,
    &base64encFlag,
    &base64decFlag,
};

static char* algMap(void) {
    static char blake2b[] = "blake2b";
    static char md5[] = "md5";
    static char sha1[] = "sha";
    static char sha256[] = "sha256";
    static char sha384[] = "sha384";
    static char sha512[] = "sha512";
    static char base64enc[] = "base64enc";
    static char base64dec[] = "base64dec";

    if (hash_algs.hash_base64dec)
        return base64dec;
    if (hash_algs.hash_base64enc)
        return base64enc;
    if (hash_algs.hash_md5)
        return md5;
    if (hash_algs.hash_sha1)
        return sha1;
    if (hash_algs.hash_sha256)
        return sha256;
    if (hash_algs.hash_sha384)
        return sha384;
    if (hash_algs.hash_sha512)
        return sha512;
    return blake2b;
}

static int hashEntry(void)
{
    int ret = WOLFCLU_SUCCESS;

    if (ret == WOLFCLU_SUCCESS && bioIn== NULL) {
        bioIn = wolfSSL_BIO_new_fp(stdin, BIO_NOCLOSE);
        if (bioIn == NULL) {
            wolfCLU_LogError("unable to open stdin");
            ret = USER_INPUT_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && bioOut == NULL) {
        bioOut = wolfSSL_BIO_new_fp(stdout, BIO_NOCLOSE);
        if (bioOut == NULL) {
            wolfCLU_LogError("unable to open stdout");
            ret = USER_INPUT_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* hashing function */
        ret = wolfCLU_hash(bioIn, bioOut, algMap(), hash_blake2b);
    }

    return ret;
}

WOLFCLI_COMMAND hashCommand = {
    /*name=*/"hash",
    /*shortHelp=*/"Create a hash of a message.",
    /*longHelp=*/
"Create a hash of a message.\n"
"   Usage: wolfssl hash -in <file> -out <file> [algoritm]\n",
    /*commandEntry=*/hashEntry,
    /*commandCleanup=*/cleanup,
    /*flags=*/{
        /*flags=*/flags,
        /*flagsSz=*/sizeof(flags) / sizeof(*flags)
    },
    /*commands=*/{0},
    /*altNames=*/{0},
    /*priv=*/{0}
};

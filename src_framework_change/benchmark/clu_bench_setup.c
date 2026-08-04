

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfcli/cli.h>

/* flag args */
static int bench_TimeFlagArg = 5;
static int bench_Algorithms[WOLFCLU_BENCH_COUNT] = {1, 1, 1, 1, 1, 1, 1, 1};
static char zeroBenchAlgs = 1;

/* name the user passes to -alg paired with the benchmark it selects, holding
 * only the algs this build was compiled with */
struct benchAlg {
    const char* algName;
    int id;
};

static const struct benchAlg benchAlgorithms[] = {
#ifndef NO_AES
    {"aes-cbc",  WOLFCLU_BENCH_AESCBC   },
#endif
#ifdef WOLFSSL_AES_COUNTER
    {"aes-ctr",  WOLFCLU_BENCH_AESCTR   },
#endif
#ifndef NO_DES3
    {"3des",     WOLFCLU_BENCH_3DES     },
#endif
#ifdef HAVE_CAMELLIA
    {"camellia", WOLFCLU_BENCH_CAMELLIA },
#endif
#ifndef NO_MD5
    {"md5",      WOLFCLU_BENCH_MD5      },
#endif
#ifndef NO_SHA
    {"sha",      WOLFCLU_BENCH_SHA      },
#endif
#ifndef NO_SHA256
    {"sha256",   WOLFCLU_BENCH_SHA256   },
#endif
#ifdef WOLFSSL_SHA384
    {"sha384",   WOLFCLU_BENCH_SHA384   },
#endif
#ifdef WOLFSSL_SHA512
    {"sha512",   WOLFCLU_BENCH_SHA512   },
#endif
#ifdef HAVE_BLAKE2B
    {"blake2b",  WOLFCLU_BENCH_BLAKE2B  },
#endif
    {NULL,       0                      }
};

static int benchHandleAlgArray(const char* arg, void* out)
{
    int ret = WOLFCLI_SUCCESS;
    word32 i;
    (void)out;

    if (zeroBenchAlgs == 1) {
        wc_ForceZero(bench_Algorithms, sizeof(bench_Algorithms));
        zeroBenchAlgs = 0;
    }

    for (i = 0; benchAlgorithms[i].algName != NULL; i++) {
        if (XSTRCMP(arg, benchAlgorithms[i].algName) == 0) {
            bench_Algorithms[benchAlgorithms[i].id] = 1;
            return ret;
        }
    }
    ret = WOLFCLI_FATAL_ERROR;
    wolfCLU_LogError("Algoritm %s is not avalible please look at -alg -h for "
            "list of algs", arg);

    return ret;
}

static const char benchAlgLongHelp[] =
"Alg that you would like to benchmark\n"
"    Algs: \n"
#ifndef NO_AES
"        aes-cbc\n"
#endif
#ifdef WOLFSSL_AES_COUNTER
"        aes-ctr\n"
#endif
#ifndef NO_DES3
"        3des\n"
#endif
#ifdef HAVE_CAMELLIA
"        camellia\n"
#endif
#ifndef NO_MD5
"        md5\n"
#endif
#ifndef NO_SHA
"        sha\n"
#endif
#ifndef NO_SHA256
"        sha256\n"
#endif
#ifdef WOLFSSL_SHA384
"        sha384\n"
#endif
#ifdef WOLFSSL_SHA512
"        sha512\n"
#endif
#ifdef HAVE_BLAKE2B
"        blake2b\n"
#endif
;

static WOLFCLI_FLAG benchAlgFlag = {
    /*flag=*/"-alg",
    /*shortHelp=*/"Alg that you would like to bench mark",
    /*longHelp=*/benchAlgLongHelp,
    /*value=*/NULL,
    /*argHandler=*/benchHandleAlgArray,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_REPEATABLE | WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{0},
        /*groups=*/{0}
    },
    /*found=*/0
};

static WOLFCLI_FLAG benchTimeFlag = {
    /*flag=*/"-time",
    /*shortHelp=*/"Amount of time the benchmark should be run for",
    /*longHelp=*/
"Amount of time the benchmark should be run for. \n"
"Default is 5 seconds max is 10.",
    /*value=*/&bench_TimeFlagArg,
    /*argHandler=*/wolfCLI_handleInt,
    /*optionalArgs=*/{
        /*dependsOn=*/{0},
        /*modes=*/WOLFCLI_FLAG_HAS_ARG,
        /*altNames=*/{0},
        /*groups=*/{0}
    },
    /*found=*/0
};

static WOLFCLI_FLAG* benchFlags[] = {
    &benchAlgFlag,
    &benchTimeFlag
};

static int benchEntry(void) {
    return wolfCLU_benchmark(bench_TimeFlagArg, bench_Algorithms);
}

WOLFCLI_COMMAND bench= {
    /*name=*/"bench",
    /*shortHelp=*/"Run benchmarks or a variety of wolfSSL tools.",
    /*longHelp=*/
"Benchmarks  the  performance of various cryptographic algorithms,\n"
"measuring how fast they encrypt, decrypt, or hash data.\n"
"Useful for understanding the speed and efficiency of different\n"
"algorithms on your system."
,
    /*commandEntry=*/benchEntry,
    /*commandCleanup=*/NULL,
    /*flags=*/{
        /*flags=*/benchFlags,
        /*flagsSz=*/sizeof(benchFlags) / sizeof(*benchFlags)
    },
    /*commands=*/{0},
    /*altNames=*/{0},
    /*priv=*/{0}
};

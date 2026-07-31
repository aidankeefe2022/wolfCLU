

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfcli/cli.h>
#include <wolfcli/manpage.h>

/* flag args */
static int bench_TimeFlagArg = 5;
static int bench_Algorithms[WOLFCLU_BENCH_COUNT] = {1, 1, 1, 1, 1, 1, 1, 1};
static char zeroBenchAlgs = 1;

static int benchHandleAlgArray(const char* arg, void* out)
{
    int ret = WOLFCLI_SUCCESS;
    word32 i;
    (void)out;

    if (zeroBenchAlgs == 1) {
        wc_ForceZero(bench_Algorithms, sizeof(bench_Algorithms));
        zeroBenchAlgs = 0;
    }

    static struct {const char* algName; int id;} algorithms[] = {
#ifndef NO_AES
    {"aes-cbc", WOLFCLU_BENCH_AESCBC},
#endif
#ifdef WOLFSSL_AES_COUNTER
    {"aes-ctr", WOLFCLU_BENCH_AESCTR   },
#endif
#ifndef NO_DES3
    {"3des", WOLFCLU_BENCH_3DES     },
#endif
#ifdef HAVE_CAMELLIA
    {"camellia", WOLFCLU_BENCH_CAMELLIA },
#endif
#ifndef NO_MD5
    {"md5", WOLFCLU_BENCH_MD5      },
#endif
#ifndef NO_SHA
    {"sha", WOLFCLU_BENCH_SHA      },
#endif
#ifndef NO_SHA256
    {"sha256", WOLFCLU_BENCH_SHA256   },
#endif
#ifdef WOLFSSL_SHA384
    {"sha384", WOLFCLU_BENCH_SHA384   },
#endif
#ifdef WOLFSSL_SHA512
    {"sha512", WOLFCLU_BENCH_SHA512   },
#endif
#ifdef HAVE_BLAKE2B
    {"blake2b", WOLFCLU_BENCH_BLAKE2B  },
#endif
    };

    for (i = 0; i < sizeof(algorithms) / sizeof(*algorithms); i++) {
        if (XSTRCMP(arg, algorithms[i].algName) == 0) {
            bench_Algorithms[algorithms[i].id] = 1;
            return ret;
        }
    }
    ret = WOLFCLI_FATAL_ERROR;
    wolfCLU_LogError("Algoritm %s is not avalible please look at -alg -h for "
            "list of algs", arg);

    return ret;
}

static const char benchAlgLongHelp[] =( ""
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
);

WOLFCLI_COMMAND bench;

static int benchEntry(void) {
    return wolfCLU_benchmark(bench_TimeFlagArg, bench_Algorithms);
}

WOLFCLI_COMMAND bench= {
    .name = "bench",
    .shortHelp = "Run benchmarks or a variety of wolfSSL tools.",
    .longHelp = (
"Benchmarks  the  performance of various cryptographic algorithms,\n\
measuring how fast they encrypt, decrypt, or hash data.\n\
Useful for understanding the speed and efficiency of different\n\
algorithms on your system."),
    .commandEntry = benchEntry,
    .flags = {
        .flags = (WOLFCLI_FLAG *[]){
            &(WOLFCLI_FLAG){
                .flag = "-alg",
                .shortHelp = "Alg that you would like to bench mark",
                .longHelp = benchAlgLongHelp,
                .argHandler = benchHandleAlgArray,
                .optionalArgs.modes = WOLFCLI_FLAG_REPEATABLE |
                                      WOLFCLI_FLAG_HAS_ARG
            },
            &(WOLFCLI_FLAG){
                .flag = "-time",
                .shortHelp = "Amount of time the benchmark should be run for",
                .longHelp =
"Amount of time the benchmark should be run for. \n\
Default is 5 seconds max is 10.",
                .value = &bench_TimeFlagArg,
                .argHandler = wolfCLI_handleInt,
                .optionalArgs.modes = WOLFCLI_FLAG_HAS_ARG
            }
        },
        .flagsSz = 2
    }
};

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfcli/cli.h>
#include <wolfclu/clu_arg_handlers.h>
#include <wolfclu/clu_crypto_flags.h>

/* Decode a hex key string into the caller-provided keyOut buffer.
 *
 * Wraps wolfCLU_hexToBin so the caller's pre-allocated key buffer is not
 * replaced by hexToBin's internal allocation (which would leak the original
 * and, on hexToBin failure, leave the caller pointing at a freed buffer).
 *
 * Returns WOLFCLU_SUCCESS on success, WOLFCLU_FATAL_ERROR on length mismatch
 * or hex decode failure, MEMORY_E on allocation failure. */
int wolfCLU_loadHexKeyInto(byte *keyOut, int keyBytes, const char *hex,
                                  word32 hexLen)
{
    byte *tmp = NULL;
    word32 tmpSz = 0;
    char *hexCopy;
    int ret;

    if (hexLen != (word32)keyBytes * 2) {
        WOLFCLU_LOG(WOLFCLU_L0, "Length of key provided was: %u.",
                    (unsigned int)(hexLen * 4));
        WOLFCLU_LOG(WOLFCLU_L0, "Length of key expected was: %d.",
                    keyBytes * 8);
        WOLFCLU_LOG(WOLFCLU_E0, "Invalid Key. Must match algorithm key size.");
        return WOLFCLU_FATAL_ERROR;
    }

    hexCopy = (char *)XMALLOC(hexLen + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (hexCopy == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(hexCopy, hex, hexLen);
    hexCopy[hexLen] = '\0';

    ret = wolfCLU_hexToBin(hexCopy, &tmp, &tmpSz, NULL, NULL, NULL, NULL, NULL,
                           NULL, NULL, NULL, NULL);
    wolfCLU_ForceZero(hexCopy, hexLen);
    XFREE(hexCopy, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret != WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_E0, "failed during conversion of Key, ret = %d",
                    ret);
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
int wolfCLU_loadHexIvInto(byte *ivOut, int block, const char *hex,
                                 word32 hexLen)
{
    byte *tmp = NULL;
    word32 tmpSz = 0;
    char *hexCopy;
    int ret;

    hexCopy = (char *)XMALLOC(hexLen + 1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (hexCopy == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(hexCopy, hex, hexLen);
    hexCopy[hexLen] = '\0';

    ret = wolfCLU_hexToBin(hexCopy, &tmp, &tmpSz, NULL, NULL, NULL, NULL, NULL,
                           NULL, NULL, NULL, NULL);
    wolfCLU_ForceZero(hexCopy, hexLen);
    XFREE(hexCopy, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    if (ret != WOLFCLU_SUCCESS) {
        WOLFCLU_LOG(WOLFCLU_E0, "failed during conversion of IV, ret = %d",
                    ret);
        /* wolfCLU_hexToBin frees its own buffer on failure; tmp is not ours. */
        return (ret == MEMORY_E) ? MEMORY_E : WOLFCLU_FATAL_ERROR;
    }

    if ((int)tmpSz != block) {
        WOLFCLU_LOG(WOLFCLU_E0, "IV length mismatch: expected %d bytes, got %u",
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

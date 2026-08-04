#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>

int wolfCLU_WriteHex(WOLFSSL_BIO* outBio, byte* data, int size)
{
    int ret = WOLFCLU_SUCCESS;
    static const char hexChars[] = "0123456789abcdef";
    word32 hexSz = (word32)size * 2;
    byte*  hex = (byte*)XMALLOC(hexSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    int    i;

    if (hex == NULL) {
        wolfCLU_LogError("Error malloc'ing for hex");
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        for (i = 0; i < size; i++) {
            hex[2 * i]     = hexChars[(data[i] >> 4) & 0x0F];
            hex[2 * i + 1] = hexChars[data[i] & 0x0F];
        }
        if (wolfSSL_BIO_write(outBio, hex, hexSz) != (int)hexSz) {
            wolfCLU_LogError("Error writing out hex data");
            ret = WOLFCLU_FATAL_ERROR;
        }
        XFREE(hex, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

/* check and convert to base64 */
int wolfCLU_WriteBase64(WOLFSSL_BIO* outBio, byte* data, int size)
{
    int ret = WOLFCLU_SUCCESS;
    byte *base64 = NULL;
    word32 base64Sz;

    if (Base64_Encode(data, size, NULL, &base64Sz) != LENGTH_ONLY_E) {
        wolfCLU_LogError("Error getting size for base64");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        base64 = (byte*)XMALLOC(base64Sz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (base64 == NULL) {
            wolfCLU_LogError("Error malloc'ing for base64");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (Base64_Encode(data, size, base64, &base64Sz) != 0) {
            wolfCLU_LogError("Error base64 encoding");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        wolfSSL_BIO_write(outBio, base64, base64Sz);
        XFREE(base64, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    else {
        XFREE(base64, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

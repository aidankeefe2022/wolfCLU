#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>

#ifndef NO_DSA

int wolfCLU_DSA_PrintParams(DsaKey* dsa, WOLFSSL_BIO* outBio)
{
    int ret = WOLFCLU_SUCCESS;
    byte* outBuf = NULL;
    byte* pem    = NULL;
    word32 outBufSz = 0;
    int pemSz       = 0;

    if (wc_DsaKeyToParamsDer_ex(dsa, NULL, &outBufSz) != LENGTH_ONLY_E) {
        wolfCLU_LogError("Unable to get output buffer size");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        outBuf = (byte*)XMALLOC(outBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS &&
            wc_DsaKeyToParamsDer_ex(dsa, outBuf, &outBufSz) <= 0) {
        wolfCLU_LogError("Could not deserialize DSA params to DER");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        pemSz = wc_DerToPem(outBuf, outBufSz, NULL, 0, DSA_PARAM_TYPE);
        if (pemSz > 0) {
            pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (pem == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        pemSz = wc_DerToPem(outBuf, outBufSz, pem, pemSz, DSA_PARAM_TYPE);
        if (pemSz <= 0) {
            wolfCLU_LogError("Could not trasnform DSA Params Der to Pem");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (outBio != NULL) {
        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(outBio, pem, pemSz) <= 0) {
            wolfCLU_LogError("Could not write to output");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (pem != NULL)
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (outBuf != NULL)
        XFREE(outBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int wolfCLU_DSA_CreateParams(DsaKey* dsa, WC_RNG* rng, word32 modSz)
{
    int ret = WOLFCLU_SUCCESS;

    /* FIPS 186-4 pairs the modulus with a group size, wolfCrypt only knows
     * (1024, 160) (2048, 256) (3072, 256) and rejects anything else */
    if (modSz != 1024 && modSz != 2048 && modSz != 3072) {
        wolfCLU_LogError("Unsupported parameters size");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS &&
            wc_MakeDsaParameters(rng, (int)modSz, dsa) != 0) {
        wolfCLU_LogError("Error generating parameters");
        ret = WOLFCLU_FATAL_ERROR;
    }

    return ret;
}

int wolfCLU_DSA_Genkey(WOLFSSL_BIO* outBio, WC_RNG* rng, DsaKey* dsa)
{
    int ret = WOLFCLU_SUCCESS;
    byte* outBuf    = NULL;
    byte* pem       = NULL;
    word32 outBufSz = 0;
    word32 pemSz    = 0;

    if (wc_MakeDsaKey(rng, dsa) != 0) {
        wolfCLU_LogError("Error making DSA key");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* get DER size (param has p,q,g and key has p,q,g,y,x) */
        if (wc_DsaKeyToParamsDer_ex(dsa, NULL, &outBufSz) != LENGTH_ONLY_E) {
            wolfCLU_LogError("Unable to get output buffer size");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* size is p,q,g + x,y
         * x will be q size plus 64 bits
         * y will be result of g^x mod p */
        outBufSz = outBufSz + outBufSz + (64/WOLFSSL_BIT_SIZE);
        outBuf = (byte*)XMALLOC(outBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wc_DsaKeyToDer(dsa, outBuf, outBufSz);
        if (ret <= 0) {
            wolfCLU_LogError("Error converting DSA key to buffer");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            outBufSz = (word32)ret;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        pemSz = wc_DerToPem(outBuf, outBufSz, NULL, 0, DSA_PRIVATEKEY_TYPE);
        if (pemSz > 0) {
            pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (pem == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        pemSz = wc_DerToPem(outBuf, outBufSz, pem, pemSz,
                DSA_PRIVATEKEY_TYPE);
        if (pemSz <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (outBio != NULL) {
        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(outBio, pem, pemSz) <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (pem != NULL)
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (outBuf != NULL)
        XFREE(outBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#endif /* !NO_DSA */

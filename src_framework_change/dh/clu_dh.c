#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>

#ifndef WOLFSSL_MAX_DH_BITS
    #define WOLFSSL_MAX_DH_BITS       4096
#endif

#ifndef WOLFSSL_MAX_DH_Q_SIZE
    #define WOLFSSL_MAX_DH_Q_SIZE     256
#endif

int wolfCLU_DH_PrintParams(DhKey* dh, WOLFSSL_BIO* outBio)
{
    int ret = WOLFCLU_SUCCESS;
    byte* outBuf = NULL;
    byte* pem    = NULL;
    word32 outBufSz = 0;
    int pemSz       = 0;

    if (wc_DhParamsToDer(dh, NULL, &outBufSz) != LENGTH_ONLY_E) {
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
            wc_DhParamsToDer(dh, outBuf, &outBufSz) <= 0) {
        ret = WOLFCLU_FATAL_ERROR;
        wolfCLU_LogError("Could not deserialize DH params to DER");
    }

    if (ret == WOLFCLU_SUCCESS) {
        pemSz = wc_DerToPem(outBuf, outBufSz, NULL, 0, DH_PARAM_TYPE);
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
        pemSz = wc_DerToPem(outBuf, outBufSz, pem, pemSz, DH_PARAM_TYPE);
        if (pemSz <= 0) {
            wolfCLU_LogError("Could not trasnform DH Params Der to Pem");
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

int wolfCLU_DH_CreateParams(DhKey* dh, WC_RNG* rng, word32 modSz)
{
    int ret = WOLFCLU_SUCCESS;
    #if defined(HAVE_FFDHE_4096)
        #if defined(HAVE_FIPS) && FIPS_VERSION_LE(2,0)
        if (modSz == 4096) {
            const DhParams* params = wc_Dh_ffdhe4096_Get();
            if (wc_DhSetKey(dh, (byte*)params->p, params->p_len,
                        (byte*)params->g, params->g_len) != 0) {
                wolfCLU_LogError("Error setting named 4096 parameters");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else
        #elif (LIBWOLFSSL_VERSION_HEX > 0x05001000)
        if (modSz == 4096) {
            if (wc_DhSetNamedKey(dh, WC_FFDHE_4096) != 0) {
                wolfCLU_LogError("Error setting named 4096 parameters");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else
        #else
        if (modSz == 4096) {
            const DhParams* params = wc_Dh_ffdhe4096_Get();
            if (wc_DhSetKey(dh, (byte*)params->p, params->p_len,
                        (byte*)params->g, params->g_len) != 0) {
                wolfCLU_LogError("Error setting named 4096 parameters");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else
        #endif /* end of version check for using named parameters */
    #endif /* have 4096 named parameters */
        {
            #if defined(HAVE_FIPS) && FIPS_VERSION_LE(2,0)
            /* extra sanity check in FIPS v2 because a clear on sp_int for
             * unsupported mod size with wc_DhGenerateParams can cause issues */
            if (modSz != 1024 && modSz != 2048 && modSz != 3072) {
                wolfCLU_LogError("Unsupported parameters size");
                ret = WOLFCLU_FATAL_ERROR;
            }
            #endif

            if (ret == WOLFCLU_SUCCESS &&
                    wc_DhGenerateParams(rng, modSz, dh) != 0) {
                wolfCLU_LogError("Error generating parameters");
            #if !defined(HAVE_FFDHE_4096)
                if (modSz == 4096) {
                    wolfCLU_LogError("HAVE_FFDHE_4096 macro possibly needs "
                            "defined when building wolfSSL for 4096 params");
                }
            #endif
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    return ret;
}

int wolfCLU_DH_Check(DhKey* dh)
{
    int ret = WOLFCLU_SUCCESS;

    byte *p = NULL;
    byte *g = NULL;
    byte *q = NULL;
    word32 p_len = 0, g_len = 0, q_len = 0;

    /* Export DH parameters */
    if (wc_DhExportParamsRaw(dh, p, &p_len, q, &q_len, g, &g_len) !=
            LENGTH_ONLY_E) {
        wolfCLU_LogError("Failed to get sizes for export DH params");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        p = (byte*)XMALLOC(p_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        q = (byte*)XMALLOC(q_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        g = (byte*)XMALLOC(g_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (p == NULL || q == NULL || g == NULL) {
            wolfCLU_LogError("Failed to malloc DH params buffer");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wc_DhExportParamsRaw(dh, p, &p_len, q, &q_len, g, &g_len) !=
                0) {
            wolfCLU_LogError("Failed to export DH params");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wc_DhSetKey_ex(dh, p, p_len, g, g_len, q, q_len) != 0) {
            wolfCLU_LogError("Failed to set/check DH params");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L0, "DH params are valid.");
        }
    }

    if (p != NULL)
        XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (q != NULL)
        XFREE(q, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (g != NULL)
        XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int wolfCLU_DH_Genkey(WOLFSSL_BIO* outBio, WC_RNG* rng, DhKey* dh)
{
    int ret = WOLFCLU_SUCCESS;
    /* print out the dh key */
    byte priv[WOLFSSL_MAX_DH_BITS/8];
    byte pub[WOLFSSL_MAX_DH_BITS/8];
    word32 privSz   = (word32)sizeof(priv);
    word32 pubSz    = (word32)sizeof(pub);
    byte* outBuf    = NULL;
    byte* pem       = NULL;
    word32 outBufSz = 0;
    word32 pemSz    = 0;

    if (wc_DhGenerateKeyPair(dh, rng, priv, &privSz, pub, &pubSz) != 0) {
        wolfCLU_LogError("Error making DH key");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* get DER size (param has p,q,g and key has p,q,g,y,x) */
        if (wc_DhParamsToDer(dh, NULL, &outBufSz) != LENGTH_ONLY_E) {
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
    #ifndef WOLFSSL_DH_EXTRA
        ret = wc_DhPrivKeyToDer(dh, priv, privSz, outBuf, &outBufSz);
    #else
        ret = wc_DhPrivKeyToDer(dh, outBuf, &outBufSz);
    #endif
        if (ret <= 0) {
            wolfCLU_LogError("Error converting DH key to buffer");
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            outBufSz = (word32)ret;
            ret = WOLFCLU_SUCCESS;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        pemSz = wc_DerToPem(outBuf, outBufSz, NULL, 0, DH_PRIVATEKEY_TYPE);
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
                DH_PRIVATEKEY_TYPE);
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

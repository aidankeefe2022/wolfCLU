/* clu_encrypt.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>
#include <wolfclu/clu_optargs.h>
#include <wolfclu/clu_io.h>
#include <wolfclu/genkey/clu_genkey.h>

#ifndef WOLFCLU_NO_FILESYSTEM

#define MAX_LEN             1024

static int turnUserStdinputToFile(char* in)
{
    int ret = 0;
    word32 inputLength = 0;
    byte* userInputBuffer = NULL;
    WOLFCLU_IO tempIo = {0};
    WOLFCLU_LOG(WOLFCLU_L0, "file did not exist, encrypting string "
            "following \"-i\" instead.");


    /* use user entered data to encrypt */
    inputLength = (int) XSTRLEN(in);
    userInputBuffer = (byte*) XMALLOC(inputLength, HEAP_HINT,
                                            DYNAMIC_TYPE_TMP_BUFFER);
    if (userInputBuffer == NULL)
        return MEMORY_E;



    /* writes the entered text to the input buffer */
    XMEMCPY(userInputBuffer, in, inputLength);

    tempIo = wolfCLU_IO_OpenFile(in, WOLFCLU_IO_WRITABLE_FILE);
    if (tempIo.type > 0) {
        ret = wolfCLU_IO_Write(&tempIo, userInputBuffer, inputLength);
        wolfCLU_IO_Close(&tempIo);
    }
    else {
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* free buffer */
    XFREE(userInputBuffer, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_encrypt(int alg, char* mode, byte* pwdKey, byte* key, word32 size,
        char* in, char* out, byte* iv, int block, int ivCheck)
{
#ifdef HAVE_CAMELLIA
    Camellia camellia;              /* camellia declaration */
#endif

    WOLFCLU_IO  inIo = {0};           /* input file */
    WOLFCLU_IO  outIo = {0};           /* output file */

    WC_RNG     rng;                 /* random number generator declaration */

    byte*   input = NULL;           /* input buffer */
    byte*   output = NULL;          /* output buffer */
    byte    salt[SALT_SIZE] = {0};  /* salt variable */

    int     ret             = WOLFCLU_SUCCESS;    /* return variable */
    int     inputLength     = 0;    /* length of input */
    int     length          = 0;    /* total length */
    int     padCounter      = 0;    /* number of padded bytes */
    word32     i               = 0;    /* loop variable */
    word32     readSz          = 0;    /* bytes read from inIo this pass */

    word32  tempMax         = MAX_LEN;  /* controls encryption amount */

    XMEMSET(&rng, 0, sizeof(rng));

    /* Start up the random number generator */
    if (wc_InitRng(&rng) != 0) {
        wolfCLU_LogError("Random Number Generator failed to start.");
        ret = WOLFCLU_FATAL_ERROR;
    }

    if (ret == WOLFCLU_SUCCESS && access(in, F_OK) == -1) {
        ret = turnUserStdinputToFile(in);
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* open the inFile in read mode */
        inIo = wolfCLU_IO_OpenFile(in, WOLFCLU_IO_READABLE_FILE);
        if (inIo.type <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        /* find length */
        XFSEEK(inIo.fp, 0, SEEK_END);
        inputLength = (int)XFTELL(inIo.fp);
        XFSEEK(inIo.fp, 0, SEEK_SET);

        length = inputLength;

        /* pads the length until it matches a block,
         * and increases pad number
         */
        while (length % block != 0) {
            length++;
            padCounter++;
        }
    }

    /* if the iv was not explicitly set,
     * generate an iv and use the pwdKey
     */
    if (ret == WOLFCLU_SUCCESS && ivCheck == 0) {
        /* IV not set, generate it */
        if (wc_RNG_GenerateBlock(&rng, iv, block) != 0) {
            wolfCLU_LogError("Failed to create IV.");
            ret = WOLFCLU_FATAL_ERROR;
        }

        /* stretches pwdKey to fit size based on wolfCLU_getAlgo() */
        if (ret == WOLFCLU_SUCCESS) {
            ret = wolfCLU_genKey_PWDBASED(&rng, pwdKey, size, salt, padCounter);
            if (ret != WOLFCLU_SUCCESS) {
                wolfCLU_LogError("failed to set pwdKey.");
            }
        }
        if (ret == WOLFCLU_SUCCESS) {
            /* move the generated pwdKey to "key" for encrypting */
            for (i = 0; i < size; i++) {
                key[i] = pwdKey[i];
            }
        }
    }

    /* MALLOC 1kB buffers */
    if (ret == WOLFCLU_SUCCESS) {
        input = (byte*) XMALLOC(MAX_LEN, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (input == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }
    if (ret == WOLFCLU_SUCCESS) {
        output = (byte*) XMALLOC(MAX_LEN, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* open the outFile in write mode */
    if (ret == WOLFCLU_SUCCESS) {
        outIo = wolfCLU_IO_OpenFile(out, WOLFCLU_IO_WRITABLE_FILE);
        if (outIo.type <= 0) {
            wolfCLU_LogError("unable to open output file %s", out);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS)
        ret = wolfCLU_IO_Write(&outIo, salt, SALT_SIZE);
    if (ret == WOLFCLU_SUCCESS)
        ret = wolfCLU_IO_Write(&outIo, iv, block);

    /* loop, encrypt 1kB at a time till length <= 0 */
    while (ret == WOLFCLU_SUCCESS && length > 0) {
        readSz = MAX_LEN;

        ret = wolfCLU_IO_ReadBlock(&inIo, (byte*)input,
                &readSz);
        if (ret != WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Error while reading from stream");
            ret = WOLFCLU_FATAL_ERROR;
            break;
        }

        if (readSz != MAX_LEN) {
            /* pad to end of block */
            for (i = readSz; i < (readSz + padCounter); i++) {
                input[i] = padCounter;
            }
            /* adjust tempMax for less than 1kB encryption */
            tempMax = readSz + padCounter;
        }

#ifdef HAVE_CAMELLIA
        if (alg == WOLFCLU_CAMELLIA128CBC || alg == WOLFCLU_CAMELLIA192CBC ||
                alg == WOLFCLU_CAMELLIA256CBC) {
            if (wc_CamelliaSetKey(&camellia, key, size / 8, iv) != 0) {
                wolfCLU_LogError("CamelliaSetKey failed.");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
            if (XSTRNCMP(mode, "cbc", 3) == 0) {
                if (wc_CamelliaCbcEncrypt(&camellia, output, input,
                            tempMax) != 0) {
                    wolfCLU_LogError("CamelliaCbcEncrypt failed.");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
            }
            else {
                wolfCLU_LogError("Incompatible mode while using Camellia.");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }
        }
#endif /* HAVE_CAMELLIA */

        ret = wolfCLU_IO_Write(&outIo, output, tempMax);

        length -= tempMax;
        if (length < 0)
            WOLFCLU_LOG(WOLFCLU_L0, "length went past zero.");
    }

    /* closes the opened files and frees the memory */
    wolfCLU_ForceZero(key, size);
    wolfCLU_ForceZero(iv, block);

    wolfCLU_IO_Close(&inIo);
    wolfCLU_IO_Close(&outIo);

    /* Use the wolfssl free for rng */
    wc_FreeRng(&rng);
    wc_ForceZero(input, MAX_LEN);
    wolfCLU_freeBins(input, output, NULL, NULL, NULL);

    (void)mode;
    (void)alg;
    return ret;
}
#endif

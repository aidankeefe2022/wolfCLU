/* clu_main.c
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
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_arg_handlers.h>
#include <wolfclu/clu_log.h>
#include <wolfcli/cli.h>

/* Commands that have been moved over to the wolfCLI framework. Everything
 * still on the old wolfCLU_*Setup() getopt path is absent from this tree and
 * is unreachable until it is migrated; add the command here as part of
 * migrating it. */
static WOLFCLI_COMMAND* rootSubCommands[] = {
    &bench,
    &dhCommand,
    &dsaCommand,
    &hashCommand,
    &decryptCommand,
    &encryptCommand,
};

WOLFCLI_COMMAND rootCommand = {
    .name = "wolfssl",
    .shortHelp = "Command Line Utility for Interacting "
        "With the WolfSSL library",
    .longHelp = (
"The wolfssl program is a command line tool for using various cryptographic \n\
functions of wolfSSL's wolfCrypt cryptography library. \n\
wolfSSL supports industry standards up to the current TLSv1.3 and \n\
DTLSv1.3 and offers a simple API for ease of use. It can be utilized for: \n\
    - Encryption and decryption with ciphers \n\
    - Hashing functionality \n\
    - Benchmark utilities \n\
    - X.509 certificate processing and conversion \n\
    - Certificate requests and signing (CA) \n\
    - Key generation and key format conversion \n\
    - Signing and signature verification \n\
    - TLS client/server testing "),
    .commands = {
        .commands = rootSubCommands,
        .commandsSz = sizeof(rootSubCommands) / sizeof(*rootSubCommands),
    },
};

#ifdef HAVE_FIPS
static void myFipsCb(int ok, int err, const char* hash)
{
    printf("in my Fips callback, ok = %d, err = %d\n", ok, err);
    printf("message = %s\n", wc_GetErrorString(err));
    printf("hash = %s\n", hash);

    if (err == IN_CORE_FIPS_E) {
        printf("In core integrity hash check failure, copy above hash\n");
        printf("into verifyCore[] in fips_test.c and rebuild\n");
    }
}
#endif

static int clu_main(int argc, const char* argv[])
{
    /* With no arguments at all there is nothing for the parser to walk, so
     * ask the framework for the root help menu instead of letting it report a
     * missing subcommand. */
    if (argc <= 1) {
        const char* helpArgv[] = { "wolfssl", "-h" };

        return wolfCLI_runCommand(2, helpArgv, &rootCommand);
    }

    return wolfCLI_runCommand(argc, argv, &rootCommand);
}

int main(int argc, const char* argv[])
{
    int ret;
#ifdef HAVE_FIPS
    WC_RNG rng;

    wolfCrypt_SetCb_fips(myFipsCb);

    #ifdef WC_RNG_SEED_CB
        wc_SetSeed_Cb(wc_GenerateSeed);
    #endif

    ret = wc_InitRng(&rng);

    if (ret != 0) {
        wolfCLU_LogError("Err %d, update the FIPS hash\n", ret);
        return ret;
    }

    wc_FreeRng(&rng);

    if (wolfCrypt_GetStatus_fips() == IN_CORE_FIPS_E) {
        WOLFCLU_LOG(WOLFCLU_L0, "Linked to a FIPS version of wolfSSL that has failed the in core"
               "integrity check. ALL FIPS crypto will report ERRORS when used."
               "To resolve please recompile wolfSSL with the correct integrity"
               "hash. If the issue continues, contact fips @ wolfssl.com");
    }
#endif

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        wolfCLU_LogError("wolfSSL initialization failed!");
        return -1;
    }

    ret = clu_main(argc, argv);

    wolfSSL_Cleanup();

    /* the shell expects 0 on success, the framework reports WOLFCLI_SUCCESS */
    return (ret == WOLFCLI_SUCCESS) ? 0 : ret;
}


#ifdef FREERTOS

#ifndef MAX_COMMAND_ARGS
#define MAX_COMMAND_ARGS 30
#endif

#ifndef HAL_CONSOLE_UART
#define HAL_CONSOLE_UART huart4
#endif
extern UART_HandleTypeDef HAL_CONSOLE_UART;

/* When building on FreeRTOS, clu_entry() acts as the entry function and
 * parses the UART-transmitted command. Be sure to rename the main function
 * above, to clu_main() so the right function is called below */
int clu_entry(const void* argument)
{

    HAL_StatusTypeDef halRet;
    byte buffer[51] = {0};

    char* command;
    char* token;

    char* argv[MAX_COMMAND_ARGS];
    int argc = 1;

    int i = 0;
    int ret;

    WOLFCLU_LOG(WOLFCLU_L0, "Please enter a wolfCLU command (wolfssl -h for help)");

    /* Receive the command from the UART console */
    do {
        halRet = HAL_UART_Receive(&HAL_CONSOLE_UART, buffer, (sizeof(buffer)-1), 100);
    } while (halRet != HAL_OK || buffer[0] == '\n' || buffer[0] == '\r');

    WOLFCLU_LOG(WOLFCLU_L0, "Command received.");

    command = (char*)buffer;

    /* Determine the number of supplied arguments */
    for (i = 0; command[i] != '\0' && i < XSTRLEN(command); i++) {
        if (command[i]==' ') {
            argc++;
        }
    }

    if (argc > MAX_COMMAND_ARGS) {
        WOLFCLU_LOG(WOLFCLU_L0, "Too many arguments (max %d)", MAX_COMMAND_ARGS);
        return -1;
    }

    i = 0;
    token = strtok(command, " ");

    /* split the command string to correspond to separate argv[i] */
    while (token != NULL && i < argc) {
        argv[i] = XMALLOC(XSTRLEN(token)+1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        XMEMSET(argv[i], 0, XSTRLEN(token)+1);
        XSTRNCPY(argv[i], token, XSTRLEN(token));
        i++;
        if (i==(argc-1)) {
            token = strtok(NULL, "\r");
        }
        else {
            token = strtok(NULL, " ");
        }
    }

    ret = clu_main(argc, (const char**)argv);

    /* free malloc'd argv[i] args */
    for (i = 0; i < argc; i++) {
        XFREE(argv[i], HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}
#endif

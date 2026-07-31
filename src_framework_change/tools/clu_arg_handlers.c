#include <wolfclu/clu_arg_handlers.h>
#include <wolfssl/ssl.h>

int wolfCLU_handleInFile(const char* arg, void* out)
{
    int ret = WOLFCLI_SUCCESS;

    WOLFSSL_BIO** bio = (WOLFSSL_BIO**)out;

    *bio = wolfSSL_BIO_new_file(arg, "rb");
    if (*bio == NULL) {
        wolfCLU_LogError("Could not open file: %s", arg);
        ret = WOLFCLI_FATAL_ERROR;
    }

    return ret;
}

int wolfCLU_handleOutFile(const char* arg, void* out)
{
    int ret = WOLFCLI_SUCCESS;

    WOLFSSL_BIO** bio = (WOLFSSL_BIO**)out;

    *bio = wolfSSL_BIO_new_file(arg, "wb");
    if (*bio == NULL) {
        wolfCLU_LogError("Could not write to file: %s", arg);
        ret = WOLFCLI_FATAL_ERROR;
    }

    return ret;
}

int wolfCLU_handleCopyString(const char* arg, void* out)
{
    if (out == NULL) {
        wolfCLU_LogError("out was null");
        return WOLFCLI_FATAL_ERROR;
    }
    struct string {
        unsigned int cap;
        char* data;
    } *string = (struct string*)out;
    XSTRNCPY(string->data, arg, string->cap);
    return WOLFCLI_SUCCESS;
}


int wolfCLU_handleGetHash(const char* arg, void* out)
{
    const WOLFSSL_EVP_MD* hashType = wolfSSL_EVP_get_digestbyname(arg);
    if (hashType == NULL) {
        wolfCLU_LogError("Hash type %s is not avalible", arg);
        return WOLFCLI_FATAL_ERROR;
    }
    *(WOLFSSL_EVP_MD**)out = (WOLFSSL_EVP_MD*)hashType;
    return WOLFCLU_SUCCESS;
}

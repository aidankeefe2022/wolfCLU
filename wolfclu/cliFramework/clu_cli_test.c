/* clu_cli_test.c
 *
 * Standalone driver for the prototype CLI framework.
 *
 * Unlike the earlier version, this file does NOT re-implement the parser.
 * It declares a small command tree and hands it straight to the framework's
 * public entry point, runCommand() (declared in clu_cli.h, defined in
 * src/cluFramework/clu_cli.c).  Everything below is just data + leaf entry
 * functions -- the walking, flag filling and help printing all live in the
 * framework.
 *
 * The design under test: each leaf command owns its own file-static value
 * slots; the flag table registers &slot so the parser writes parsed strings
 * through the opaque `const char**` handle, and the zero-arg commandEntry()
 * reads its own slots back -- never naming another command's variables.
 *
 * Build (note: clu_cli.c is now part of the link):
 *   gcc -I. -I/usr/local/include -Wall -Wextra \
 *       wolfclu/cliFramework/clu_cli_test.c \
 *       src/cluFramework/clu_cli.c src/clu_log.c \
 *       -L/usr/local/lib -lwolfssl -o clu_cli_test
 *
 * Try:
 *   ./clu_cli_test -h
 *   ./clu_cli_test genkey -out key.pem -algo rsa
 *   ./clu_cli_test hash -in file.txt
 *   ./clu_cli_test -v genkey -out key.pem
 */

#include <wolfclu/cliFramework/clu_cli.h>

/* --- genkey command ------------------------------------------------------ */
/* value slots owned by this "command's file" (here, this translation unit) */
static const char* genkeyOut  = NULL;
static const char* genkeyAlgo = NULL;

static int genkeyEntry(void)
{
    wolfCLU_Log(WOLFCLU_L0, "[genkey] out  = %s",
                genkeyOut  ? genkeyOut  : "(unset)");
    wolfCLU_Log(WOLFCLU_L0, "[genkey] algo = %s",
                genkeyAlgo ? genkeyAlgo : "(unset)");
    return WOLFCLU_SUCCESS;
}

static WOLFCLU_FLAG genkeyFlags[] = {
    { .flag = "-out",
      .modes = WOLFCLU_FLAG_HAS_ARG | WOLFCLU_FLAG_REQUIRED,
      .shortHelp = "output key file",
      .longHelp  = "-out <file>\n  File to write the generated key to.\n",
      .value = &genkeyOut },
    { .flag = "-algo",
      .modes = WOLFCLU_FLAG_HAS_ARG,
      .shortHelp = "key algorithm",
      .longHelp  = "-algo <name>\n  Key algorithm to generate, e.g. rsa/ecc.\n",
      .value = &genkeyAlgo },
};

/* --- hash command -------------------------------------------------------- */
static const char* hashIn   = NULL;
static const char* hashAlgo = NULL;

static int hashEntry(void)
{
    wolfCLU_Log(WOLFCLU_L0, "[hash] in   = %s", hashIn   ? hashIn   : "(unset)");
    wolfCLU_Log(WOLFCLU_L0, "[hash] algo = %s", hashAlgo ? hashAlgo : "(unset)");
    return WOLFCLU_SUCCESS;
}

static WOLFCLU_FLAG hashFlags[] = {
    { .flag = "-in",
      .modes = WOLFCLU_FLAG_HAS_ARG | WOLFCLU_FLAG_REQUIRED,
      .shortHelp = "input file",
      .longHelp  = "-in <file>\n  File to hash.\n",
      .value = &hashIn },
    { .flag = "-algo",
      .modes = WOLFCLU_FLAG_HAS_ARG,
      .shortHelp = "digest algorithm",
      .longHelp  = "-algo <name>\n  Digest to use, e.g. sha256.\n",
      .value = &hashAlgo },
};

/* --- root command -------------------------------------------------------- */
static const char* rootVerbose = NULL;   /* presence flag slot */

static int rootEntry(void)
{
    wolfCLU_Log(WOLFCLU_L0,
                "clu: no subcommand given (try 'genkey', 'hash', or -h)");
    if (rootVerbose != NULL) {
        wolfCLU_Log(WOLFCLU_L0, "clu: verbose mode on");
    }
    return WOLFCLU_SUCCESS;
}

static WOLFCLU_FLAG rootFlags[] = {
    { .flag = "-v",
      .modes = 0,   /* presence flag: consumes no argument */
      .shortHelp = "verbose output",
      .longHelp  = "Enable verbose output.",
      .value = &rootVerbose },
};

static WOLFCLU_COMMAND subCommands[] = {
    { .name = "genkey",
      .shortHelp = "generate a key",
      .longHelp  = "genkey -out <file> [-algo <name>]\n",
      .commandEntry = genkeyEntry,
      .flagsSz = sizeof(genkeyFlags) / sizeof(genkeyFlags[0]),
      .flags   = genkeyFlags },
    { .name = "hash",
      .shortHelp = "hash a file",
      .longHelp  = "hash -in <file> [-algo <name>]\n",
      .commandEntry = hashEntry,
      .flagsSz = sizeof(hashFlags) / sizeof(hashFlags[0]),
      .flags   = hashFlags },
};

static WOLFCLU_COMMAND rootCommand = {
    .name = "clu",
    .shortHelp = "wolfCLU prototype CLI",
    .longHelp  = "clu [-v] <command> [options]\n",
    .commandEntry = rootEntry,
    .flagsSz = sizeof(rootFlags) / sizeof(rootFlags[0]),
    .flags   = rootFlags,
    .commandsSz = sizeof(subCommands) / sizeof(subCommands[0]),
    .commands   = subCommands,
};

int main(int argc, char** argv)
{
    int ret;

    /* skip argv[0] (program name); walk from the root command.  The framework
     * takes const char**; argv is char** so cast the tail explicitly. */
    ret = runCommand(argc - 1, (const char**)(argv + 1), &rootCommand);

    return (ret == WOLFCLU_SUCCESS) ? 0 : 1;
}

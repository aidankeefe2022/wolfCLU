/* clu_error_codes.h
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
#include <wolfclu/cliFramework/clu_cli.h>

static int flagHelp(const WOLFCLU_FLAG* flag)
{
    wolfCLU_Log(WOLFCLU_L0, "==== %s FLAG HELP ====\n", flag->flag);
    wolfCLU_Log(WOLFCLU_L0, "  %s", flag->longHelp);
    return WOLFCLU_SUCCESS;
}


static int commandHelp(const WOLFCLU_COMMAND* command)
{
    wolfCLU_Log(WOLFCLU_L0, "==== HELP MENU FOR %s ====\n", command->name);
    wolfCLU_Log(WOLFCLU_L0, "%s", command->longHelp);
    if (command->commandsSz > 0) {
        wolfCLU_Log(WOLFCLU_L0, "\n==== SUB COMMANDS FOR %s ====\n", command->name);
        for (word32 i = 0; i < command->commandsSz; i++) {
            wolfCLU_Log(WOLFCLU_L0, "  %s -> %s", command->commands[i].name,
                    command->commands[i].shortHelp);
        }
    }
    if (command->flagsSz> 0) {
        wolfCLU_Log(WOLFCLU_L0, "\n==== FLAGS FOR %s ====\n", command->name);
        for (word32 i = 0; i < command->flagsSz; i++) {
            wolfCLU_Log(WOLFCLU_L0, "  %s -> %s", command->flags[i].flag,
                    command->flags[i].shortHelp);
        }
    }
    return WOLFCLU_SUCCESS;
}

static int isHelp(const char* tok) {
    if (tok == NULL) {
        return 0;
    }
    return (strcmp(tok, "-h") == 0) || (strcmp(tok, "-help") == 0);
}

static WOLFCLU_FLAG* handleFlag(WOLFCLU_COMMAND* command, const char* tok,
        const char* next)
{
    word32 i;
    WOLFCLU_FLAG* flag = NULL;

    for (i = 0; i < command->flagsSz; i++) {
        if (strcmp(command->flags[i].flag, tok) == 0) {
            /* Repeatable argument so we append to a user buffer */
            if (command->flags[i].found == WOLFCLU_FLAG_FOUND) {
                if (!(command->flags[i].modes & WOLFCLU_FLAG_REPEATABLE)) {
                    wolfCLU_LogError("A flag that is not repeatable was "
                            "found more than once: %s", command->flags[i].flag);
                    return NULL;
                }
            }
            command->flags[i].found = WOLFCLU_FLAG_FOUND;
            flag = &command->flags[i];
            break;
        }
    }

    if (flag != NULL) {
        if (flag->modes & WOLFCLU_FLAG_HAS_ARG) {
            if (next == NULL || next[0] == '-') {
                wolfCLU_LogError("A flag that requires an argument did "
                        "not find one: %s", tok);
                return NULL;
            }

            if (flag->found == WOLFCLU_FLAG_FOUND) {
                (*flag->value)++;
            }
            *flag->value = next;
        }
        else {
            *flag->value = (char*)flag->flag;
        }
    }
    else {
        wolfCLU_LogError("A flag of %s was not a real flag: %s",
                command->name, tok);
        return NULL;
    }


    return flag;
}


static WOLFCLU_COMMAND* findSubCommand(const WOLFCLU_COMMAND* command,
        const char* tok)
{
    word32 i;
    for (i = 0; i < command->commandsSz; i++) {
        if (strcmp(tok, command->commands[i].name) == 0) {
            return &command->commands[i];
        }
    }
    wolfCLU_LogError("A Subcommand of %s was not a subcommand: %s",
            command->name, tok);
    return NULL;
}

int runCommand(int argc, const char* argv[], WOLFCLU_COMMAND* command)
{
    int ret = WOLFCLU_SUCCESS;
    WOLFCLU_COMMAND* curCommand = command;

    if (command == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    for (int i = 0; i < argc; i++) {
        if (isHelp(argv[i])) {
            return commandHelp(curCommand);
        }
        if (argv[i][0] == '-') {
            const char* next = i + 1 < argc ? argv[i+1] : NULL;
            WOLFCLU_FLAG* flag = handleFlag(curCommand, argv[i], next);
            if (flag == NULL) {
                return WOLFCLU_FATAL_ERROR;
            }
            if (isHelp(next)) {
                return flagHelp(flag);
            }
            if (flag->modes & WOLFCLU_FLAG_HAS_ARG) {
                i++;
            }
            continue;
        }
        curCommand = findSubCommand(curCommand, argv[i]);
        if (curCommand == NULL) {
            return WOLFCLU_FATAL_ERROR;
        }
    }

    ret = curCommand->commandEntry();
    return ret;
}

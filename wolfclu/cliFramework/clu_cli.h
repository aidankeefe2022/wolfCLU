/* clu_error_codes.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by
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

#ifndef WOLFCLU_CLI_H
#define WOLFCLU_CLI_H

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_error_codes.h>
#include <wolfclu/clu_log.h>


enum WOLFCLU_FLAG_OPTIONS {
    WOLFCLU_FLAG_REPEATABLE = 1 << 1,
    WOLFCLU_FLAG_REQUIRED   = 1 << 2,
    WOLFCLU_FLAG_HAS_ARG    = 1 << 3,
};

const static byte WOLFCLU_FLAG_FOUND = 1;
const static byte WOLFCLU_FLAG_NOT_FOUND = 0;


typedef struct WOLFCLU_FLAG {
    const char* flag;
    /* used as flags to be bit OR set and AND checked
     * NOT modes == <OPTION> USE modes & <OPTION> */
    enum WOLFCLU_FLAG_OPTIONS modes;
    const char* shortHelp;
    const char* longHelp;
    const char** value;
    byte found;
}WOLFCLU_FLAG;

typedef struct WOLFCLU_COMMAND {
    const char* name;
    const char* shortHelp;
    const char* longHelp;
    int (*commandEntry)(void);
    word32 flagsSz;
    WOLFCLU_FLAG* flags;
    word32 commandsSz;
    struct WOLFCLU_COMMAND* commands;
    byte found;
}WOLFCLU_COMMAND;

int runCommand(int argc, const char* argv[], WOLFCLU_COMMAND* command);




#endif

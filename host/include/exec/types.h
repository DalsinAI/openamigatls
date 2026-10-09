/* Host build of OpenTLS: the few AmigaOS types its headers use.
 * MIT, Copyright (c) 2026 Dalsin Limited. */
#ifndef EXEC_TYPES_H
#define EXEC_TYPES_H
#include <stdint.h>
typedef void *APTR;
typedef const void *CONST_APTR;
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef int16_t WORD;
typedef uint16_t UWORD;
typedef int8_t BYTE;
typedef uint8_t UBYTE;
typedef char *STRPTR;
typedef const char *CONST_STRPTR;
typedef short BOOL;
#define VOID void
#define CONST const
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#endif

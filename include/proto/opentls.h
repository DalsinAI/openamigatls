#ifndef PROTO_OPENTLS_H
#define PROTO_OPENTLS_H
/* opentls.library. MIT licensed and free. Copyright (c) 2026 AmigaChrome Team. */

#include <exec/types.h>
#include <exec/libraries.h>
#include <libraries/opentls.h>

#ifndef __NOLIBBASE__
extern struct Library *OpenTLSBase;
#endif

#if defined(__VBCC__)
#include <inline/opentls_protos.h>
#elif defined(__GNUC__)
#include <inline/opentls.h>
#else
#include <clib/opentls_protos.h>
#endif

#endif

/* Host build of OpenTLS: struct Hook, entered as a C function
 * h_Entry(hook, object, message). MIT, Copyright (c) 2026 Dalsin Limited. */
#ifndef UTILITY_HOOKS_H
#define UTILITY_HOOKS_H
#include <exec/types.h>
struct MinNode { struct MinNode *mln_Succ, *mln_Pred; };
struct Hook {
    struct MinNode h_MinNode;
    ULONG (*h_Entry)(struct Hook *, APTR, APTR);
    ULONG (*h_SubEntry)(struct Hook *, APTR, APTR);
    APTR h_Data;
};
#endif

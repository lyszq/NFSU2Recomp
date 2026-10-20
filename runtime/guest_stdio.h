#ifndef NFSU2_GUEST_STDIO_H
#define NFSU2_GUEST_STDIO_H
#include "guest_execution.h"
/* Explicit GUI guest process with no console, redirected or inherited std
 * handles. GetStdHandle supports only DWORD selectors -10,-11,-12 and returns
 * NULL (not a fake handle), preserving LastError. Other selectors unsupported.
 * GetFileType accepts only known-invalid handles NULL/INVALID_HANDLE_VALUE:
 * returns FILE_TYPE_UNKNOWN=0 and sets guest TEB+0x34 LastError=6. Other handles
 * remain unsupported until there is an actual guest file-handle table.
 * Both use stdcall argc1, preserve flags/nonresult GPRs, snapshot the readable
 * 8-byte frame and validate all writes before mutation. GetFileType requires
 * a nonzero TEB (-2 on zero); memory/overflow faults -1. Unknown/malformed host
 * args return 0 unchanged. Return contract matches GuestImportHandler. */
int guest_stdio_import(CPU *, const GuestImport *, uint32_t *fault);
#endif

# Analysis of Toolhelp Execution and Downstream Boundaries in SPEED2.EXE

## 1. Executive Summary

This report documents the downstream reverse engineering and dynamic execution analysis of `SPEED2.EXE` (SHA256: `8f6a9ae2c4cfa01181d2fd755d99c6f4b7103f60273908ea1de1e719dfe2a297`, size 4,788,224 bytes) beyond the current startup reference boundary at `CreateToolhelp32Snapshot`.

### Key Findings

1. **CheckMultipleInstances (`0x005b7b30`) Flow**:
   - `0x00580e17` calls `0x005b7b30` with `("speed2.exe", 1)`.
   - `0x005b7b30` allocates `0x22c` bytes on the stack for `PROCESSENTRY32` (size `0x128` = 296 bytes).
   - It invokes `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS=2, 0)`.
   - It iterates using `Process32First` and `Process32Next`. For each entry, `szExeFile` (offset `+0x24` / `esp + 0x34`) is checked via `strrchr('\\')` at `0x0075d660` and compared against `"speed2.exe"` via `_stricmp` at `0x0075dd6f`.
   - When exactly 1 instance matches, `count (1) <= max_allowed (1)`.
   - The snapshot handle is closed via `CloseHandle(hSnapshot)`.
   - The function returns `al = 0` (`0x005b7c38: mov al, dl; ... ret`).
   - At `0x00580e1f: test al, al; je 0x580e2a;`, the jump to `0x00580e2a` is taken.

2. **The Hidden CRT Prerequisite (`GetLastError` / `SetLastError`)**:
   - Statically linked MSVC CRT `_stricmp` (`0x0075dd6f`) invokes `_getptd()` (`0x00761e3c`) to retrieve per-thread locale data.
   - `_getptd()` preserves the Win32 last error code across thread-data lookup by calling `GetLastError()` and `SetLastError()`.
   - If only the 4 toolhelp imports (`CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `CloseHandle`) are intercepted without `GetLastError`, execution stops prematurely at `0x00761e3e` (`KERNEL32.dll!GetLastError`) before `0x005b7b30` can finish.
   - When `GetLastError` and `SetLastError` are backed by the guest TEB last-error slot (`TEB_BASE + 0x34`), `_stricmp` succeeds, `0x005b7b30` finishes cleanly, and execution proceeds downstream.

3. **The EXACT Next Unsupported Import**:
   - With toolhelp and CRT last-error handling in place, execution proceeds past `0x00580e2a`, enters `0x0057ed20` (`GameInit`), calls `0x005b76a0` (`PlatformInit`), which jumps via `0x0043e5b0` into `0x0043bd90` (`TimerCalibrate`).
   - At IP `0x0043bd98`, execution attempts to call:
     $$\mathbf{KERNEL32.dll!QueryPerformanceFrequency}$$
   - Import target sentinel: `0xf000007e` (IAT slot: `0x00783118`).
   - Return address: `0x0043bd9e`.
   - Stack pointer (ESP): `0x7fefeeec`.
   - Argument passed: `[0x7fefeef4]` (`OUT LARGE_INTEGER *lpFrequency`, pointer to 8-byte stack buffer).

4. **Extended Downstream Boundaries**:
   - If `QueryPerformanceFrequency` is satisfied (returning non-zero with e.g. 1,000,000 Hz):
     - Execution advances to `0x006f580f`, stopping at `KERNEL32.dll!GetCurrentProcess` (target `0xf000009b`), where the game prepares to duplicate its thread pseudo-handle via `DuplicateHandle` at `0x006f581c`.
   - If process/thread handle queries (`GetCurrentProcess`, `GetCurrentThread`, `DuplicateHandle`) are satisfied:
     - Execution advances to `0x006f5d17`, stopping at `WINMM.dll!timeGetDevCaps` (target `0xf00000ef`), where multimedia timer initialization begins.

---

## 2. Quantitative Execution Statistics

The following table summarizes execution metrics from the PE entry point (`0x0075bcc7`) to each boundary stage, measured with `tools/ios_private/explore_downstream.py`:

| Metric | Current Master (CreateToolhelp32Snapshot) | Stage -1 (Strict Toolhelp; stops at GetLastError) | Stage 0 (Downstream Boundary: QueryPerformanceFrequency) | Stage 1 (Extended: GetCurrentProcess) | Stage 2 (Extended: timeGetDevCaps) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Status** | `GUEST_STOP_IMPORT` | `GUEST_STOP_IMPORT` | `GUEST_STOP_IMPORT` | `GUEST_STOP_IMPORT` | `GUEST_STOP_IMPORT` |
| **Boundary API** | `KERNEL32!CreateToolhelp32Snapshot` | `KERNEL32!GetLastError` | `KERNEL32!QueryPerformanceFrequency` | `KERNEL32!GetCurrentProcess` | `WINMM!timeGetDevCaps` |
| **Call IP** | `0x0076e9fc` | `0x00761e3e` | `0x0043bd98` | `0x006f580f` | `0x006f5d17` |
| **Return Address** | `0x005b7b5e` | `0x00761e44` | `0x0043bd9e` | `0x006f5811` | `0x006f5d1d` |
| **Target Sentinel** | `0xf000008d` | `0xf000007d` | `0xf000007e` | `0xf000009b` | `0xf00000ef` |
| **ESP at Call** | `0x7fefecac` | `0x7fefecb0` | `0x7fefeeec` | `0x7fefeee4` | `0x7fefeecc` |
| **Arguments** | `[0x2, 0x0]` | `[]` | `[0x7fefeef4]` | `[]` | `[0x7fefeee4, 0x8]` |
| **Arch Instructions** | 191,558 | 191,669 (+111) | **191,966** (+408) | 192,835 (+1,277) | 192,892 (+1,334) |
| **Raw Instructions** | 217,258 | 217,390 (+132) | **217,687** (+429) | 218,556 (+1,298) | 218,621 (+1,363) |
| **Trace Hash (Arch)**| 1459213057555500656 | 231030590570232141 | **14916273144485837567** | 7281239442220866530 | 950126576534750896 |
| **Raw Trace Hash** | 7202581... | 3182885359486698533 | **17047650262956798359** | 4387902853386396810 | 13921962448031439024 |
| **CALL Dispatches** | 10,482 | 10,487 (+5) | **10,509** (+27) | 10,541 (+59) | 10,547 (+65) |
| **API Invocations** | 865 | 867 (+2) | **877** (+12) | 884 (+19) | 888 (+23) |
| **Max Call Depth** | 12 | 12 | **12** | 12 | 12 |
| **Observed Targets** | 1,022 | 1,026 (+4) | **1,034** (+12) | 1,047 (+25) | 1,049 (+27) |

---

## 3. Disassembly Analysis and Detailed Execution Flow

### 3.1 Main Function Entry (`0x00580e10`)

The CRT startup calls `main` at `0x0075be2b`:
```x86
0x0075be1e: push       eax                    ; nCmdShow / envp
0x0075be1f: push       dword ptr [0x8b8448]   ; argv
0x0075be25: push       dword ptr [0x8b8444]   ; argc
0x0075be2b: call       0x00580e10             ; main(argc, argv, envp)
```

Inside `main` (`0x00580e10`):
```x86
0x00580e10: push       1                      ; max_instances = 1
0x00580e12: push       0x007a0dfc             ; "speed2.exe"
0x00580e17: call       0x005b7b30             ; CheckMultipleInstances("speed2.exe", 1)
0x00580e1c: add        esp, 8
0x00580e1f: test       al, al
0x00580e21: je         0x00580e2a             ; If 0, jump to downstream init!
0x00580e23: push       0
0x00580e25: call       0x0075d5a4             ; exit(0)
; --- Success Path ---
0x00580e2a: mov        eax, dword ptr [esp + 8] ; argv
0x00580e2e: mov        ecx, dword ptr [esp + 4] ; argc
0x00580e32: push       eax
0x00580e33: push       ecx
0x00580e34: call       0x0057ed20             ; GameInit(argc, argv)
0x00580e39: add        esp, 8
0x00580e3c: call       0x00580890             ; CheckSafeMode()
0x00580e41: test       al, al
0x00580e43: je         0x00580e4c
0x00580e45: call       0x004fef60
...
0x00580e80: call       0x005811d0             ; MainGameLoop()
0x00580e85: call       0x005cf970             ; GameShutdown()
0x00580e8a: push       0
0x00580e8c: call       0x0075d5a4             ; exit(0)
```

### 3.2 The CheckMultipleInstances Function (`0x005b7b30`)

```x86
0x005b7b30: sub        esp, 0x22c             ; Local frame for PROCESSENTRY32 (0x128 bytes) + temp buf
0x005b7b36: push       ebx
0x005b7b37: push       ebp
0x005b7b38: push       esi
0x005b7b39: push       edi
0x005b7b3a: xor        eax, eax
0x005b7b3c: mov        dword ptr [esp + 0x10], 0
0x005b7b44: mov        ecx, 0x49
0x005b7b49: lea        edi, [esp + 0x14]
0x005b7b4d: rep stosd                         ; Zero out PROCESSENTRY32
0x005b7b4f: xor        edi, edi               ; edi = match_counter = 0
0x005b7b51: push       edi                    ; th32ProcessID = 0
0x005b7b52: push       2                      ; dwFlags = TH32CS_SNAPPROCESS (2)
0x005b7b54: mov        ebx, 3                 ; retry_limit = 3
0x005b7b59: call       0x0076e9fc             ; CreateToolhelp32Snapshot(2, 0)
0x005b7b5e: mov        esi, eax               ; esi = hSnapshot
0x005b7b60: cmp        esi, -1
0x005b7b63: je         0x005b7c21             ; If INVALID_HANDLE_VALUE, exit returning 0
0x005b7b69: mov        ebp, dword ptr [0x00783150] ; KERNEL32!Sleep

; Process enumeration loop:
0x005b7b70: lea        eax, [esp + 0x10]
0x005b7b74: push       eax                    ; &pe32
0x005b7b75: push       esi                    ; hSnapshot
0x005b7b76: mov        dword ptr [esp + 0x18], 0x128 ; pe32.dwSize = sizeof(PROCESSENTRY32) = 296
0x005b7b7e: call       0x0076e9f6             ; Process32First(hSnapshot, &pe32)
0x005b7b83: test       eax, eax
0x005b7b85: je         0x005b7bee             ; If FALSE, break to CloseHandle

; Extract filename from pe32.szExeFile (esp + 0x34):
0x005b7b87: lea        ecx, [esp + 0x34]
0x005b7b8b: push       0x5c                   ; '\\'
0x005b7b8d: push       ecx
0x005b7b8e: call       0x0075d660             ; strrchr(pe32.szExeFile, '\\')
0x005b7b93: add        esp, 8
0x005b7b96: test       eax, eax
0x005b7b98: je         0x005b7bb0             ; If no backslash, copy raw string
0x005b7b9a: inc        eax                    ; Skip backslash
0x005b7b9b: lea        edx, [esp + 0x138]
; string copy loop ...
0x005b7bc2: mov        eax, dword ptr [esp + 0x240] ; arg_0 = "speed2.exe"
0x005b7bc9: lea        edx, [esp + 0x138]     ; extracted exe name
0x005b7bd0: push       edx
0x005b7bd1: push       eax
0x005b7bd2: call       0x0075dd6f             ; _stricmp("speed2.exe", extracted_name)
0x005b7bd7: add        esp, 8
0x005b7bda: test       eax, eax
0x005b7bdc: jne        0x005b7bdf
0x005b7bde: inc        edi                    ; If match, edi++ (edi = 1)
0x005b7bdf: lea        ecx, [esp + 0x10]
0x005b7be3: push       ecx                    ; &pe32
0x005b7be4: push       esi                    ; hSnapshot
0x005b7be5: call       0x0076e9f0             ; Process32Next(hSnapshot, &pe32)
0x005b7bea: test       eax, eax
0x005b7bec: jne        0x005b7b87             ; Loop while more processes exist

; Enumeration finish:
0x005b7bee: push       esi
0x005b7bef: call       dword ptr [0x00783144] ; KERNEL32!CloseHandle(hSnapshot)
0x005b7bf5: mov        eax, dword ptr [esp + 0x244] ; arg_4 = max_instances = 1
0x005b7bfc: dec        ebx
0x005b7bfd: cmp        edi, eax               ; Compare count (1) with max_instances (1)
0x005b7bff: jle        0x005b7c2e             ; 1 <= 1 is TRUE -> jump to return 0!
...
; Success return block:
0x005b7c2e: xor        edx, edx
0x005b7c30: cmp        edi, eax               ; edi (1), eax (1)
0x005b7c32: pop        edi
0x005b7c33: pop        esi
0x005b7c34: setg       dl                     ; dl = (count > max_allowed) ? 1 : 0 -> 0!
0x005b7c37: pop        ebp
0x005b7c38: mov        al, dl                 ; al = 0
0x005b7c3a: pop        ebx
0x005b7c3b: add        esp, 0x22c
0x005b7c41: ret                               ; Return to 0x00580e1c with al = 0
```

### 3.3 The CRT Locale / Thread-Data Path in `_stricmp` (`0x0075dd6f`)

When `_stricmp` is called at `0x005b7bd2`:
```x86
0x0075dd6f: push       ebp
0x0075dd70: mov        ebp, esp
0x0075dd72: push       ecx
0x0075dd73: push       ebx
0x0075dd74: call       0x00761e3c             ; _getptd()
```

Inside `_getptd()` (`0x00761e3c`):
```x86
0x00761e3c: push       ebx
0x00761e3d: push       esi
0x00761e3e: call       dword ptr [0x00783114] ; KERNEL32!GetLastError()
0x00761e44: push       dword ptr [0x0081a314] ; __tlsindex
0x00761e4a: mov        ebx, eax               ; Save LastError in ebx
0x00761e4c: call       dword ptr [0x007832b0] ; KERNEL32!TlsGetValue(__tlsindex)
0x00761e52: mov        esi, eax
0x00761e54: test       esi, esi
0x00761e56: jne        0x00761ea1             ; Already allocated!
; (If not allocated, allocates 0x88 bytes, registers with TlsSetValue)
0x00761ea1: push       ebx
0x00761ea2: call       dword ptr [0x007830e4] ; KERNEL32!SetLastError(ebx)
0x00761ea8: mov        eax, esi               ; Return _tiddata*
0x00761eaa: pop        esi
0x00761eab: pop        ebx
0x00761eac: ret
```

Following `_getptd()`, `_stricmp` acquires and releases the CRT locale critical section via `_lock_locale` (`0x0075e3d3`) and `_unlock_locale` (`0x0075e405`), which call `EnterCriticalSection` and `LeaveCriticalSection` (already supported in `startup_oracle.py`).

### 3.4 Downstream Execution: `GameInit` (`0x0057ed20`) and `PlatformInit` (`0x005b76a0`)

After `CheckMultipleInstances` returns 0, `main` jumps to `0x00580e2a` and calls `0x0057ed20`:
```x86
0x0057ed20: push       esi
0x0057ed21: mov        esi, dword ptr [esp + 0xc] ; argv
0x0057ed25: push       edi
0x0057ed26: mov        edi, dword ptr [esp + 0xc] ; argc
0x0057ed2a: push       esi
0x0057ed2b: push       edi
0x0057ed2c: call       0x005b76a0             ; PlatformInit(argc, argv)
```

Inside `PlatformInit` (`0x005b76a0`):
```x86
0x005b76a0: call       0x0043e5b0             ; TimerInit()
0x005b76a5: call       0x00440360             ; MemoryInit()
0x005b76aa: call       0x006fbe2c
0x005b76af: call       0x006f57ea             ; ThreadHandleInit()
0x005b76b4: push       0x64
0x005b76b6: call       0x006f5c91             ; MultimediaTimerInit()
0x005b76bb: add        esp, 4
0x005b76be: call       0x005b7a80
0x005b76c3: call       0x005c0d40
```

`0x0043e5b0` is an unconditional jump to the timer calibrator:
```x86
0x0043e5b0: jmp        0x0043bd90
```

Inside `0x0043bd90` (`TimerCalibrate`):
```x86
0x0043bd90: sub        esp, 8                 ; Allocate 8 bytes for LARGE_INTEGER freq
0x0043bd93: lea        eax, [esp]
0x0043bd97: push       eax                    ; lpFrequency = esp
0x0043bd98: call       dword ptr [0x00783118] ; KERNEL32!QueryPerformanceFrequency(&freq)
; --- NEXT BOUNDARY REACHED HERE ---
0x0043bd9e: fild       qword ptr [esp]        ; Convert freq to ST(0)
0x0043bda2: xor        ecx, ecx
0x0043bda4: mov        dword ptr [0x008284e4], ecx
0x0043bdaa: fdivr      dword ptr [0x00784550] ; ST(0) = 1000.0f / freq (ms per tick)
0x0043bdb0: fst        dword ptr [0x00828028] ; Store scale factor
0x0043bdb6: fmul       dword ptr [0x00786d84] ; Multiply by 2^31 (2147483648.0f)
0x0043bdbc: call       0x0075c600             ; Convert to int64
0x0043bdc1: mov        dword ptr [0x0082802c], eax
0x0043bdc6: mov        dword ptr [0x00828030], edx
0x0043bdcb: add        esp, 8
0x0043bdce: ret
```

### 3.5 The Role of Subroutines `0x0057ed20` and `0x00580890`

1. **`0x0057ed20` (`GameInit`)**:
   - Master subsystem initialization dispatcher.
   - Dispatches in sequence: `PlatformInit` (`0x005b76a0`), audio subsystem (`0x0057cd80`), engine memory pools (`0x00440e60`), filesystem initialization (`0x005736e0`), physics/world init (`0x005ba800`), rendering pipeline (`0x0060c690`), and game state machine (`0x00452ec0`).
   - Sets global initialization status `byte ptr [0x0086534c] = 1`.
   - Jumps to `0x0057fd60`, which flushes queued init events and executes `ret` back to `main` at `0x00580e39`.

2. **`0x00580890` (`CheckSafeMode` / `CheckDebugOption`)**:
   ```x86
   0x00580890: mov        eax, dword ptr [0x008650cc]
   0x00580895: sub        esp, 0xc
   0x00580898: push       ebp
   0x00580899: xor        ebp, ebp
   0x0058089b: cmp        eax, ebp
   0x0058089d: je         0x005808a7
   0x0058089f: cmp        dword ptr [0x00864fe8], ebp
   0x005808a5: jne        0x005808ae
   0x005808a7: xor        al, al
   0x005808a9: pop        ebp
   0x005808aa: add        esp, 0xc
   0x005808ad: ret        
   0x005808ae: mov        al, 1
   0x005808b0: pop        ebp
   0x005808b1: add        esp, 0xc
   0x005808b4: ret
   ```
   - Checks global flags at `0x008650cc` and `0x00864fe8`.
   - Returns boolean `al = 0` under standard execution.
   - Called at `0x00580e3c` **after** `0x0057ed20` completes. Because execution stops inside `0x0057ed20` at `QueryPerformanceFrequency` (`0x0043bd98`), `0x00580890` is **downstream** of the current boundary and is not executed in Stage 0.

---

## 4. Call Stack and Observed Transfer Targets

### 4.1 Guest Call Stack at `QueryPerformanceFrequency` Stop

```
[Frame 0] 0x0075bcc7  (PE Entry Point: CRT Startup)
[Frame 1] 0x00580e10  (main, called at 0x0075be2b)
[Frame 2] 0x0057ed20  (GameInit, called at 0x00580e34)
[Frame 3] 0x005b76a0  (PlatformInit, called at 0x0057ed2c)
[Frame 4] 0x0043e5b0  (TimerInit, called at 0x005b76a0; jmp 0x0043bd90)
[Stop IP] 0x0043bd98  (call dword ptr [0x00783118] -> KERNEL32!QueryPerformanceFrequency)
```

### 4.2 The 12 Newly Observed Transfer Targets in Stage 0

Advancing past `CreateToolhelp32Snapshot` adds exactly 12 unique transfer targets to the observed set (expanding from 1,022 to 1,034):

1. `0x0043e5b0`: High-resolution timer initialization entry (jumps to `0x0043bd90`).
2. `0x0057ed20`: `GameInit` master entry point.
3. `0x005b76a0`: `PlatformInit` entry point.
4. `0x0075d660`: CRT `strrchr` (path separator scan).
5. `0x0075dd6f`: CRT `_stricmp` entry point.
6. `0x0075e1cd`: CRT `___updatetid` (TLS thread-data synchronization).
7. `0x0075e3d3`: CRT `_lock_locale` (locale critical section acquisition).
8. `0x0075e405`: CRT `_unlock_locale` (locale critical section release).
9. `0x00761e3c`: CRT `_getptd` (per-thread data accessor).
10. `0x00767730`: CRT `_stricmp_l` (locale-aware string comparison core).
11. `0x0076e9f0`: Import thunk for `KERNEL32.dll!Process32Next`.
12. `0x0076e9f6`: Import thunk for `KERNEL32.dll!Process32First`.

*(Note: `0x00580e10` [main], `0x005b7b30` [CheckMultipleInstances], and `0x0076e9fc` [CreateToolhelp32Snapshot thunk] were already registered in the baseline 1,022 target set because they were reached prior to the snapshot stop).*

---

## 5. CPU Register State at the New Boundaries

### 5.1 Register State at Stage 0 (`QueryPerformanceFrequency` at `0x0043bd98`)

```
EAX:    0x7fefeef4  (pointer to 8-byte stack frequency buffer [esp])
ECX:    0x00000001
EDX:    0x00000000
EBX:    0x00000000
ESP:    0x7fefeeec  (return address 0x0043bd9e pushed)
EBP:    0x7fefeff8
ESI:    0x20004730
EDI:    0x00000001
EIP:    0xf000007e  (import sentinel for KERNEL32!QueryPerformanceFrequency)
EFLAGS: 0x00000202  (IF set; masked with 0x00200cd5 -> 0x00000200)
```

### 5.2 Register State at Stage -1 (`GetLastError` at `0x00761e3e`)

```
EAX:    0x007a0dfc  ("speed2.exe")
ECX:    0x00000000
EDX:    0x7fefee10
EBX:    0x00000003  (retry counter)
ESP:    0x7fefecb0  (return address 0x00761e44 pushed)
EBP:    0x7fefecc8
ESI:    0xcafe0001  (snapshot handle)
EDI:    0x00000000  (match counter)
EIP:    0xf000007d  (import sentinel for KERNEL32!GetLastError)
EFLAGS: 0x00000246  (ZF, PF set)
```

---

## 6. Implementation Guidance for Next Milestone

To lift and execute through this boundary in the native static recompilation pipeline:

1. **Toolhelp API Contracts (`guest_toolhelp.c`)**:
   - `CreateToolhelp32Snapshot(dwFlags, th32ProcessID)`: Validate flags (`TH32CS_SNAPPROCESS = 0x2`). Return a synthetic process snapshot descriptor handle (e.g. `0xcafe0001`).
   - `Process32First(hSnapshot, lppe)`: Verify `lppe->dwSize >= sizeof(PROCESSENTRY32)`. Fill `th32ProcessID = 100`, `cntThreads = 1`, and `szExeFile = "speed2.exe"`. Return `TRUE` (1).
   - `Process32Next(hSnapshot, lppe)`: Return `FALSE` (0), set `LastError = ERROR_NO_MORE_FILES` (18).
   - `CloseHandle(hObject)`: Validate snapshot handle, release descriptor, return `TRUE` (1).

2. **CRT Error Prerequisites (`guest_teb.c` / `guest_err.c`)**:
   - `GetLastError()`: Read `uint32_t` from `TEB->LastErrorValue` (`offset +0x34`).
   - `SetLastError(dwErrCode)`: Write `dwErrCode` to `TEB->LastErrorValue` (`offset +0x34`).

3. **High-Resolution Timer Contract (`guest_time.c`)**:
   - `QueryPerformanceFrequency(lpFrequency)`: Validate non-null writable pointer. Write fixed frequency `10,000,000` (10 MHz) or `1,000,000` (1 MHz) as a 64-bit integer (`LARGE_INTEGER`). Return `TRUE` (1).
   - Note: The game computes `1000.0f / freq` using x87 float division. A positive non-zero value is mandatory to avoid x87 divide-by-zero exceptions.

4. **Code Generation & Function Budget**:
   - Expand the bounded function generation list from 1,200 to at least 1,250 functions to incorporate the 12 newly observed transfer targets.

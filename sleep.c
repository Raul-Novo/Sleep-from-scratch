
//cl /nologo /TC /std:c17 /W4 /O2 /GS- /Zl /c main.c

//link /nologo /NODEFAULTLIB /ENTRY:entry /SUBSYSTEM:CONSOLE /MACHINE:X64 main.obj /OUT:main.exe

/*
 * main.c
 * Windows 11 x64 — C17 / MSVC
 *
 * Sin CRT, UCRT, VCRuntime, Windows.h ni bibliotecas.
 * Sin importaciones PE.
 */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;
typedef long long i64;

/* Intrinseco de MSVC para acceder a GS. */
unsigned __int64 __readgsqword(unsigned long offset);
#pragma intrinsic(__readgsqword)

/* --------------------------------------------------------- */
/* Comparacion de cadenas sin strcmp()                       */
/* --------------------------------------------------------- */

static int str_eq(const char* a, const char* b) {
  while (*a && *a == *b) {
    ++a;
    ++b;
  }

  return *a == *b;
}

/* --------------------------------------------------------- */
/* Encontrar ntdll.dll mediante el PEB                        */
/* --------------------------------------------------------- */

static void* find_ntdll(void) {
  /* GS:[0x60] = PEB en Windows x64. */
  u8* peb = (u8*)__readgsqword(0x60);

  /* PEB->Ldr */
  u8* ldr = *(u8**)(peb + 0x18);

  /* PEB_LDR_DATA.InMemoryOrderModuleList */
  u8* head = ldr + 0x20;

  for (u8* node = *(u8**)head; node != head; node = *(u8**)node) {
    /* InMemoryOrderLinks tiene offset 0x10. */
    u8* entry = node - 0x10;

    /* BaseDllName: UNICODE_STRING */
    u16 length = *(u16*)(entry + 0x58);
    const u16* name = *(const u16**)(entry + 0x60);

    const char expected[] = "ntdll.dll";

    if (length != 18 || !name)
      continue;

    int match = 1;

    for (u32 i = 0; i < 9; ++i) {
      u16 ch = name[i];

      if (ch >= 'A' && ch <= 'Z')
        ch += 'a' - 'A';

      if (ch != (u16)(u8)expected[i]) {
        match = 0;
        break;
      }
    }

    if (match) {
      /* LDR_DATA_TABLE_ENTRY.DllBase */
      return *(void**)(entry + 0x30);
    }
  }

  return 0;
}

/* --------------------------------------------------------- */
/* Resolver exportaciones PE sin GetProcAddress()            */
/* --------------------------------------------------------- */

static void* find_export(void* module, const char* symbol) {
  const u8* base = (const u8*)module;

  /* DOS signature: MZ */
  if (*(const u16*)base != 0x5A4D)
    return 0;

  /* IMAGE_NT_HEADERS */
  const u8* pe = base + *(const u32*)(base + 0x3C);

  /* PE signature y formato PE32+ */
  if (*(const u32*)pe != 0x00004550 || *(const u16*)(pe + 0x18) != 0x020B)
    return 0;

  /* IMAGE_DIRECTORY_ENTRY_EXPORT */
  u32 export_rva = *(const u32*)(pe + 0x88);
  u32 export_size = *(const u32*)(pe + 0x8C);

  if (!export_rva)
    return 0;

  const u8* exp = base + export_rva;

  /* IMAGE_EXPORT_DIRECTORY */
  u32 count = *(const u32*)(exp + 0x18);

  const u32* functions = (const u32*)(base + *(const u32*)(exp + 0x1C));

  const u32* names = (const u32*)(base + *(const u32*)(exp + 0x20));

  const u16* ordinals = (const u16*)(base + *(const u32*)(exp + 0x24));

  for (u32 i = 0; i < count; ++i) {
    const char* name = (const char*)(base + names[i]);

    if (str_eq(name, symbol)) {
      u32 rva = functions[ordinals[i]];

      if (!rva)
        return 0;

      /* No interpretar forwarders como codigo. */
      if (rva >= export_rva && rva - export_rva < export_size)
        return 0;

      return (void*)(base + rva);
    }
  }

  return 0;
}

/* --------------------------------------------------------- */
/* Firmas de las funciones nativas                           */
/* --------------------------------------------------------- */

typedef long(__stdcall* nt_delay_fn)(u8 alertable, const i64* interval);

typedef long(__stdcall* nt_exit_fn)(void* process, long status);

/* --------------------------------------------------------- */
/* Nuestra implementacion de sleep_ms()                       */
/* --------------------------------------------------------- */

static long sleep_ms(nt_delay_fn delay, u32 ms) {
  /* NtDelayExecution utiliza intervalos de 100 ns. */
  i64 interval = -((i64)ms * 10000);

  return delay(0, &interval);
}

/* --------------------------------------------------------- */
/* Punto de entrada sin CRT                                  */
/* --------------------------------------------------------- */

void entry(void) {
  void* ntdll = find_ntdll();

  if (!ntdll)
    return;

  nt_delay_fn delay = (nt_delay_fn)find_export(ntdll, "NtDelayExecution");

  nt_exit_fn terminate = (nt_exit_fn)find_export(ntdll, "NtTerminateProcess");

  long status = 1;

  if (delay)
    status = sleep_ms(delay, 3000);

  if (terminate)
    terminate((void*)-1, status);
}

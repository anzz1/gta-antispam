// gta-antispam.c

/*
 *  Simple POC example for filtering chat spam in GTAV
 *    for GTAV v1.61 (1.0.2699.0)
 *
 *  - Blocks duplicate messages
 *  - Filters messages containing a blacklisted phrase
 *      Blacklist is loaded from blacklist.txt, one phrase per line, in lowercase
 *
 *  Compile with no CRT, no exceptions, and all "security" nonsense options disabled
 *
 *  MSVC: cl   /MD /Zl /O2 /GS- /Oi /kernel
 *        link /dll /entry:DllMain /nodefaultlib /incremental:no
 *
 */

#include <windows.h>

__forceinline static char* _strrchr(const char* s, char c) {
  char *p = 0;
  while (*s != 0) {
    if (*s == c)
      p = (char*)s;
    s++;
  }
  return p;
}
__forceinline static char* _strcpy(char* dst, const char* src) {
  while (*src != 0) *dst++ = *src++;
  *dst = 0;
  return dst;
}
__forceinline static char* _strncpy(char* dst, const char* src, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    if (*src == 0) break;
    *dst++ = *src++;
  }
  *dst = 0;
  return dst;
}
__forceinline static int _strncmp(const char* s1, const char* s2, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    if (s1[i] > s2[i]) return 1;
    else if (s2[i] > s1[i]) return -1;
    else if (s1[i] == 0) return 0;
  }
  return 0;
}

// s2 should be in lowercase
__forceinline static const char* _stristr(const char* s1, const char* s2) {
  unsigned int i;
  char c;
  while (*s1 != 0) {
    i = 0;
    while (1) {
      if (s2[i] == 0) return s1;
      if (s1[i] == 0) break;
      c = (s1[i]>64 && s1[i]<91) ? (s1[i]+32):s1[i]; // A-Z -> a-z
      if (s2[i] != c) break;
      i++;
    }
    s1++;
  }
  return 0;
}

static char* filter = 0;
static char* filter_end = 0;

__forceinline static char* read_next_line(char* s) {
  while (s < filter_end && *s != 0) {
    s++;
  }
  while (s < filter_end && *s == 0) {
    s++;
  }
  if (s == filter_end) return 0;
  return s;
}

BYTE m_chat_receive_stub[] = {0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0xFF,0x25,0,0,0,0,0,0,0,0,0,0,0,0};
char last_msg[256];

// this function will receive the chat messages
__declspec(noinline) 
__int64 my_chat_receive(void* v1, void* v2, void* v3, const char* msg, char team) {
  if (!msg)
    return 0;

  if (*msg != 0) {
    char* line;

    if (!_strncmp(last_msg, msg, 254)) // if message is duplicate, skip it
      return 0;

    line = filter;
    while (line) {
      if (_stristr(msg, line)) // if message contains phrase from filter list, skip it
        return 0;
      line = read_next_line(line);
    }

    _strncpy(last_msg, msg, 254); // save message to last_msg
  }

  // call the "original" func
  return ((__int64 (*)(void*, void*, void*, const char*, char))(void*)(m_chat_receive_stub))(v1, v2, v3, msg, team);
}

// this is simple and slow, big boys use proper algos like Boyer-Moore-Horspool
__forceinline static BYTE* find_pattern_wildcard(BYTE* src_start, BYTE* src_end, BYTE* pattern_start, BYTE* pattern_end, BYTE wildcard) {
  BYTE *pos,*end,*s1,*p1;
  end = src_end-(pattern_end-pattern_start);
  for (pos = src_start; pos <= end; pos++) {
    s1 = pos-1;
    p1 = pattern_start-1;
    while (*++s1 == *++p1 || *p1 == wildcard) { 
      if (p1 == pattern_end)
        return pos;
    }
  }
  return src_end;
}

__forceinline static BYTE* get_func_ptr() {
  MEMORY_BASIC_INFORMATION memBI;
  BYTE* res;
  ULONG_PTR addr;

  // ptr to func
  // 4D 85 C9 0F 84 ?? ?? ?? ?? 48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 4C 89 48 20
  BYTE search[] = {0x4D,0x85,0xC9,0x0F,0x84,0,0,0,0,0x48,0x8B,0xC4,0x48,0x89,0x58,0x08,0x48,0x89,0x70,0x10,0x48,0x89,0x78,0x18,0x4C,0x89,0x48,0x20};

  addr = (ULONG_PTR)GetModuleHandleA(0); // start search at proc base addr
  memset(&memBI, 0, sizeof(memBI));
  while (VirtualQueryEx((HANDLE)-1, (void*)addr, &memBI, sizeof(memBI))) {
    // skip noncommitted, unreadable and guard pages
    if ((memBI.State & MEM_COMMIT) && (memBI.Protect == ((memBI.Protect & ~(PAGE_NOACCESS | PAGE_GUARD)) | (memBI.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY))))) {
      res = find_pattern_wildcard((BYTE*)memBI.BaseAddress, (BYTE*)memBI.BaseAddress + memBI.RegionSize, search, search + (sizeof(search) / sizeof(search[0])), 0);
      if (res != (BYTE*)memBI.BaseAddress + memBI.RegionSize && res != search)
        return res; // found
    }
    addr = (ULONG_PTR)((ULONG_PTR)memBI.BaseAddress+(ULONG_PTR)memBI.RegionSize);
  }
  return 0;
}

__forceinline static void load_filter(HINSTANCE hInst) {
  char path[MAX_PATH+1];
  char *pos;
  DWORD dwFileSize = 0;
  DWORD dwBytesRead = 0;
  HANDLE hFile;

  if (!GetModuleFileNameA(hInst, path, MAX_PATH)) return;
  path[MAX_PATH] = 0;
  pos = _strrchr(path, '\\');
  if (!pos) return;
  if (pos-path+15 > MAX_PATH) return;
  _strcpy(pos+1, "blacklist.txt");
  hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_ALWAYS, 0, 0);
  if (!hFile || hFile == INVALID_HANDLE_VALUE) return;
  dwFileSize = GetFileSize(hFile, 0);
  if (dwFileSize > 0 && dwFileSize != INVALID_FILE_SIZE) {
    filter = (char*)LocalAlloc(0, dwFileSize); // LMEM_FIXED
    if (filter) {
      if (!ReadFile(hFile, filter, dwFileSize, &dwBytesRead, 0)) {
        LocalFree(filter);
        filter = 0;
      } else {
        filter_end = filter+dwFileSize-1;
        for (pos = filter; pos <= filter_end; pos++) {
          if (*pos == '\r' || *pos == '\n')
            *pos = 0;
        }
        if (dwFileSize > 3 && filter[0] == 0xEF && filter[1] == 0xBB && filter[2] == 0xBF)
          filter += 3; // skip UTF-8 BOM
        while (*filter == 0 && filter < filter_end)
          filter++; // skip leading newlines
      }
    }
  }
  CloseHandle(hFile);
}

DWORD __stdcall mainThread(void* param) {
  DWORD old_rights = 0;
  DWORD new_rights = 0;
  ULONG_PTR* my_jmp_ptr = 0;
  ULONG_PTR* ret_jmp_ptr = 0;
  BYTE* func_ptr = 0;
  MEMORY_BASIC_INFORMATION memBI;
  HINSTANCE hInst;

  hInst = (HINSTANCE)param;
  last_msg[0] = 0;
  load_filter(hInst);

  while (!FindWindowA("grcWindow", "Grand Theft Auto V"))
    Sleep(1000);

  func_ptr = get_func_ptr();
  if (!func_ptr)
    return 0; // didn't find the sig

  my_jmp_ptr = (ULONG_PTR*)((ULONG_PTR)func_ptr+6);
  ret_jmp_ptr = (ULONG_PTR*)((ULONG_PTR)m_chat_receive_stub+13);

  VirtualProtectEx((HANDLE)-1, (void*)ret_jmp_ptr, 8, PAGE_READWRITE, &old_rights);
  *ret_jmp_ptr = (ULONG_PTR)func_ptr+16;
  VirtualProtectEx((HANDLE)-1, (void*)ret_jmp_ptr, 8, PAGE_EXECUTE_READ, &old_rights);

  memset(&memBI, 0, sizeof(memBI));
  VirtualQueryEx((HANDLE)-1, (void*)func_ptr, &memBI, sizeof(memBI));

  old_rights = memBI.Protect;
  new_rights = (old_rights & ~(PAGE_NOACCESS | PAGE_GUARD | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)) | (old_rights & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE));

  if (old_rights != new_rights) {
    if ((new_rights & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE)) == 0)
      new_rights |= (old_rights & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY)) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    VirtualProtectEx((HANDLE)-1, (void*)func_ptr, 14, new_rights, &old_rights);
  }

  func_ptr[0] = 0xFF;
  func_ptr[1] = 0x25;
  func_ptr[2] = 0x00;
  func_ptr[3] = 0x00;
  func_ptr[4] = 0x00;
  func_ptr[5] = 0x00;
  *my_jmp_ptr = (ULONG_PTR)my_chat_receive;

  if (old_rights != new_rights)
    VirtualProtectEx((HANDLE)-1, (void*)func_ptr, 14, old_rights, &new_rights);
  return 0;
}

int __stdcall DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved) {
  if (dwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hInst);
    CreateThread(0, 0, mainThread, (void*)hInst, 0, 0);
  }
  return 1;
}

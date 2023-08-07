#include <pe_parser.h>

BOOL pe_insert_tls(PCHAR pImageBuffer, DWORD dwFunRva)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(pImageBuffer);
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((ULONG_PTR)pImageBuffer + pDos->e_lfanew);

    DWORD dwIDx = pe_get_section_idx32(pImageBuffer, (char*)".data");
    DWORD startRVA = 0;
    pe_extend_section32(pImageBuffer, dwIDx, 0x1000, &startRVA);

    *(int*)(pImageBuffer + startRVA + 0x8) = startRVA + 0x10 + pNts->OptionalHeader.ImageBase;
    *(int*)(pImageBuffer + startRVA + 0xC) = dwFunRva + pNts->OptionalHeader.ImageBase;

    // 修改目录表
    int* pTlsDir = (int*)&(pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    *pTlsDir = startRVA;
    *(pTlsDir+1) = 0x18;
}
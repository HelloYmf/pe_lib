#include <pe_parser.h>

PCHAR pe_insert_tls(PCHAR pImageBuffer, DWORD dwFunRva)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(pImageBuffer);
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((ULONG_PTR)pImageBuffer + pDos->e_lfanew);

    DWORD dwIDx = pe_get_section_idx32(pImageBuffer, (char*)".idata");
    DWORD startRVA = 0;
    PCHAR pNewImageBuffer = pe_extend_section32(pImageBuffer, dwIDx, 0x1000, &startRVA);
    if(!pNewImageBuffer)
        return NULL;

    PIMAGE_DOS_HEADER pNewDos = (PIMAGE_DOS_HEADER)(pNewImageBuffer);
	PIMAGE_NT_HEADERS pNewNts = (PIMAGE_NT_HEADERS)((ULONG_PTR)pNewImageBuffer + pNewDos->e_lfanew);

    *(int*)(pNewImageBuffer + startRVA + 0x8) = startRVA + 0x10 + pNewNts->OptionalHeader.ImageBase;
    *(int*)(pNewImageBuffer + startRVA + 0xC) = startRVA + 0x20 + pNewNts->OptionalHeader.ImageBase;
    *(int*)(pNewImageBuffer + startRVA + 0x20) = dwFunRva + pNewNts->OptionalHeader.ImageBase;

    // 修改目录表
    int* pTlsDir = (int*)&(pNewNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    *pTlsDir = startRVA;
    *(pTlsDir+1) = 0x18;
    return pNewImageBuffer;
}
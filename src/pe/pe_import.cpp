#include <Windows.h>
#include <winnt.h>

#include <pe_parser.h>

typedef struct _NAME_STRUCT
{
    short hint;
    std::string name;
}NAME_STRUCT;

typedef struct _MY_IAT_RVA
{
    int oldrva;
    int newrva;
}MY_IAT_RVA;

DWORD pos_old_import(PIMAGE_SECTION_HEADER pSecs, DWORD dwSecNum, ULONG_PTR ulImpBase)
{
    for(DWORD i = 0; i < dwSecNum; i++)
    {
        if(ulImpBase >= pSecs[i].VirtualAddress && ulImpBase <= pSecs[i].VirtualAddress + pSecs[i].Misc.VirtualSize)
            return i;
    }
    return -1;
}

VOID parse_import_table(
        PCHAR pImageBuffer,
        PIMAGE_IMPORT_DESCRIPTOR pImport, 
        std::vector<IMAGE_IMPORT_DESCRIPTOR>* vImportTable,
        std::vector<std::string>* vImportDLLName,
        std::vector<std::vector<NAME_STRUCT>>* vImportFunName,
        std::vector<MY_IAT_RVA>* vIatRvas
        )
{
    while(pImport->FirstThunk)
    {
        // 导入表结构
        IMAGE_IMPORT_DESCRIPTOR tmpDesImp;
        memcpy(&tmpDesImp, pImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        vImportTable->push_back(tmpDesImp);
        // 导入模块名字
        char* dname = pImageBuffer + pImport->Name;
        std::string sTmpDLLName = dname;
        vImportDLLName->push_back(sTmpDLLName);
        // 导入模块的函数
        std::vector<NAME_STRUCT> sTmpNames;
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pImageBuffer + pImport->FirstThunk);
        while(pThunk->u1.Function)
        {
            // 收集iat自身所在的rva
            MY_IAT_RVA myRva;
            myRva.oldrva = (char*)pThunk - pImageBuffer;
            myRva.newrva = 0;
            vIatRvas->push_back(myRva);
            PIMAGE_IMPORT_BY_NAME pImpFunName = (PIMAGE_IMPORT_BY_NAME)(pImageBuffer + pThunk->u1.AddressOfData);
            char* fname = pImpFunName->Name;
            NAME_STRUCT sTmpFun;
            sTmpFun.hint = pImpFunName->Hint;
            sTmpFun.name = fname;
            sTmpNames.push_back(sTmpFun);
            pThunk++;
        }
        vImportFunName->push_back(sTmpNames);
        pImport++;
    }
}

VOID clean_import_table(PCHAR pImageBuffer, PIMAGE_IMPORT_DESCRIPTOR pImport, DWORD dwVal)
{
    while(pImport->FirstThunk)
    {   
        PIMAGE_THUNK_DATA pIatThunk = (PIMAGE_THUNK_DATA)(pImageBuffer + pImport->FirstThunk);
        // 清除IAT表
        while(pIatThunk->u1.Function)
        {
            PIMAGE_IMPORT_BY_NAME pImpFunName = (PIMAGE_IMPORT_BY_NAME)(pImageBuffer + pIatThunk->u1.AddressOfData);
            char* fname = pImpFunName->Name;
            // 清除FUN_NAME_DATA结构
            memset(fname, dwVal, strlen(fname));
            memset(pIatThunk, dwVal, sizeof(IMAGE_THUNK_DATA));
            pIatThunk++;
        }

        // 清除IAT结构
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pImageBuffer + pImport->FirstThunk);
        while(pThunk->u1.Function)
        {
            memset(pThunk, dwVal, sizeof(IMAGE_THUNK_DATA));
            pThunk++;
        }

        // 清除模块名字
        char* dname = pImageBuffer + pImport->Name;
        memset(dname, dwVal, strlen(dname));

         // 清除导入表结构
        memset(pImport, dwVal, sizeof(IMAGE_IMPORT_DESCRIPTOR));

        pImport++;
    }
}

PCHAR pe_add_import_entry(PCHAR pOldImageBuffer, PCHAR pDLLName, std::vector<std::string> pFunNames)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(pOldImageBuffer);
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((ULONG_PTR)pOldImageBuffer + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSecs = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&(pNts->OptionalHeader) + pNts->FileHeader.SizeOfOptionalHeader);
    PIMAGE_DATA_DIRECTORY pImportDir = (PIMAGE_DATA_DIRECTORY) & (pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pOldImageBuffer + pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // 描述结构
    std::vector<IMAGE_IMPORT_DESCRIPTOR> vImportTable;
    // DLL name
    std::vector<std::string> vImportDLLName;
    // Func name
    std::vector<std::vector<NAME_STRUCT>> vImportFunName;
    // Thunk
    std::vector<std::vector<int>> vThunks;
    // iat自身的rvas(old-new映射)
    std::vector<MY_IAT_RVA> vIatRvas;

    // 解析导入表
    parse_import_table(pOldImageBuffer, pImp, &vImportTable, &vImportDLLName, &vImportFunName, &vIatRvas);
    printf("[+]import: parse original import table success\r\n");
    printf("[+]import: collected %d iats rva success\r\n", vIatRvas.size());

    // 检查重复添加
    for(auto i = vImportDLLName.begin(); i < vImportDLLName.end(); i++)
    {
        if(!strcasecmp(i->c_str(), pDLLName))
        {
            printf("[-]import: import dll already exits\r\n");
            return pOldImageBuffer;
        }
    }

    size_t sDllNameTotalize = 0;
    for(auto i = vImportDLLName.begin(); i != vImportDLLName.end(); i++)
    {
        sDllNameTotalize += (i->length() + 1);
    }

    size_t sFunNameTotalSize = 0;
    int iFunNum = 0;
    for(auto i = vImportFunName.begin(); i != vImportFunName.end(); i++)
    {
        for(auto j = i->begin(); j != i->end(); j++)
        {
            sFunNameTotalSize += (j->name.length() + 1);
            iFunNum++;
        }
    }
    
    size_t sOrdImportSize = sizeof(IMAGE_IMPORT_DESCRIPTOR) * vImportTable.size()       // 导入表描述结构
                        + sizeof(IMAGE_THUNK_DATA) * iFunNum * 2                        // Thunks和IATs
                        + sDllNameTotalize + sFunNameTotalSize;                         // Names

    size_t sAddFunNameTotalSize = 0;
    for(auto i = pFunNames.begin(); i != pFunNames.end(); i++)
    {
        sAddFunNameTotalSize += (i->length() + 1);
    }

    // 获取当前导入表所在的节区，用于扩展
    DWORD dwCurSecIdx = pos_old_import(pSecs, pNts->FileHeader.NumberOfSections, pImportDir->VirtualAddress);
    // 扩展大小 = 原始导入表大小 + 新增导入项(0x14) + 新增导入DLL名字(strlen(pDLLName) + 新增导入函数名字 + IAT项(0x4))
    size_t sExpSize = sOrdImportSize + sizeof(IMAGE_IMPORT_DESCRIPTOR) + (strlen(pDLLName) + 1) + sAddFunNameTotalSize + pFunNames.size() * 4;
    sExpSize += pSecs[dwCurSecIdx].Misc.VirtualSize > pSecs[dwCurSecIdx].SizeOfRawData ? pSecs[dwCurSecIdx].Misc.VirtualSize - pSecs[dwCurSecIdx].SizeOfRawData : 0;
    // 扩展节区
    DWORD pExtendStartRva = NULL;
    char* pNewImageBuffer = pe_extend_section32(pOldImageBuffer, dwCurSecIdx, sExpSize, &pExtendStartRva);
    if(!pNewImageBuffer)
        return NULL;
    printf("[+]import: expand %d sectin %x bytes success\r\n", (int)dwCurSecIdx, sExpSize);

    // 导入表构建起始位置
    char* pStartWrite = pNewImageBuffer + pSecs[dwCurSecIdx].VirtualAddress + pSecs[dwCurSecIdx].Misc.VirtualSize;
    char* pCurWrite = pStartWrite;

    IMAGE_IMPORT_DESCRIPTOR newImport;
    newImport.OriginalFirstThunk = 0;
    newImport.FirstThunk = 0;
    newImport.ForwarderChain = 0;
    newImport.TimeDateStamp = 0;
    newImport.Name = 0;

    // 写入DLL名字
    for(int i = 0; i < vImportDLLName.size(); i++)
    {
        // 更新dll name rva
        vImportTable[i].Name = pCurWrite - pNewImageBuffer;
        memcpy(pCurWrite, vImportDLLName[i].c_str(), vImportDLLName[i].length() + 1);
        pCurWrite += (vImportDLLName[i].length() + 1);
        printf("    [*]import: writing original dll name %s\r\n", vImportDLLName[i].c_str());
    }
    // 写入新增加的DLL名字
    newImport.Name = pCurWrite - pNewImageBuffer;
    memcpy(pCurWrite, pDLLName, strlen(pDLLName) + 1);
    pCurWrite += (strlen(pDLLName) + 1);
    printf("    [*]import: writing new dll name %s\r\n", pDLLName);
    printf("[+]import: write %d new dll name success\r\n", vImportDLLName.size() + 1);

    // 写入函数名字
    for(int i = 0; i < vImportFunName.size(); i++)
    {
        std::vector<int> vTmp;
        for(int j = 0; j < vImportFunName[i].size(); j++)
        {
            vTmp.push_back(pCurWrite - pNewImageBuffer);
            *(PWORD)pCurWrite = vImportFunName[i][j].hint;                  // Hit字段
            pCurWrite += 2;
            memcpy(pCurWrite, vImportFunName[i][j].name.c_str(), vImportFunName[i][j].name.length() + 1);
            pCurWrite += (vImportFunName[i][j].name.length() + 1);
        }
        vThunks.push_back(vTmp);
    }
    // 写入新增加的函数名字
    std::vector<int> vAddFuns;
    for(int i = 0; i < pFunNames.size(); i++)
    {
        vAddFuns.push_back(pCurWrite - pNewImageBuffer);
        *(PWORD)pCurWrite = 0;                  // Hit字段
        pCurWrite += 2;
        memcpy(pCurWrite, pFunNames[i].c_str(), pFunNames[i].length() + 1);
        pCurWrite += (pFunNames[i].length() + 1);
        printf("    [*]import: writing new function name %s\r\n", pFunNames[i].c_str());
    }
    vThunks.push_back(vAddFuns);
    printf("[+]import: write %d new function name success\r\n", pFunNames.size());

    vImportTable.push_back(newImport);
    // 写入Thunks
    for(int i = 0; i < vThunks.size(); i++)
    {
        vImportTable[i].OriginalFirstThunk = (pCurWrite - pNewImageBuffer);
        for(int j = 0; j < vThunks[i].size(); j++)
        {
            *(PDWORD)pCurWrite = vThunks[i][j];
            pCurWrite += 4;
        }
        *(PDWORD)pCurWrite = 0;
        pCurWrite += 4;
    }
    // 写入结束标识
    *(PDWORD)pCurWrite = 0;
    pCurWrite += 4;
    printf("[+]import: write thunks success\r\n");

    // 写入Iats
    int curI = 0;
    for(int i = 0; i < vThunks.size(); i++)
    {
        vImportTable[i].FirstThunk = (pCurWrite - pNewImageBuffer);
        for(int j = 0; j < vThunks[i].size(); j++)
        {
            vIatRvas[curI++].newrva = (pCurWrite - pNewImageBuffer);
            *(PDWORD)pCurWrite = vThunks[i][j];
            pCurWrite += 4;
        }
        *(PDWORD)pCurWrite = 0;
        pCurWrite += 4;
    }
    *(PDWORD)pCurWrite = 0;
    pCurWrite += 4;
    printf("[+]import: write iats success\r\n");

    
    PIMAGE_DOS_HEADER pNewDos = (PIMAGE_DOS_HEADER)(pNewImageBuffer);
	PIMAGE_NT_HEADERS pNewNts = (PIMAGE_NT_HEADERS)((ULONG_PTR)pNewImageBuffer + pDos->e_lfanew);

    // 清除旧的导入表
    PIMAGE_IMPORT_DESCRIPTOR pNewOldImp = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pNewImageBuffer + pNewNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    clean_import_table(pNewImageBuffer,pNewOldImp,0x90);
    printf("[+]import: clean import table success\r\n");

    // 更新VirtualAddress
    PIMAGE_DATA_DIRECTORY pNewImportDir = (PIMAGE_DATA_DIRECTORY) & (pNewNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    pNewImportDir->VirtualAddress = (DWORD)(pCurWrite - pNewImageBuffer);
    pNewImportDir->Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    printf("[+]import: update import directory success\r\n");

    // 写入导入描述结构
    for(int i = 0; i < vImportTable.size(); i++)
    {
        *(PIMAGE_IMPORT_DESCRIPTOR)pCurWrite = vImportTable[i];
        pCurWrite += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    // 写入结束标识
    memset(pCurWrite, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    printf("[+]import: write %d import descriptor success\r\n", vImportTable.size());

    // 修复重定位表
    if(pNewNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
    {
        PIMAGE_BASE_RELOCATION pBaseRelocal = (PIMAGE_BASE_RELOCATION)( pNewImageBuffer + pNewNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while ( pBaseRelocal->VirtualAddress && pBaseRelocal->SizeOfBlock)
        {
            typedef struct  
            {
                unsigned short Offset:12;
                unsigned short Type:4;
            }WORD_RELOCAL, *PWORD_RELOCAL;

            PWORD_RELOCAL pRelocalWord = (PWORD_RELOCAL)((char*)pBaseRelocal + sizeof(IMAGE_BASE_RELOCATION));
            DWORD dwBlockSize = pBaseRelocal->SizeOfBlock / sizeof(WORD_RELOCAL);
            for ( int i = 0; i < dwBlockSize && pRelocalWord->Type == 0x3; i++)
            {
                char* reloc_addr = pNewImageBuffer + pBaseRelocal->VirtualAddress + pRelocalWord->Offset;
                ULONG_PTR cmp_rva = (*(ULONG_PTR*)reloc_addr) - pNewNts->OptionalHeader.ImageBase;

                // 比较rva是否在旧的iat范围内
                for(int j = 0; j < vIatRvas.size(); j++)
                {
                    if(vIatRvas[j].oldrva == cmp_rva)
                    {
                        (*(ULONG_PTR*)reloc_addr) = pNewNts->OptionalHeader.ImageBase + vIatRvas[j].newrva;
                    }
                }

                pRelocalWord++;
            }
            pBaseRelocal = (PIMAGE_BASE_RELOCATION)( (char*)pBaseRelocal + pBaseRelocal->SizeOfBlock);
        }
    }
    printf("[+]import: write apis call addr\r\n");

    // 修复DIR->IAT目录
    PIMAGE_DATA_DIRECTORY pNewIATDir = (PIMAGE_DATA_DIRECTORY) & (pNewNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]);
    pNewIATDir->VirtualAddress = vIatRvas[0].newrva;
    pNewIATDir->Size += (pFunNames.size() * 4);
    printf("[+]import: update iat directory success\r\n");

    return pNewImageBuffer;
}
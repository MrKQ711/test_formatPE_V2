#include <stdio.h>
#include <windows.h>
#include <time.h>
#include <tchar.h>
#include <wctype.h>

void Notification()
{
	printf("\nBuild Successful\n");
}
int main(int argc, char **argv)
{

	int i = 0;
	HANDLE hMapObject, hFile;		  // File Mapping Object
	LPVOID lpBase;					  // Pointer to the base memory of mapped file
	PIMAGE_DOS_HEADER dosHeader;	  // Pointer to DOS Header
	PIMAGE_NT_HEADERS ntHeader;		  // Pointer to NT Header
	IMAGE_FILE_HEADER header;		  // Pointer to image file header of NT Header
	IMAGE_OPTIONAL_HEADER opHeader;	  // Optional Header of PE files present in NT Header structure
	PIMAGE_SECTION_HEADER pSecHeader; // Section Header or Section Table Header
	if (argc > 1)
	{

		// Open the Exe File
		hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("\nERROR : Could not open the file specified\n");
		};

		// Mapping Given EXE file to Memory
		hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		lpBase = MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);

		// Get the DOS Header Base
		dosHeader = (PIMAGE_DOS_HEADER)lpBase; // 0x04000000 is default base address of the EXE file

		// Get the Base of NT Header(PE Header)
		ntHeader = (PIMAGE_NT_HEADERS)((DWORD)(dosHeader) + (dosHeader->e_lfanew));
		// Identify for valid PE file

		if (ntHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			printf("\n\nDumping PE Optional Header Info....\n-----------------------------------");
			// Info about Optional Header
			opHeader = ntHeader->OptionalHeader;
			printf("\n\nInfo of optional Header\n-----------------------");
			printf("\n%-36s%#x", "Address of Entry Point ", opHeader.AddressOfEntryPoint);
			printf("\n%-36s%#x", "Check Sum ", opHeader.CheckSum);
			printf("\n%-36s%#x", "Base Address of the Image ", opHeader.ImageBase);
			printf("\n%-36s%#x", "File Alignment ", opHeader.FileAlignment);
			printf("\n%-36s%#x", "Size Of Image ", opHeader.SizeOfImage);
			printf("\n\nDumping Sections Header Info....\n--------------------------------");

			// Retrive a pointer to First Section Header(or Section Table Entry)

			for (pSecHeader = IMAGE_FIRST_SECTION(ntHeader), i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, pSecHeader++)
			{
				printf("\n\nSection Info (%d of %d)", i + 1, ntHeader->FileHeader.NumberOfSections);
				printf("\n---------------------");
				printf("\n%-36s%s", "Section Header name ", pSecHeader->Name);
				printf("\n%-36s%s", "Characteristics ", "Contains ");
				if ((pSecHeader->Characteristics & 0x20) == 0x20)
					printf("executable code, ");
				if ((pSecHeader->Characteristics & 0x40) == 0x40)
					printf("initialized data, ");
				if ((pSecHeader->Characteristics & 0x80) == 0x80)
					printf("uninitialized data, ");
				if ((pSecHeader->Characteristics & 0x80) == 0x80)
					printf("uninitialized data, ");
				if ((pSecHeader->Characteristics & 0x200) == 0x200)
					printf("comments and linker commands, ");
				if ((pSecHeader->Characteristics & 0x10000000) == 0x10000000)
					printf("shareable data(via DLLs), ");
				if ((pSecHeader->Characteristics & 0x40000000) == 0x40000000)
					printf("Readable, ");
				if ((pSecHeader->Characteristics & 0x80000000) == 0x80000000)
					printf("Writable, ");
				printf("\n%-36s%#x", "Raw address ", pSecHeader->PointerToRawData);
				printf("\n%-36s%#x", "Raw size ", pSecHeader->SizeOfRawData);
				printf("\n%-36s%#x", "Virtual Address(RVA) ", pSecHeader->VirtualAddress);
				printf("\n%-36s%#x", "ActualSize ", pSecHeader->Misc.VirtualSize);
			}

			// list all the imported functions
			printf("\n\nDumping Imported Functions Info....\n-----------------------------------");
			PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			while (pImportDesc->Name)
			{
				printf("\n\nImported Functions from %s", (char *)((DWORD)lpBase + pImportDesc->Name));
				printf("\n-----------------------------------");
				PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD)lpBase + pImportDesc->FirstThunk);
				while (pThunk->u1.Function)
				{
					printf("\n%-36s%s", "Imported Function ", (char *)((DWORD)lpBase + ((PIMAGE_IMPORT_BY_NAME)pThunk->u1.AddressOfData)->Name));
					pThunk++;
				}
				pImportDesc++;
			}

			// list all the exported functions
			printf("\n\nDumping Exported Functions Info....\n-----------------------------------");
			PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpBase + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			DWORD *pAddressOfFunctions = (DWORD *)((DWORD)lpBase + pExportDir->AddressOfFunctions);
			DWORD *pAddressOfNames = (DWORD *)((DWORD)lpBase + pExportDir->AddressOfNames);
			WORD *pAddressOfNameOrdinals = (WORD *)((DWORD)lpBase + pExportDir->AddressOfNameOrdinals);
			for (i = 0; i < pExportDir->NumberOfNames; i++)
			{
				printf("\n%-36s%s", "Exported Function ", (char *)((DWORD)lpBase + pAddressOfNames[i]));
			}
			

			

			printf("\n===============================================================================\n");
		}
		else
			goto end;

	end:
		// UnMaping
		UnmapViewOfFile(lpBase);
		CloseHandle(hMapObject);
	}
	else
		Notification();
}

// Way to run the program
// PEFormat.exe <EXE file name>

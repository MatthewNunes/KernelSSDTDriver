/*
* File handling process
*/
//#define UNICODE
//#define _UNICODE
//#include <ntddk.h>
#include <ntstrsafe.h>
#define  BUFFER_SIZE 500

NTSTATUS ntstatus;

extern UINT32 globalSetter;
extern UINT32 counter;
/*
typedef enum {ZWCLOSEARRAY, ZWOPENARRAY} method_array;
typedef struct WriteMe{
	PUNICODE_STRING stringToLog;
	PUNICODE_STRING filename;
	method_array method;
} WriteBlock, *PWriteBlock;

UINT32 CloseCounter = 0;
*/
NTSTATUS driverCreateFile(PUNICODE_STRING filename) {
	HANDLE   handle;
	IO_STATUS_BLOCK ioStatusBlock;
	OBJECT_ATTRIBUTES  objAttr;
	
	InitializeObjectAttributes(&objAttr, filename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    // Do not try to perform any file operations at higher IRQL levels.
    // Instead, you may use a work item or a system worker thread to perform file operations.

    if(KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE; 
    ntstatus = ZwCreateFile(&handle,
                            GENERIC_WRITE,
                            &objAttr, &ioStatusBlock, NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            0,
                            FILE_OVERWRITE_IF, 
                            FILE_SYNCHRONOUS_IO_ALERT,
                            NULL, 0);
	ZwClose(handle);
	return ntstatus;
}
/*
NTSTATUS driverLogWrite(PUNICODE_STRING stringToLog, PUNICODE_STRING filename, method_array method) {
	PWCHAR processString;
	PWCHAR fullString;
	
	UNICODE_STRING uProcess = {0};
	UNICODE_STRING uFullString = {0};
	
	uProcess.MaximumLength = 150 * sizeof(WCHAR);
	uFullString.MaximumLength = 950 * sizeof(WCHAR);
	
	uProcess.Length = 0;
	uFullString.Length = 0;
	
	processString = (PWCHAR)ExAllocatePoolWithTag(PagedPool, sizeof(WCHAR) * 150, 'icpr');
	fullString = (PWCHAR)ExAllocatePoolWithTag(PagedPool, sizeof(WCHAR) * 950, 'icfs');
	
	PWriteBlock block = (PWriteBlock)ExAllocatePoolWithTag(PagedPool, sizeof(WriteBlock), 'icfs');
	RtlUnicodeStringCopy
}
*/
NTSTATUS driverWriteFile(PUNICODE_STRING stringToLog, PUNICODE_STRING filename) {
	HANDLE   handle;
	OBJECT_ATTRIBUTES  objAttr;
	IO_STATUS_BLOCK ioStatusBlock;
	ANSI_STRING ansiString;
	char buffer[BUFFER_SIZE];
	LARGE_INTEGER ByteOffset;
	//DbgPrint("DriverWriteFile\n");
	size_t cb;
	ntstatus = RtlUnicodeStringToAnsiString(&ansiString, stringToLog, TRUE);
	
	if(KeGetCurrentIrql() != PASSIVE_LEVEL) {
		DbgPrint("Incorrect IRQL");
        return STATUS_INVALID_DEVICE_STATE; 
	}
	//DbgPrint("File: %wZ String: %wZ \r\n", filename, stringToLog);
    ByteOffset.HighPart = -1;
    ByteOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;
	if (NT_SUCCESS(ntstatus)) {
		//DbgPrint("DriverWriteFile called with: %s", ansiString.Buffer);
		InitializeObjectAttributes(&objAttr, filename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		ntstatus = ZwOpenFile(&handle, GENERIC_WRITE, &objAttr, &ioStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, 1234567L);

		if (NT_SUCCESS(ntstatus)) {
			ntstatus = RtlStringCbPrintfA(buffer, sizeof(buffer), ansiString.Buffer, 0x0);
			if (NT_SUCCESS(ntstatus)) {
				ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb);
				if (NT_SUCCESS(ntstatus)) {
					ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, buffer, cb, &ByteOffset, NULL);
					if (ntstatus == STATUS_SUCCESS) {
						//DbgPrint("I write in %wZ \r\n", &filename);
					}
					else {
						DbgPrint("Error Writing %wZ to %wZ! %x \r\n", stringToLog, filename, ntstatus);
					}
					
				}
				
			}
			ZwClose(handle);
		}
		else {
			DbgPrint("Error opening file: %wZ NtStatus: %x \r\n", filename, ntstatus);
		}
	}
	
	return ntstatus;
}
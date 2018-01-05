//#include <wdm.h>
#define UNICODE
#define _UNICODE
#include <ntddk.h>
#include <ntstrsafe.h>
//#include "filehandling.c"

typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef WORD LANGID;
typedef PVOID PLANGID;
typedef float FLOAT;
typedef BYTE* PBYTE;
typedef unsigned long ULONG;
typedef ULONG *PULONG;
#ifdef _UNICODE
typedef wchar_t TCHAR;
#else
typedef char TCHAR;
#endif

/* Function Prototypes */

NTSTATUS MyDriver_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID MyDriver_Unload(PDRIVER_OBJECT  DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath);
void unHookSSDT(BYTE* apiCall, BYTE* oldAddr, DWORD* callTable);
void unHookSSDTWithIndex(DWORD apiCall, BYTE* oldAddr, DWORD* callTable);
NTSTATUS getPIDByThreadHandle(HANDLE hThread, PUNICODE_STRING ProcessImageName);
NTSTATUS getFilenameByHandle(HANDLE hFile, PUNICODE_STRING FileName);
DWORD getSSDTIndex(BYTE* address);

//Undocumented structures!

typedef enum _SYSDBG_COMMAND {
    SysDbgQueryModuleInformation=1,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall,
    SysDbgClearSpecialCalls,
    SysDbgQuerySpecialCalls
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef struct _PORT_MESSAGE {
   USHORT      DataSize;
   USHORT      MessageSize;
   USHORT      MessageType;
   USHORT      VirtualRangesOffset;
   CLIENT_ID   ClientId;
   ULONG       MessageId;
   ULONG       SectionSize;
   // UCHAR Data[];
}PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _PORT_SECTION_WRITE {
   ULONG Length;
   HANDLE hSection;
   ULONG SectionOffset;
   ULONG ViewSize;
   PVOID ViewBase;
   PVOID TargetViewBase;
} PORT_SECTION_WRITE, *PPORT_SECTION_WRITE;

typedef struct _PORT_SECTION_READ {
   ULONG Length;
   ULONG ViewSize;
   ULONG ViewBase;
} PORT_SECTION_READ, *PPORT_SECTION_READ;

/* The structure representing the System Service Table. */
typedef struct SystemServiceTable { 
        UINT32* 	ServiceTable; 
        UINT32* 	CounterTable; 
        UINT32		ServiceLimit; 
        UINT32*     ArgumentTable; 
} SST;



typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

#define SystemProcessInformation 5
#define SystemProcessorPerformanceInformation 8

typedef struct _SYSTEM_PROCESS_INFO {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	ULONG Reserved[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFO {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER Reserved1[2];
	ULONG Reserved2;
}SYSTEM_PROCESSOR_PERFORMANCE_INFO, *PSYSTEM_PROCESSOR_PERFORMANCE_INFO;


typedef struct _THREAD_BASIC_INFORMATION {
  NTSTATUS                ExitStatus;
  PVOID                   TebBaseAddress;
  CLIENT_ID               ClientId;
  ULONG 	              AffinityMask;
  ULONG		              Priority;
  ULONG					  BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _USER_STACK {
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef enum _TOKEN_INFORMATION_CLASS { 
  TokenUser                             = 1,
  TokenGroups,
  TokenPrivileges,
  TokenOwner,
  TokenPrimaryGroup,
  TokenDefaultDacl,
  TokenSource,
  TokenType,
  TokenImpersonationLevel,
  TokenStatistics,
  TokenRestrictedSids,
  TokenSessionId,
  TokenGroupsAndPrivileges,
  TokenSessionReference,
  TokenSandBoxInert,
  TokenAuditPolicy,
  TokenOrigin,
  TokenElevationType,
  TokenLinkedToken,
  TokenElevation,
  TokenHasRestrictions,
  TokenAccessInformation,
  TokenVirtualizationAllowed,
  TokenVirtualizationEnabled,
  TokenIntegrityLevel,
  TokenUIAccess,
  TokenMandatoryPolicy,
  TokenLogonSid,
  TokenIsAppContainer,
  TokenCapabilities,
  TokenAppContainerSid,
  TokenAppContainerNumber,
  TokenUserClaimAttributes,
  TokenDeviceClaimAttributes,
  TokenRestrictedUserClaimAttributes,
  TokenRestrictedDeviceClaimAttributes,
  TokenDeviceGroups,
  TokenRestrictedDeviceGroups,
  TokenSecurityAttributes,
  TokenIsRestricted,
  MaxTokenInfoClass
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS { 
  MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _SID_IDENTIFIER_AUTHORITY
{
	UCHAR Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID
{
    UCHAR Revision;
    UCHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    ULONG SubAuthority[1];
} SID;

typedef struct _FILE_USER_QUOTA_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER QuotaUsed;
    LARGE_INTEGER QuotaThreshold;
    LARGE_INTEGER QuotaLimit;
    SID Sid[1];
} FILE_USER_QUOTA_INFORMATION, *PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION {
  ULONG NextEntryOffset;
  UCHAR EaNameLength;
  CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    SID Sid[1];
} FILE_QUOTA_LIST_INFORMATION, *PFILE_QUOTA_LIST_INFORMATION;

typedef struct _FILE_NOTIFY_INFORMATION {
  DWORD NextEntryOffset;
  DWORD Action;
  DWORD FileNameLength;
  WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION, *PFILE_NOTIFY_INFORMATION;

typedef enum _PORT_INFORMATION_CLASS {
    PortNoInformation
} PORT_INFORMATION_CLASS, *PPORT_INFORMATION_CLASS;


typedef struct _PORT_VIEW {
    ULONG Length;
    HANDLE SectionHandle;
    ULONG SectionOffset;
    ULONG ViewSize;
    PVOID ViewBase;
    PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW {
    ULONG Length;
    ULONG ViewSize;
    PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef enum _DEBUG_CONTROL_CODE {
  DebugGetTraceInformation = 1,
	DebugSetInternalBreakpoint,
	DebugSetSpecialCall,
	DebugClearSpecialCalls,
	DebugQuerySpecialCalls,
	DebugDbgBreakPoint,
	DebugMaximum
} DEBUG_CONTROL_CODE;

typedef enum _OBJECT_INFORMATION_CLASS { 
  ObjectBasicInformation  = 0,
  ObjectTypeInformation   = 2
} OBJECT_INFORMATION_CLASS;

typedef enum _SECTION_INFORMATION_CLASS {
  SectionBasicInformation = 0,
  SectionImageInformation
} SECTION_INFORMATION_CLASS;

typedef enum _JOBOBJECTINFOCLASS {
	JobObjectBasicAccountingInformation = 1,
	JobObjectBasicLimitInformation,
	JobObjectBasicProcessIdList,
	JobObjectBasicUIRestrictions,
	JobObjectSecurityLimitInformation,
	JobObjectEndOfJobTimeInformation,
	JobObjectAssociateCompletionPortInformation,
	JobObjectBasicAndIoAccountingInformation,
	JobObjectExtendedLimitInformation,
	MaxJobObjectInfoClass
} JOBOBJECTINFOCLASS;

#define TOKEN_SOURCE_LENGTH 8

typedef struct _SID_AND_ATTRIBUTES {
  PSID  Sid;
  DWORD Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

typedef enum _TOKEN_TYPE
{
    TokenPrimary = 1,
    TokenImpersonation = 2
} TOKEN_TYPE;

typedef struct _TOKEN_GROUPS {
  DWORD              GroupCount;
  SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
} TOKEN_GROUPS, *PTOKEN_GROUPS;

typedef struct _TOKEN_PRIVILEGES {
  DWORD               PrivilegeCount;
  LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

typedef struct _TOKEN_USER {
  SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

typedef struct _TOKEN_OWNER {
  PSID Owner;
} TOKEN_OWNER, *PTOKEN_OWNER;

typedef struct _TOKEN_PRIMARY_GROUP {
  PSID PrimaryGroup;
} TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;

typedef struct _TOKEN_DEFAULT_DACL {
  PACL DefaultDacl;
} TOKEN_DEFAULT_DACL, *PTOKEN_DEFAULT_DACL;

typedef struct _TOKEN_SOURCE {
  CHAR SourceName[TOKEN_SOURCE_LENGTH];
  LUID SourceIdentifier;
} TOKEN_SOURCE, *PTOKEN_SOURCE;

typedef enum _TIMER_INFORMATION_CLASS {
	TimerBasicInformation
} TIMER_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS {
	EventBasicInformation
} EVENT_INFORMATION_CLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS {
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS {
	MutantBasicInformation
} MUTANT_INFORMATION_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS {
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

 typedef struct _OBJECT_TYPE_LIST {
   WORD Level;
   ACCESS_MASK Remaining;
   GUID* ObjectType;
 } OBJECT_TYPE_LIST, *POBJECT_TYPE_LIST;

 typedef enum _AUDIT_EVENT_TYPE { 
  AuditEventObjectAccess,
  AuditEventDirectoryServiceAccess
} AUDIT_EVENT_TYPE, *PAUDIT_EVENT_TYPE;
 
typedef enum _ATOM_INFORMATION_CLASS {
    AtomBasicInformation,
    AtomListInformation
} ATOM_INFORMATION_CLASS;

typedef struct _LDT_ENTRY {
  WORD  LimitLow;
  WORD  BaseLow;
  union {
    struct {
      BYTE BaseMid;
      BYTE Flags1;
      BYTE Flags2;
      BYTE BaseHi;
    } Bytes;
    struct {
      DWORD BaseMid  :8;
      DWORD Type  :5;
      DWORD Dpl  :2;
      DWORD Pres  :1;
      DWORD LimitHi  :4;
      DWORD Sys  :1;
      DWORD Reserved_0  :1;
      DWORD Default_Big  :1;
      DWORD Granularity  :1;
      DWORD BaseHi  :8;
    } Bits;
  } HighWord;
} LDT_ENTRY, *PLDT_ENTRY; 

typedef enum _HARDERROR_RESPONSE_OPTION {
  OptionAbortRetryIgnore,
  OptionOk,
  OptionOkCancel,
  OptionRetryCancel,
  OptionYesNo,
  OptionYesNoCancel,
  OptionShutdownSystem
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE {
  ResponseReturnToCaller,
  ResponseNotHandled,
  ResponseAbort,
  ResponseCancel,
  ResponseIgnore,
  ResponseNo,
  ResponseOk,
  ResponseRetry,
  ResponseYes
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

typedef enum _DEBUGOBJECTINFOCLASS
{
    DebugObjectFlags = 1,
    MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

typedef struct _JOB_SET_ARRAY
{
    HANDLE JobHandle;
    ULONG MemberLevel;
    ULONG Flags;
} JOB_SET_ARRAY, *PJOB_SET_ARRAY;

typedef struct _FILE_PATH
{
    ULONG Version;
    ULONG Length;
    ULONG Type;
    UCHAR FilePath[1];
} FILE_PATH, *PFILE_PATH;


typedef struct _EXCEPTION_REGISTRATION_RECORD 
{ 
   struct _EXCEPTION_REGISTRATION_RECORD *Next; 
   PEXCEPTION_ROUTINE                     Handler; 
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;

typedef struct _KTRAP_FRAME
{
     ULONG DbgEbp;
     ULONG DbgEip;
     ULONG DbgArgMark;
     ULONG DbgArgPointer;
     WORD TempSegCs;
     UCHAR Logging;
     UCHAR Reserved;
     ULONG TempEsp;
     ULONG Dr0;
     ULONG Dr1;
     ULONG Dr2;
     ULONG Dr3;
     ULONG Dr6;
     ULONG Dr7;
     ULONG SegGs;
     ULONG SegEs;
     ULONG SegDs;
     ULONG Edx;
     ULONG Ecx;
     ULONG Eax;
     ULONG PreviousPreviousMode;
     PEXCEPTION_REGISTRATION_RECORD ExceptionList;
     ULONG SegFs;
     ULONG Edi;
     ULONG Esi;
     ULONG Ebx;
     ULONG Ebp;
     ULONG ErrCode;
     ULONG Eip;
     ULONG SegCs;
     ULONG EFlags;
     ULONG HardwareEsp;
     ULONG HardwareSegSs;
     ULONG V86Es;
     ULONG V86Ds;
     ULONG V86Fs;
     ULONG V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;
 
//Methods to hook

//SET REGISTRY VALUE

NTSTATUS newZwSetValueKey(
  IN     HANDLE          KeyHandle,
  IN     PUNICODE_STRING ValueName,
  IN 	 ULONG           TitleIndex,
  IN     ULONG           Type,
  IN     PVOID           Data,
  IN     ULONG           DataSize
  );

NTSYSAPI NTSTATUS NTAPI ZwSetValueKey (
  IN     HANDLE          KeyHandle,
  IN     PUNICODE_STRING ValueName,
  IN 	 ULONG           TitleIndex,
  IN     ULONG           Type,
  IN     PVOID           Data,
  IN     ULONG           DataSize
);

typedef NTSTATUS (*ZwSetValueKeyPtr)(
  IN     HANDLE          KeyHandle,
  IN     PUNICODE_STRING ValueName,
  IN 	 ULONG           TitleIndex,
  IN     ULONG           Type,
  IN     PVOID           Data,
  IN     ULONG           DataSize
);

//TASK MANAGER PROCESS LIST

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	ULONG  SystemInformationClass, 
	PVOID  SystemInformation, 
	ULONG  SystemInformationLength, 
	PULONG ReturnLength 
);

typedef NTSTATUS (*ZwQuerySystemInformationPtr)(
	ULONG SystemInformationCLass,
	PVOID SystemInformation, 
	ULONG SystemInformationLength, 
	PULONG ReturnLength
);

/**
//OPEN A PROCESS

NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(
	OUT PHANDLE ProcessHandle, 
	IN ACCESS_MASK DesiredAccess, 
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
	IN OPTIONAL PCLIENT_ID ClientID
);

NTSTATUS newZwOpenProcess(
	OUT PHANDLE ProcessHandle, 
	IN ACCESS_MASK DesiredAccess, 
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
	IN OPTIONAL PCLIENT_ID ClientID
);

typedef NTSTATUS (*ZwOpenProcessPtr)(
	OUT PHANDLE ProcessHandle, 
	IN ACCESS_MASK DesiredAccess, 
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
	IN OPTIONAL PCLIENT_ID ClientID
);
*/
/**
//Write to Virtual Memory to user mode address range of another process

#define WRITE_VIRUTAL_MEMORY_INDEX 0x115

NTSYSAPI NTSTATUS NTAPI ZwWriteVirtualMemory(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	PVOID Buffer, 
	ULONG NumberOfBytesToWrite, 
	PULONG NumberOfBytesWritten
);

NTSTATUS newZwWriteVirtualMemory(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	PVOID Buffer, 
	ULONG NumberOfBytesToWrite, 
	PULONG NumberOfBytesWritten
);

typedef NTSTATUS (*ZwWriteVirtualMemoryPtr)(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	PVOID Buffer, 
	ULONG NumberOfBytesToWrite, 
	PULONG NumberOfBytesWritten
);
*/
/**
//Read virtual memory
#define READ_VIRTUAL_MEMORY_INDEX 0xBA

NTSTATUS newZwReadVirtualMemory(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	PVOID Buffer, 
	ULONG NumberOfBytesToRead, 
	PULONG NumberOfBytesReaded
);

typedef NTSTATUS (*ZwReadVirtualMemoryPtr)(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	PVOID Buffer, 
	ULONG NumberOfBytesToRead, 
	PULONG NumberOfBytesReaded
);
*/
/**
//Debug an active process, can be used for code injection
#define DEBUG_ACTIVE_PROCESS_INDEX 0x39
NTSTATUS newZwDebugActiveProcess(
	HANDLE ProcessHandle, 
	HANDLE DebugHandle
);

typedef NTSTATUS (*ZwDebugActiveProcessPtr)(
	HANDLE ProcessHandle, 
	HANDLE DebugHandle
);
*/
/**
//Create Section
#define CREATE_SECTION_INDEX 0x32

NTSTATUS newZwCreateSection (
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PLARGE_INTEGER SectionSize OPTIONAL,
	IN ULONG Protect,
	IN ULONG Attributes,
	IN HANDLE FileHandle
);

typedef NTSTATUS (*ZwCreateSectionPtr) (
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PLARGE_INTEGER SectionSize OPTIONAL,
	IN ULONG Protect,
	IN ULONG Attributes,
	IN HANDLE FileHandle
);
*/
/**
//CREATE PROCESS 

#define CREATE_PROCESS_INDEX 0x2F

NTSTATUS newZwCreateProcess (
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
	IN HANDLE InheritFromProcessHandle,
	IN BOOLEAN InheritHandles,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL
);

typedef NTSTATUS (*ZwCreateProcessPtr) (
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
	IN HANDLE InheritFromProcessHandle,
	IN BOOLEAN InheritHandles,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL
);
*/
/**
//Also creates a process

#define CREATE_PROCESS_EX_INDEX 0x30

NTSTATUS newZwCreateProcessEx(
	PHANDLE ProcessHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	HANDLE InheritFromProcessHandle, 
	BOOLEAN InheritHandles, 
	HANDLE SectionHandle, 
	HANDLE DebugPort, 
	HANDLE ExceptionPort, 
	HANDLE dunno
);

typedef NTSTATUS (*ZwCreateProcessExPtr)(
	PHANDLE ProcessHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	HANDLE InheritFromProcessHandle, 
	BOOLEAN InheritHandles, 
	HANDLE SectionHandle, 
	HANDLE DebugPort, 
	HANDLE ExceptionPort, 
	HANDLE dunno
);
*/
/**
//Logs thread-based Asynchronous Procedure Call creation (may be used for code injection).
#define QUEUE_APC_THREAD_INDEX 0xB4

NTSTATUS newZwQueueApcThread(
	HANDLE ThreadHandle, 
	PIO_APC_ROUTINE ApcRoutine, 
	PVOID ApcRoutineContext, 
	PIO_STATUS_BLOCK ApcStatusBlock, 
	ULONG ApcReserved
);

typedef NTSTATUS (*ZwQueueApcThreadPtr) (
	HANDLE ThreadHandle, 
	PIO_APC_ROUTINE ApcRoutine, 
	PVOID ApcRoutineContext, 
	PIO_STATUS_BLOCK ApcStatusBlock, 
	ULONG ApcReserved
);
*/
/**
//CREATE A THREAD

#define CREATE_THREAD_INDEX 0x35

NTSTATUS newZwCreateThread(
	PHANDLE ThreadHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	HANDLE ProcessHandle, 
	PCLIENT_ID ClientID, 
	PCONTEXT ThreadContext, 
	PUSER_STACK UserStack, 
	BOOLEAN CreateSuspended
);

typedef NTSTATUS (*ZwCreateThreadPtr) (
	PHANDLE ThreadHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	HANDLE ProcessHandle, 
	PCLIENT_ID ClientID, 
	PCONTEXT ThreadContext, 
	PUSER_STACK UserStack, 
	BOOLEAN CreateSuspended	
);
*/
/**
//Create Thread
#define CREATE_THREAD_EX_INDEX 0x36

NTSTATUS newZwCreateThreadEx(
	PHANDLE ThreadHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	HANDLE ProcessHandle, 
	PVOID StartAddress, 
	PVOID Parameter, 
	BOOLEAN CreateSuspended, 
	ULONG StackZeroBits, 
	ULONG SizeOfStackCommit, 
	ULONG SizeOfStackReserve, 
	PVOID BytesBuffer
);

typedef NTSTATUS (*ZwCreateThreadExPtr)(
	PHANDLE ThreadHandle, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	HANDLE ProcessHandle, 
	PVOID StartAddress, 
	PVOID Parameter, 
	BOOLEAN CreateSuspended, 
	ULONG StackZeroBits, 
	ULONG SizeOfStackCommit, 
	ULONG SizeOfStackReserve, 
	PVOID BytesBuffer
);
*/
//Used for section mapping (may be used for code injection)
#define MAP_VIEW_OF_SECTION_INDEX 0x6C

NTSTATUS newZwMapViewOfSection(
	HANDLE SectionHandle, 
	HANDLE ProcessHandle, 
	PVOID *BaseAddress, 
	ULONG_PTR ZeroBits, 
	SIZE_T CommitSize, 
	PLARGE_INTEGER SectionOffset, 
	PSIZE_T ViewSize, 
	SECTION_INHERIT InheritDisposition, 
	ULONG AllocationType, 
	ULONG Win32Protect
);

typedef NTSTATUS (*ZwMapViewOfSectionPtr)(
	HANDLE SectionHandle, 
	HANDLE ProcessHandle, 
	PVOID *BaseAddress, 
	ULONG_PTR ZeroBits, 
	SIZE_T CommitSize, 
	PLARGE_INTEGER SectionOffset, 
	PSIZE_T ViewSize, 
	SECTION_INHERIT InheritDisposition, 
	ULONG AllocationType, 
	ULONG Win32Protect
);

//Logs thread context manipulation (may be used for code injection)

#define SET_CONTEXT_THREAD_INDEX 0xD5

NTSTATUS newZwSetContextThread(
	HANDLE ThreadHandle, 
	PCONTEXT Context
);

typedef NTSTATUS (*ZwSetContextThreadPtr)(
	HANDLE ThreadHandle, 
	PCONTEXT Context
);

/**
#define SYSTEM_DEBUG_CONTROL_INDEX 0xFF

NTSTATUS newZwSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

typedef NTSTATUS (*ZwSystemDebugControlPtr)(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
*/

/**
#define OPEN_FILE_INDEX 0x74

NTSTATUS newZwOpenFile (
  OUT	 PHANDLE 		    FileHandle,
  IN     ACCESS_MASK	    DesiredAccess,
  IN 	 POBJECT_ATTRIBUTES ObjectAttributes,
  OUT 	 PIO_STATUS_BLOCK   IoStatusBlock,
  IN	 ULONG				ShareAccess,
  IN     ULONG              OpenOptions
);

NTSYSAPI NTSTATUS NTAPI ZwOpenFile (
  OUT	 PHANDLE 		    FileHandle,
  IN     ACCESS_MASK	    DesiredAccess,
  IN 	 POBJECT_ATTRIBUTES ObjectAttributes,
  OUT 	 PIO_STATUS_BLOCK   IoStatusBlock,
  IN	 ULONG				ShareAccess,
  IN     ULONG              OpenOptions
);

typedef NTSTATUS (*ZwOpenFilePtr) (
  OUT	 PHANDLE 		    FileHandle,
  IN     ACCESS_MASK	    DesiredAccess,
  IN 	 POBJECT_ATTRIBUTES ObjectAttributes,
  OUT 	 PIO_STATUS_BLOCK   IoStatusBlock,
  IN	 ULONG				ShareAccess,
  IN     ULONG              OpenOptions
);
*/
/**
#define CREATE_FILE_INDEX 0x25

NTSTATUS newZwCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

typedef NTSTATUS (*ZwCreateFilePtr)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
*/


#define READ_FILE_INDEX 0xb7

NTSTATUS newZwReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

typedef NTSTATUS (*ZwReadFilePtr)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);


/**
#define DELETE_FILE_INDEX 0x3e
NTSTATUS newZwDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwDeleteFilePtr)(POBJECT_ATTRIBUTES ObjectAttributes);
*/

/**
#define SET_INFORMATION_FILE_INDEX 0xe0
NTSTATUS newZwSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef (*ZwSetInformationFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
*/
/**
#define CREATE_MUTANT_INDEX 0x2B
NTSTATUS newZwCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner);
typedef (*ZwCreateMutantPtr)(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner);
*/

#define DEVICE_IO_CONTROL_FILE_INDEX 0x42
NTSTATUS newZwDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OuputBuffer, ULONG OutputBufferLength);
typedef (*ZwDeviceIoControlFilePtr)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OuputBuffer, ULONG OutputBufferLength);

/**
#define TERMINATE_PROCESS_INDEX 0x101
NTSTATUS newZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef (*ZwTerminateProcessPtr)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
*/
/**
#define LOAD_DRIVER_INDEX 0x61
NTSTATUS newZwLoadDriver(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS (*ZwLoadDriverPtr)(PUNICODE_STRING DriverServiceName);*/

#define DELAY_EXECUTION_INDEX 0x3B
NTSTATUS newZwDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
typedef NTSTATUS (*ZwDelayExecutionPtr)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
/**
#define QUERY_VALUE_KEY_INDEX 0xB1
NTSTATUS newZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
typedef NTSTATUS (*ZwQueryValueKeyPtr)(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);*/
/**
#define QUERY_ATTRIBUTES_FILE_INDEX 0x8B
NTSTATUS newZwQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);
typedef NTSTATUS (*ZwQueryAttributesFilePtr)(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);*/
/**
#define ACCEPT_CONNECT_PORT 0x00
NTSTATUS newZwAcceptConnectPort(PHANDLE PortHandle, ULONG PortIdentifier, PPORT_MESSAGE Message, BOOLEAN Accept, PPORT_SECTION_WRITE WriteSection, PPORT_SECTION_READ ReadSection);
typedef NTSTATUS (*ZwAcceptConnectPortPtr)(PHANDLE PortHandle, ULONG PortIdentifier, PPORT_MESSAGE Message, BOOLEAN Accept, PPORT_SECTION_WRITE WriteSection, PPORT_SECTION_READ ReadSection);*/

#define WAIT_FOR_SINGLE_OBJECT 0x10F
NTSTATUS newZwWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS (*ZwWaitForSingleObjectPtr)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

#define REPLY_WAIT_RECEIVE_PORT 0xC3
NTSTATUS newZwReplyWaitReceivePort(HANDLE PortHandle, PULONG PortIdentifier, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE Message);
typedef NTSTATUS (*ZwReplyWaitReceivePortPtr)(HANDLE PortHandle, PULONG PortIdentifier, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE Message);

#define REQUEST_WAIT_REPLY_PORT 0xC8
NTSTATUS newZwRequestWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage, PPORT_MESSAGE ReplyMessage);
typedef NTSTATUS (*ZwRequestWaitReplyPortPtr)(HANDLE PortHandle, PPORT_MESSAGE RequestMessage, PPORT_MESSAGE ReplyMessage);

#define CLOSE 0x19
NTSTATUS newZwClose(HANDLE Handle);
typedef NTSTATUS (*ZwClosePtr)(HANDLE Handle);

#define SET_EVENT 0xDB
NTSTATUS newZwSetEvent(HANDLE EventHandle, PULONG PreviousState);
typedef NTSTATUS (*ZwSetEventPtr)(HANDLE EventHandle, PULONG PreviousState);

#define OPEN_THREAD_TOKEN 0x81
NTSTATUS newZwOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle);
typedef NTSTATUS (*ZwOpenThreadTokenPtr)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle);

#define OPEN_THREAD_TOKEN_EX 0x82
NTSTATUS newZwOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, ULONG HandleAttributes, PHANDLE TokenHandle);
typedef NTSTATUS (*ZwOpenThreadTokenExPtr)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, ULONG HandleAttributes, PHANDLE TokenHandle);

#define OPEN_KEY 0x77
NTSTATUS newZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenKeyPtr)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define ALLOCATE_VIRTUAL_MEMORY 0x11
NTSTATUS newZwAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddresss, ULONG ZeroBits, PULONG AllocationSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS (*ZwAllocateVirtualMemoryPtr)(HANDLE ProcessHandle, PVOID *BaseAddresss, ULONG ZeroBits, PULONG AllocationSize, ULONG AllocationType, ULONG Protect);

#define PROTECT_VIRTUAL_MEMORY 0x89
NTSTATUS newZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddresss, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS (*ZwProtectVirtualMemoryPtr)(HANDLE ProcessHandle, PVOID *BaseAddresss, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);

#define QUERY_INFORMATION_TOKEN 0x9C
NTSTATUS newZwQueryInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryInformationTokenPtr)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);

#define ENUMERATE_KEY 0x47
NTSTATUS newZwEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwEnumerateKeyPtr)(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ResultLength);

#define FLUSH_INSTRUCTION_CACHE 0x4E
NTSTATUS newZwFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddresss, ULONG FlushSize);
typedef NTSTATUS (*ZwFlushInstructionCachePtr)(HANDLE ProcessHandle, PVOID BaseAddresss, ULONG FlushSize);

#define QUERY_SECURITY_OBJECT 0xA8
NTSTATUS newZwQuerySecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQuerySecurityObjectPtr)(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength, PULONG ReturnLength);

#define QUERY_DEFAULT_LOCALE 0x8F
NTSTATUS newZwQueryDefaultLocale(BOOLEAN ThreadOrSystem, PLCID Locale);
typedef NTSTATUS (*ZwQueryDefaultLocalePtr)(BOOLEAN ThreadOrSystem, PLCID Locale);

#define QUERY_SYSTEM_TIME 0xAE
NTSTATUS newZwQuerySystemTime(PLARGE_INTEGER CurrentTime);
typedef NTSTATUS (*ZwQuerySystemTimePtr)(PLARGE_INTEGER CurrentTime);

#define OPEN_SECTION 0x7D
NTSTATUS newZwOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenSectionPtr)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define SET_INFORMATION_PROCESS 0xE4
NTSTATUS newZwSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef NTSTATUS (*ZwSetInformationProcessPtr)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);

#define QUERY_INFORMATION_PROCESS 0x9A
NTSTATUS newZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryInformationProcessPtr)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

#define GET_CONTEXT_THREAD 0x55
NTSTATUS newZwGetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
typedef NTSTATUS (*ZwGetContextThreadPtr)(HANDLE ThreadHandle, PCONTEXT Context);

#define CREATE_PROFILE 0x31
NTSTATUS newZwCreateProfile(PHANDLE ProfileHandle, HANDLE ProcessHandle, PVOID Base, ULONG Size, ULONG BucketShift, PULONG Buffer, ULONG BufferLength, KPROFILE_SOURCE Source, ULONG ProcessorMask);
typedef NTSTATUS (*ZwCreateProfilePtr)(PHANDLE ProfileHandle, HANDLE ProcessHandle, PVOID Base, ULONG Size, ULONG BucketShift, PULONG Buffer, ULONG BufferLength, KPROFILE_SOURCE Source, ULONG ProcessorMask);

#define START_PROFILE 0xFB
NTSTATUS newZwStartProfile(HANDLE ProfileHandle);
typedef NTSTATUS (*ZwStartProfilePtr)(HANDLE ProfileHandle);

#define ACCESS_CHECK 0x01
NTSTATUS newZwAccessCheck(PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE TokenHandle, ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PBOOLEAN AccessStatus);
typedef NTSTATUS (*ZwAccessCheckPtr)(PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE TokenHandle, ACCESS_MASK DesiredAccess, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PBOOLEAN AccessStatus);

#define ACCESS_CHECK_AND_AUDIT_ALARM 0x02
NTSTATUS newZwAccessCheckAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PBOOLEAN AccessStatus, PBOOLEAN GenerateOnClose);
typedef NTSTATUS (*ZwAccessCheckAndAuditAlarmPtr)(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PBOOLEAN AccessStatus, PBOOLEAN GenerateOnClose);

#define SET_SYSTEM_INFORMATION 0xF0
NTSTATUS newZwSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation);
typedef NTSTATUS (*ZwSetSystemInformationPtr)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation);

#define GET_PLUG_PLAY_EVENT 0x57
NTSTATUS newZwGetPlugPlayEvent(ULONG Reserved1, ULONG Reserved2, PVOID Buffer, ULONG BufferLength);
typedef NTSTATUS (*ZwGetPlugPlayEventPtr)(ULONG Reserved1, ULONG Reserved2, PVOID Buffer, ULONG BufferLength);

#define PLUG_PLAY_CONTROL 0x84
NTSTATUS newZwPlugPlayControl(ULONG ControlCode, PVOID Buffer, ULONG BufferLength);
typedef NTSTATUS (*ZwPlugPlayControlPtr)(ULONG ControlCode, PVOID Buffer, ULONG BufferLength);

#define LOCK_VIRTUAL_MEMORY 0x67
NTSTATUS newZwLockVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG LockSize, ULONG LockType);
typedef NTSTATUS (*ZwLockVirtualMemoryPtr)(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG LockSize, ULONG LockType);

#define UNLOCK_VIRTUAL_MEMORY 0x10A
NTSTATUS newZwUnlockVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG LockSize, ULONG LockType);
typedef NTSTATUS (*ZwUnlockVirtualMemoryPtr)(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG LockSize, ULONG LockType);

#define FLUSH_VIRTUAL_MEMORY 0x50
NTSTATUS newZwFlushVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG FlushSize, PIO_STATUS_BLOCK IoStatusBlock);
typedef NTSTATUS (*ZwFlushVirtualMemoryPtr)(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG FlushSize, PIO_STATUS_BLOCK IoStatusBlock);

#define ALLOCATE_USER_PHYSICAL_PAGES 0x0F
NTSTATUS newZwAllocateUserPhysicalPages(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG PageFrameNumbers);
typedef NTSTATUS (*ZwAllocateUserPhysicalPagesPtr)(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG PageFrameNumbers);

#define FREE_USER_PHYSICAL_PAGES 0x52
NTSTATUS newZwFreeUserPhysicalPages(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG PageFrameNumbers);
typedef NTSTATUS (*ZwFreeUserPhysicalPagesPtr)(HANDLE ProcessHandle, PULONG NumberOfPages, PULONG PageFrameNumbers);

#define MAP_USER_PHYSICAL_PAGES 0x6A
NTSTATUS newZwMapUserPhysicalPages(PVOID BaseAddress, PULONG NumberOfPages, PULONG PageFrameNumbers);
typedef NTSTATUS (*ZwMapUserPhysicalPagesPtr)(PVOID BaseAddress, PULONG NumberOfPages, PULONG PageFrameNumbers);

#define MAP_USER_PHYSICAL_PAGES_SCATTER 0x6B
NTSTATUS newZwMapUserPhysicalPagesScatter(PVOID *BaseAddress, PULONG NumberOfPages, PULONG PageFrameNumbers);
typedef NTSTATUS (*ZwMapUserPhysicalPagesScatterPtr)(PVOID *BaseAddress, PULONG NumberOfPages, PULONG PageFrameNumbers);

#define GET_WRITE_WATCH 0x58
NTSTATUS newZwGetWriteWatch(HANDLE ProcessHandle, ULONG Flags, PVOID BaseAddress, ULONG RegionSize, PULONG Buffer, PULONG BufferEntries, PULONG Granularity);
typedef NTSTATUS (*ZwGetWriteWatchPtr)(HANDLE ProcessHandle, ULONG Flags, PVOID BaseAddress, ULONG RegionSize, PULONG Buffer, PULONG BufferEntries, PULONG Granularity);

#define RESET_WRITE_WATCH 0xCB
NTSTATUS newZwResetWriteWatch(HANDLE ProcessHandle, PVOID BaseAddress, ULONG RegionSize);
typedef NTSTATUS (*ZwResetWriteWatchPtr)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG RegionSize);

#define FREE_VIRTUAL_MEMORY 0x53
NTSTATUS newZwFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG FreeSize, ULONG FreeType);
typedef NTSTATUS (*ZwFreeVirtualMemoryPtr)(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG FreeSize, ULONG FreeType);

#define QUERY_VIRTUAL_MEMORY 0xB2
NTSTATUS newZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, ULONG MemoryInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryVirtualMemoryPtr)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, ULONG MemoryInformationLength, PULONG ReturnLength);

#define READ_VIRTUAL_MEMORY 0xBA
NTSTATUS newZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwReadVirtualMemoryPtr)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

#define WRITE_VIRTUAL_MEMORY 0x115
NTSTATUS newZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwWriteVirtualMemoryPtr)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

#define CREATE_FILE 0x25
NTSTATUS newZwCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS (*ZwCreateFilePtr)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

#define OPEN_FILE 0x74
NTSTATUS newZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
typedef NTSTATUS (*ZwOpenFilePtr)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);

#define DELETE_FILE 0x3E
NTSTATUS newZwDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwDeleteFilePtr)(POBJECT_ATTRIBUTES ObjectAttributes);

#define FLUSH_BUFFERS_FILE 0x4D
NTSTATUS newZwFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);
typedef NTSTATUS (*ZwFlushBuffersFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);

#define CANCEL_IO_FILE 0x16
NTSTATUS newZwCancelIoFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);
typedef NTSTATUS (*ZwCancelIoFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);

#define WRITE_FILE 0x112
NTSTATUS newZwWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS (*ZwWriteFilePtr)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

#define READ_FILE_SCATTER 0xB8
NTSTATUS newZwReadFileScatter(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS (*ZwReadFileScatterPtr)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

#define WRITE_FILE_GATHER 0x113
NTSTATUS newZwWriteFileGather(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS (*ZwWriteFileGatherPtr)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_SEGMENT_ELEMENT Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

#define LOCK_FILE 0x64
NTSTATUS newZwLockFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PULARGE_INTEGER LockOffset, PULARGE_INTEGER LockLength, ULONG Key, BOOLEAN FailImmediately, BOOLEAN ExclusiveLock);
typedef NTSTATUS (*ZwLockFilePtr)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PULARGE_INTEGER LockOffset, PULARGE_INTEGER LockLength, ULONG Key, BOOLEAN FailImmediately, BOOLEAN ExclusiveLock);

#define UNLOCK_FILE 0x109
NTSTATUS newZwUnlockFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PULARGE_INTEGER LockOffset, PULARGE_INTEGER LockLength, ULONG Key);
typedef NTSTATUS (*ZwUnlockFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PULARGE_INTEGER LockOffset, PULARGE_INTEGER LockLength, ULONG Key);

#define FS_CONTROL_FILE 0x54
NTSTATUS newZwFsControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
typedef NTSTATUS (*ZwFsControlFilePtr)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

#define NOTIFY_CHANGE_DIRECTORY_FILE 0x6E
NTSTATUS newZwNotifyChangeDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_NOTIFY_INFORMATION Buffer, ULONG BufferLength, ULONG NotifyFilter, BOOLEAN WatchSubtree);
typedef NTSTATUS (*ZwNotifyChangeDirectoryFilePtr)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PFILE_NOTIFY_INFORMATION Buffer, ULONG BufferLength, ULONG NotifyFilter, BOOLEAN WatchSubtree);

#define QUERY_EA_FILE 0x93
NTSTATUS newZwQueryEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_FULL_EA_INFORMATION Buffer, ULONG BufferLength, BOOLEAN ReturnSingleEntry, PFILE_GET_EA_INFORMATION EaList, ULONG EaListLength, PULONG EaIndex, BOOLEAN RestartScan);
typedef NTSTATUS (*ZwQueryEaFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_FULL_EA_INFORMATION Buffer, ULONG BufferLength, BOOLEAN ReturnSingleEntry, PFILE_GET_EA_INFORMATION EaList, ULONG EaListLength, PULONG EaIndex, BOOLEAN RestartScan);

#define SET_EA_FILE 0xDA
NTSTATUS newZwSetEaFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_FULL_EA_INFORMATION Buffer, ULONG BufferLength);
typedef NTSTATUS (*ZwSetEaFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_FULL_EA_INFORMATION Buffer, ULONG BufferLength);

#define CREATE_NAMED_PIPE_FILE 0x2C
NTSTATUS newZwCreateNamedPipeFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, BOOLEAN TypeMessage, BOOLEAN ReadmodeMessage, BOOLEAN Nonblocking, ULONG MaxInstances, ULONG InBufferSize, ULONG OutBufferSize, PLARGE_INTEGER DefaultTimeout);
typedef NTSTATUS (*ZwCreateNamedPipeFilePtr)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, BOOLEAN TypeMessage, BOOLEAN ReadmodeMessage, BOOLEAN Nonblocking, ULONG MaxInstances, ULONG InBufferSize, ULONG OutBufferSize, PLARGE_INTEGER DefaultTimeout);

#define CREATE_MAILSLOT_FILE 0x2A
NTSTATUS newZwCreateMailslotFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG CreateOptions, ULONG InBufferSize, ULONG MaxMessageSize, PLARGE_INTEGER ReadTimeout);
typedef NTSTATUS (*ZwCreateMailslotFilePtr)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG CreateOptions, ULONG InBufferSize, ULONG MaxMessageSize, PLARGE_INTEGER ReadTimeout);

#define QUERY_VOLUME_INFORMATION_FILE 0xB3
NTSTATUS newZwQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID VolumeInformation, ULONG VolumeInformationLength, FS_INFORMATION_CLASS VolumeInformationClass);
typedef NTSTATUS (*ZwQueryVolumeInformationFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID VolumeInformation, ULONG VolumeInformationLength, FS_INFORMATION_CLASS VolumeInformationClass);

#define SET_VOLUME_INFORMATION_FILE 0xF8
NTSTATUS newZwSetVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG BufferLength, FS_INFORMATION_CLASS VolumeInformationClass);
typedef NTSTATUS (*ZwSetVolumeInformationFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG BufferLength, FS_INFORMATION_CLASS VolumeInformationClass);

#define QUERY_QUOTA_INFORMATION_FILE 0xA6
NTSTATUS newZwQueryQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_USER_QUOTA_INFORMATION Buffer, ULONG BufferLength, BOOLEAN ReturnSingleEntry, PFILE_QUOTA_LIST_INFORMATION QuotaList, ULONG QuotaListLength, PSID ResumeSid, BOOLEAN RestartScan);
typedef NTSTATUS (*ZwQueryQuotaInformationFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_USER_QUOTA_INFORMATION Buffer, ULONG BufferLength, BOOLEAN ReturnSingleEntry, PFILE_QUOTA_LIST_INFORMATION QuotaList, ULONG QuotaListLength, PSID ResumeSid, BOOLEAN RestartScan);

#define SET_QUOTA_INFORMATION_FILE 0xEC
NTSTATUS newZwSetQuotaInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_USER_QUOTA_INFORMATION Buffer, ULONG BufferLength);
typedef NTSTATUS (*ZwSetQuotaInformationFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PFILE_USER_QUOTA_INFORMATION Buffer, ULONG BufferLength);

#define QUERY_ATTRIBUTES_FILE 0x8B
NTSTATUS newZwQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);
typedef NTSTATUS (*ZwQueryAttributesFilePtr)(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);

#define QUERY_FULL_ATTRIBUTES_FILE 0x95
NTSTATUS newZwQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation);
typedef NTSTATUS (*ZwQueryFullAttributesFilePtr)(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation);

#define QUERY_INFORMATION_FILE 0x97
NTSTATUS newZwQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG FileInformationLength, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (*ZwQueryInformationFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG FileInformationLength, FILE_INFORMATION_CLASS FileInformationClass);

#define SET_INFORMATION_FILE 0xE0
NTSTATUS newZwSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG FileInformationLength, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (*ZwSetInformationFilePtr)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG FileInformationLength, FILE_INFORMATION_CLASS FileInformationClass);

#define QUERY_DIRECTORY_FILE 0x91
NTSTATUS newZwQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG FileInformationLength, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
typedef NTSTATUS (*ZwQueryDirectoryFilePtr)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG FileInformationLength, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);

#define CREATE_KEY 0x29
NTSTATUS newZwCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
typedef NTSTATUS (*ZwCreateKeyPtr)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);

#define DELETE_KEY 0x3F
NTSTATUS newZwDeleteKey(HANDLE KeyHandle);
typedef NTSTATUS (*ZwDeleteKeyPtr)(HANDLE KeyHandle);

#define FLUSH_KEY 0x4F
NTSTATUS newZwFlushKey(HANDLE KeyHandle);
typedef NTSTATUS (*ZwFlushKeyPtr)(HANDLE KeyHandle);

#define SAVE_KEY 0xCF
NTSTATUS newZwSaveKey(HANDLE KeyHandle, HANDLE FileHandle);
typedef NTSTATUS (*ZwSaveKeyPtr)(HANDLE KeyHandle, HANDLE FileHandle);

#define SAVE_KEY_EX 0xD0
NTSTATUS newZwSaveKeyEx(HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags);
typedef NTSTATUS (*ZwSaveKeyExPtr)(HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags);

#define SAVE_MERGED_KEYS 0xD1
NTSTATUS newZwSaveMergedKeys(HANDLE KeyHandle1, HANDLE KeyHandle2, HANDLE FileHandle);
typedef NTSTATUS (*ZwSaveMergedKeysPtr)(HANDLE KeyHandle1, HANDLE KeyHandle2, HANDLE FileHandle);

#define RESTORE_KEY 0xCC
NTSTATUS newZwRestoreKey(HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags);
typedef NTSTATUS (*ZwRestoreKeyPtr)(HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags);

#define LOAD_KEY 0x62
NTSTATUS newZwLoadKey(POBJECT_ATTRIBUTES KeyObjectAttributes, POBJECT_ATTRIBUTES FileObjectAttributes);
typedef NTSTATUS (*ZwLoadKeyPtr)(POBJECT_ATTRIBUTES KeyObjectAttributes, POBJECT_ATTRIBUTES FileObjectAttributes);

#define LOAD_KEY2 0x63
NTSTATUS newZwLoadKey2(POBJECT_ATTRIBUTES KeyObjectAttributes, POBJECT_ATTRIBUTES FileObjectAttributes, ULONG Flags);
typedef NTSTATUS (*ZwLoadKey2Ptr)(POBJECT_ATTRIBUTES KeyObjectAttributes, POBJECT_ATTRIBUTES FileObjectAttributes, ULONG Flags);

#define UNLOAD_KEY 0x107
NTSTATUS newZwUnloadKey(POBJECT_ATTRIBUTES KeyObjectAttributes);
typedef NTSTATUS (*ZwUnloadKeyPtr)(POBJECT_ATTRIBUTES KeyObjectAttributes);

#define UNLOAD_KEY_EX 0x108
NTSTATUS newZwUnloadKeyEx(POBJECT_ATTRIBUTES TargetKey, HANDLE Event);
typedef NTSTATUS (*ZwUnloadKeyExPtr)(POBJECT_ATTRIBUTES TargetKey, HANDLE Event);

#define QUERY_OPEN_SUBKEYS 0xA4
NTSTATUS newZwQueryOpenSubKeys(POBJECT_ATTRIBUTES KeyObjectAttributes, PULONG NumberOfKeys);
typedef NTSTATUS (*ZwQueryOpenSubKeysPtr)(POBJECT_ATTRIBUTES KeyObjectAttributes, PULONG NumberOfKeys);

#define REPLACE_KEY 0xC1
NTSTATUS newZwReplaceKey(POBJECT_ATTRIBUTES NewFileObjectAttributes, HANDLE KeyHandle, POBJECT_ATTRIBUTES OldFileObjectAttributes);
typedef NTSTATUS (*ZwReplaceKeyPtr)(POBJECT_ATTRIBUTES NewFileObjectAttributes, HANDLE KeyHandle, POBJECT_ATTRIBUTES OldFileObjectAttributes);

#define SET_INFORMATION_KEY 0xE2
NTSTATUS newZwSetInformationKey(HANDLE KeyHandle, KEY_SET_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength);
typedef NTSTATUS (*ZwSetInformationKeyPtr)(HANDLE KeyHandle, KEY_SET_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength);

#define QUERY_KEY 0xA0
NTSTATUS newZwQueryKey(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwQueryKeyPtr)(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ResultLength);

#define NOTIFY_CHANGE_KEY 0x6F
NTSTATUS newZwNotifyChangeKey(HANDLE KeyHandle, HANDLE EventHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG NotifyFilter, BOOLEAN WatchSubtree, PVOID Buffer, ULONG BufferLength, BOOLEAN Asynchronous);
typedef NTSTATUS (*ZwNotifyChangeKeyPtr)(HANDLE KeyHandle, HANDLE EventHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG NotifyFilter, BOOLEAN WatchSubtree, PVOID Buffer, ULONG BufferLength, BOOLEAN Asynchronous);

#define NOTIFY_CHANGE_MULTIPLE_KEYS 0x70
NTSTATUS newZwNotifyChangeMultipleKeys(HANDLE KeyHandle, ULONG Flags, POBJECT_ATTRIBUTES KeyObjectAttributes, HANDLE EventHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG NotifyFilter, BOOLEAN WatchSubtree, PVOID Buffer, ULONG BufferLength, BOOLEAN Asynchronous);
typedef NTSTATUS (*ZwNotifyChangeMultipleKeysPtr)(HANDLE KeyHandle, ULONG Flags, POBJECT_ATTRIBUTES KeyObjectAttributes, HANDLE EventHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG NotifyFilter, BOOLEAN WatchSubtree, PVOID Buffer, ULONG BufferLength, BOOLEAN Asynchronous);

#define DELETE_VALUE_KEY 0x41
NTSTATUS newZwDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName);
typedef NTSTATUS (*ZwDeleteValueKeyPtr)(HANDLE KeyHandle, PUNICODE_STRING ValueName);

#define SET_VALUE_KEY 0xF7
NTSTATUS newZwSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
typedef NTSTATUS (*ZwSetValueKeyPtr)(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);

#define QUERY_VALUE_KEY 0xB1
NTSTATUS newZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwQueryValueKeyPtr)(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, PULONG ResultLength);

#define ENUMERATE_VALUE_KEY 0x49
NTSTATUS newZwEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwEnumerateValueKeyPtr)(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, PULONG ResultLength);

#define QUERY_MULTIPLE_VALUE_KEY 0xA1
NTSTATUS newZwQueryMultipleValueKey(HANDLE KeyHandle, PKEY_VALUE_ENTRY ValueList, ULONG NumberOfValues, PVOID Buffer, PULONG Length, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryMultipleValueKeyPtr)(HANDLE KeyHandle, PKEY_VALUE_ENTRY ValueList, ULONG NumberOfValues, PVOID Buffer, PULONG Length, PULONG ReturnLength);

#define INITIALIZE_REGISTRY 0x5C
NTSTATUS newZwInitializeRegistry(BOOLEAN Setup);
typedef NTSTATUS (*ZwInitializeRegistryPtr)(BOOLEAN Setup);

#define CREATE_PORT 0x2E
NTSTATUS newZwCreatePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxDataSize, ULONG MaxMessageSize, ULONG Reserved);
typedef NTSTATUS (*ZwCreatePortPtr)(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxDataSize, ULONG MaxMessageSize, ULONG Reserved);

#define CREATE_WAITABLE_PORT 0x38
NTSTATUS newZwCreateWaitablePort(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxDataSize, ULONG MaxMessageSize, ULONG Reserved);
typedef NTSTATUS (*ZwCreateWaitablePortPtr)(PHANDLE PortHandle, POBJECT_ATTRIBUTES ObjectAttributes, ULONG MaxDataSize, ULONG MaxMessageSize, ULONG Reserved);

#define CONNECT_PORT 0x1F
NTSTATUS newZwConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_VIEW ClientView, PREMOTE_PORT_VIEW ServerView, PULONG MaxMessageLength, PVOID ConnectInformation, PULONG ConnectInformationLength);
typedef NTSTATUS (*ZwConnectPortPtr)(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_VIEW ClientView, PREMOTE_PORT_VIEW ServerView, PULONG MaxMessageLength, PVOID ConnectInformation, PULONG ConnectInformationLength);

#define SECURE_CONNECT_PORT 0xD2
NTSTATUS newZwSecureConnectPort(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_VIEW ClientView, PSID ServerSid, PREMOTE_PORT_VIEW ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength);
typedef NTSTATUS (*ZwSecureConnectPortPtr)(PHANDLE PortHandle, PUNICODE_STRING PortName, PSECURITY_QUALITY_OF_SERVICE SecurityQos, PPORT_VIEW ClientView, PSID ServerSid, PREMOTE_PORT_VIEW ServerView, PULONG MaxMessageLength, PVOID ConnectionInformation, PULONG ConnectionInformationLength);

#define LISTEN_PORT 0x60
NTSTATUS newZwListenPort(HANDLE PortHandle, PPORT_MESSAGE Message);
typedef NTSTATUS (*ZwListenPortPtr)(HANDLE PortHandle, PPORT_MESSAGE Message);

#define ACCEPT_CONNECT_PORT 0x00
NTSTATUS newZwAcceptConnectPort(PHANDLE PortHandle, PVOID PortIdentifier, PPORT_MESSAGE Message, BOOLEAN Accept, PPORT_VIEW ServerView, PREMOTE_PORT_VIEW ClientView);
typedef NTSTATUS (*ZwAcceptConnectPortPtr)(PHANDLE PortHandle, PVOID PortIdentifier, PPORT_MESSAGE Message, BOOLEAN Accept, PPORT_VIEW ServerView, PREMOTE_PORT_VIEW ClientView);

#define COMPLETE_CONNECT_PORT 0x1D
NTSTATUS newZwCompleteConnectPort(HANDLE PortHandle);
typedef NTSTATUS (*ZwCompleteConnectPortPtr)(HANDLE PortHandle);

#define REQUEST_PORT 0xC7
NTSTATUS newZwRequestPort(HANDLE PortHandle, PPORT_MESSAGE RequestMessage);
typedef NTSTATUS (*ZwRequestPortPtr)(HANDLE PortHandle, PPORT_MESSAGE RequestMessage);

#define REPLY_PORT 0xC2
NTSTATUS newZwReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage);
typedef NTSTATUS (*ZwReplyPortPtr)(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage);

#define REPLY_WAIT_REPLY_PORT 0xC5
NTSTATUS newZwReplyWaitReplyPort(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage);
typedef NTSTATUS (*ZwReplyWaitReplyPortPtr)(HANDLE PortHandle, PPORT_MESSAGE ReplyMessage);

#define REPLY_WAIT_RECEIVE_PORT_EX 0xC4
NTSTATUS newZwReplyWaitReceivePortEx(HANDLE PortHandle, PVOID *PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage,PLARGE_INTEGER Timeout);
typedef NTSTATUS (*ZwReplyWaitReceivePortExPtr)(HANDLE PortHandle, PVOID *PortContext, PPORT_MESSAGE ReplyMessage, PPORT_MESSAGE ReceiveMessage,PLARGE_INTEGER Timeout);

#define READ_REQUEST_DATA 0xB9
NTSTATUS newZwReadRequestData(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Index, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwReadRequestDataPtr)(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Index, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

#define WRITE_REQUEST_DATA 0x114
NTSTATUS newZwWriteRequestData(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Index, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwWriteRequestDataPtr)(HANDLE PortHandle, PPORT_MESSAGE Message, ULONG Index, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);

#define QUERY_INFORMATION_PORT 0x99
NTSTATUS newZwQueryInformationPort(HANDLE PortHandle, PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG PortInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryInformationPortPtr)(HANDLE PortHandle, PORT_INFORMATION_CLASS PortInformationClass, PVOID PortInformation, ULONG PortInformationLength, PULONG ReturnLength);

#define IMPERSONATE_CLIENT_OF_PORT 0x5A
NTSTATUS newZwImpersonateClientOfPort(HANDLE PortHandle, PPORT_MESSAGE Message);
typedef NTSTATUS (*ZwImpersonateClientOfPortPtr)(HANDLE PortHandle, PPORT_MESSAGE Message);

#define CREATE_PROCESS 0x2F
NTSTATUS newZwCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort);
typedef NTSTATUS (*ZwCreateProcessPtr)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort);

#define CREATE_PROCESS_EX 0x30
NTSTATUS newZwCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES oa, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, DWORD arg9);
typedef NTSTATUS (*ZwCreateProcessExPtr)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES oa, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, DWORD arg9);

#define OPEN_PROCESS 0x7A
NTSTATUS newZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS (*ZwOpenProcessPtr)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

#define TERMINATE_PROCESS 0x101
NTSTATUS newZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS (*ZwTerminateProcessPtr)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

#define CREATE_THREAD 0x35
NTSTATUS newZwCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PUSER_STACK UserStack, BOOLEAN CreateSuspended);
typedef NTSTATUS (*ZwCreateThreadPtr)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PUSER_STACK UserStack, BOOLEAN CreateSuspended);

#define OPEN_THREAD 0x80
NTSTATUS newZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS (*ZwOpenThreadPtr)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

#define TERMINATE_THREAD 0x102
NTSTATUS newZwTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);
typedef NTSTATUS (*ZwTerminateThreadPtr)(HANDLE ThreadHandle, NTSTATUS ExitStatus);

#define QUERY_INFORMATION_THREAD 0x9B
NTSTATUS newZwQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryInformationThreadPtr)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

#define SET_INFORMATION_THREAD 0xE5
NTSTATUS newZwSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
typedef NTSTATUS (*ZwSetInformationThreadPtr)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);

#define SUSPEND_THREAD 0xFE
NTSTATUS newZwSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS (*ZwSuspendThreadPtr)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

#define RESUME_THREAD 0xCE
NTSTATUS newZwResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS (*ZwResumeThreadPtr)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

#define QUEUE_APC_THREAD 0xB4
NTSTATUS newZwQueueApcThread(HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2);
typedef NTSTATUS (*ZwQueueApcThreadPtr)(HANDLE ThreadHandle, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2);

#define TEST_ALERT 0x103
NTSTATUS newZwTestAlert();
typedef NTSTATUS (*ZwTestAlertPtr)();

#define ALERT_THREAD 0x0D
NTSTATUS newZwAlertThread(HANDLE ThreadHandle);
typedef NTSTATUS (*ZwAlertThreadPtr)(HANDLE ThreadHandle);

#define ALERT_RESUME_THREAD 0x0C
NTSTATUS newZwAlertResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS (*ZwAlertResumeThreadPtr)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

#define REGISTER_THREAD_TERMINATE_PORT 0xBB
NTSTATUS newZwRegisterThreadTerminatePort(HANDLE PortHandle);
typedef NTSTATUS (*ZwRegisterThreadTerminatePortPtr)(HANDLE PortHandle);

#define IMPERSONATE_THREAD 0x5B
NTSTATUS newZwImpersonateThread(HANDLE ThreadHandle, HANDLE TargetThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQos);
typedef NTSTATUS (*ZwImpersonateThreadPtr)(HANDLE ThreadHandle, HANDLE TargetThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQos);

#define IMPERSONATE_ANONYMOUS_TOKEN 0x59
NTSTATUS newZwImpersonateAnonymousToken(HANDLE ThreadHandle);
typedef NTSTATUS (*ZwImpersonateAnonymousTokenPtr)(HANDLE ThreadHandle);

#define QUERY_SYSTEM_ENVIRONMENT_VALUE 0xAB
NTSTATUS newZwQuerySystemEnvironmentValue(PUNICODE_STRING Name, PVOID Value, ULONG ValueLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQuerySystemEnvironmentValuePtr)(PUNICODE_STRING Name, PVOID Value, ULONG ValueLength, PULONG ReturnLength);

#define QUERY_SYSTEM_ENVIRONMENT_VALUE_EX 0xAC
NTSTATUS newZwQuerySystemEnvironmentValueEx(PUNICODE_STRING name, LPGUID vendor, PVOID value, PULONG retlength, PULONG attrib);
typedef NTSTATUS (*ZwQuerySystemEnvironmentValueExPtr)(PUNICODE_STRING name, LPGUID vendor, PVOID value, PULONG retlength, PULONG attrib);

#define SET_SYSTEM_ENVIRONMENT_VALUE 0xEE
NTSTATUS newZwSetSystemEnvironmentValue(PUNICODE_STRING Name, PUNICODE_STRING Value);
typedef NTSTATUS (*ZwSetSystemEnvironmentValuePtr)(PUNICODE_STRING Name, PUNICODE_STRING Value);

#define SET_SYSTEM_ENVIRONMENT_VALUE_EX 0xEF
NTSTATUS newZwSetSystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, ULONG ValueLength, ULONG Attributes);;
typedef NTSTATUS (*ZwSetSystemEnvironmentValueExPtr)(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, ULONG ValueLength, ULONG Attributes);;

#define SHUTDOWN_SYSTEM 0xF9
NTSTATUS newZwShutdownSystem(SHUTDOWN_ACTION Action);
typedef NTSTATUS (*ZwShutdownSystemPtr)(SHUTDOWN_ACTION Action);

#define SYSTEM_DEBUG_CONTROL 0xFF
NTSTATUS newZwSystemDebugControl(DEBUG_CONTROL_CODE ControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwSystemDebugControlPtr)(DEBUG_CONTROL_CODE ControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

#define QUERY_OBJECT 0xA3
NTSTATUS newZwQueryObject(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryObjectPtr)(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

#define SET_INFORMATION_OBJECT 0xE3
NTSTATUS newZwSetInformationObject(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength);
typedef NTSTATUS (*ZwSetInformationObjectPtr)(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength);

#define DUPLICATE_OBJECT 0x44
NTSTATUS newZwDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);
typedef NTSTATUS (*ZwDuplicateObjectPtr)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);

#define MAKE_TEMPORARY_OBJECT 0x69
NTSTATUS newZwMakeTemporaryObject(HANDLE Handle);
typedef NTSTATUS (*ZwMakeTemporaryObjectPtr)(HANDLE Handle);

#define SET_SECURITY_OBJECT 0xED
NTSTATUS newZwSetSecurityObject(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor);
typedef NTSTATUS (*ZwSetSecurityObjectPtr)(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor);

#define CREATE_DIRECTORY_OBJECT 0x22
NTSTATUS newZwCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwCreateDirectoryObjectPtr)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define OPEN_DIRECTORY_OBJECT 0x71
NTSTATUS newZwOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenDirectoryObjectPtr)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define QUERY_DIRECTORY_OBJECT 0x92
NTSTATUS newZwQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG BufferLength, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryDirectoryObjectPtr)(HANDLE DirectoryHandle, PVOID Buffer, ULONG BufferLength, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);

#define CREATE_SYMBOLIC_LINK_OBJECT 0x34
NTSTATUS newZwCreateSymbolicLinkObject(PHANDLE SymbolicLinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING TargetName);
typedef NTSTATUS (*ZwCreateSymbolicLinkObjectPtr)(PHANDLE SymbolicLinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING TargetName);

#define OPEN_SYMBOLIC_LINK_OBJECT 0x7F
NTSTATUS newZwOpenSymbolicLinkObject(PHANDLE SymbolicLinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenSymbolicLinkObjectPtr)(PHANDLE SymbolicLinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define QUERY_SYMBOLIC_LINK_OBJECT 0xAA
NTSTATUS newZwQuerySymbolicLinkObject(HANDLE SymbolicLinkHandle, PUNICODE_STRING TargetName, PULONG ReturnLength);
typedef NTSTATUS (*ZwQuerySymbolicLinkObjectPtr)(HANDLE SymbolicLinkHandle, PUNICODE_STRING TargetName, PULONG ReturnLength);

#define CREATE_SECTION 0x32
NTSTATUS newZwCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER SectionSize, ULONG Protect, ULONG Attributes, HANDLE FileHandle);
typedef NTSTATUS (*ZwCreateSectionPtr)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER SectionSize, ULONG Protect, ULONG Attributes, HANDLE FileHandle);

#define QUERY_SECTION 0xA7
NTSTATUS newZwQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS SectionInformationClass, PVOID SectionInformation, ULONG SectionInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwQuerySectionPtr)(HANDLE SectionHandle, SECTION_INFORMATION_CLASS SectionInformationClass, PVOID SectionInformation, ULONG SectionInformationLength, PULONG ResultLength);

#define EXTEND_SECTION 0x4A
NTSTATUS newZwExtendSection(HANDLE SectionHandle, PLARGE_INTEGER SectionSize);
typedef NTSTATUS (*ZwExtendSectionPtr)(HANDLE SectionHandle, PLARGE_INTEGER SectionSize);

#define UNMAP_VIEW_OF_SECTION 0x10B
NTSTATUS newZwUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS (*ZwUnmapViewOfSectionPtr)(HANDLE ProcessHandle, PVOID BaseAddress);

#define ARE_MAPPED_FILES_THE_SAME 0x12
NTSTATUS newZwAreMappedFilesTheSame(PVOID Address1, PVOID Address2);
typedef NTSTATUS (*ZwAreMappedFilesTheSamePtr)(PVOID Address1, PVOID Address2);

#define CREATE_JOB_OBJECT 0x27
NTSTATUS newZwCreateJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwCreateJobObjectPtr)(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define OPEN_JOB_OBJECT 0x76
NTSTATUS newZwOpenJobObject(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenJobObjectPtr)(PHANDLE JobHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define TERMINATE_JOB_OBJECT 0x100
NTSTATUS newZwTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus);
typedef NTSTATUS (*ZwTerminateJobObjectPtr)(HANDLE JobHandle, NTSTATUS ExitStatus);

#define ASSIGN_PROCESS_TO_JOB_OBJECT 0x13
NTSTATUS newZwAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle);
typedef NTSTATUS (*ZwAssignProcessToJobObjectPtr)(HANDLE JobHandle, HANDLE ProcessHandle);

#define QUERY_INFORMATION_JOB_OBJECT 0x98
NTSTATUS newZwQueryInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass, PVOID JobInformation, ULONG JobInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryInformationJobObjectPtr)(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass, PVOID JobInformation, ULONG JobInformationLength, PULONG ReturnLength);

#define SET_INFORMATION_JOB_OBJECT 0xE1
NTSTATUS newZwSetInformationJobObject(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass, PVOID JobInformation, ULONG JobInformationLength);
typedef NTSTATUS (*ZwSetInformationJobObjectPtr)(HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass, PVOID JobInformation, ULONG JobInformationLength);

#define CREATE_TOKEN 0x37
NTSTATUS newZwCreateToken(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE Type, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime, PTOKEN_USER User, PTOKEN_GROUPS Groups, PTOKEN_PRIVILEGES Privileges, PTOKEN_OWNER Owner, PTOKEN_PRIMARY_GROUP PrimaryGroup, PTOKEN_DEFAULT_DACL DefaultDacl, PTOKEN_SOURCE Source);
typedef NTSTATUS (*ZwCreateTokenPtr)(PHANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TOKEN_TYPE Type, PLUID AuthenticationId, PLARGE_INTEGER ExpirationTime, PTOKEN_USER User, PTOKEN_GROUPS Groups, PTOKEN_PRIVILEGES Privileges, PTOKEN_OWNER Owner, PTOKEN_PRIMARY_GROUP PrimaryGroup, PTOKEN_DEFAULT_DACL DefaultDacl, PTOKEN_SOURCE Source);

#define OPEN_PROCESS_TOKEN 0x7B
NTSTATUS newZwOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
typedef NTSTATUS (*ZwOpenProcessTokenPtr)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);

#define OPEN_PROCESS_TOKEN_EX 0x7C
NTSTATUS newZwOpenProcessTokenEx(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle);
typedef NTSTATUS (*ZwOpenProcessTokenExPtr)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle);

#define DUPLICATE_TOKEN 0x45
NTSTATUS newZwDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);
typedef NTSTATUS (*ZwDuplicateTokenPtr)(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);

#define FILTER_TOKEN 0x4B
NTSTATUS newZwFilterToken(HANDLE ExistingTokenHandle, ULONG Flags, PTOKEN_GROUPS SidsToDisable, PTOKEN_PRIVILEGES PrivilegesToDelete, PTOKEN_GROUPS SidsToRestricted, PHANDLE NewTokenHandle);
typedef NTSTATUS (*ZwFilterTokenPtr)(HANDLE ExistingTokenHandle, ULONG Flags, PTOKEN_GROUPS SidsToDisable, PTOKEN_PRIVILEGES PrivilegesToDelete, PTOKEN_GROUPS SidsToRestricted, PHANDLE NewTokenHandle);

#define ADJUST_PRIVILEGES_TOKEN 0x0B
NTSTATUS newZwAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);
typedef NTSTATUS (*ZwAdjustPrivilegesTokenPtr)(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);

#define ADJUST_GROUPS_TOKEN 0x0A
NTSTATUS newZwAdjustGroupsToken(HANDLE TokenHandle, BOOLEAN ResetToDefault, PTOKEN_GROUPS NewState, ULONG BufferLength, PTOKEN_GROUPS PreviousState, PULONG ReturnLength);
typedef NTSTATUS (*ZwAdjustGroupsTokenPtr)(HANDLE TokenHandle, BOOLEAN ResetToDefault, PTOKEN_GROUPS NewState, ULONG BufferLength, PTOKEN_GROUPS PreviousState, PULONG ReturnLength);

#define SET_INFORMATION_TOKEN 0xE6
NTSTATUS newZwSetInformationToken(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength);
typedef NTSTATUS (*ZwSetInformationTokenPtr)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength);

#define SIGNAL_AND_WAIT_FOR_SINGLE_OBJECT 0xFA
NTSTATUS newZwSignalAndWaitForSingleObject(HANDLE HandleToSignal, HANDLE HandleToWait, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS (*ZwSignalAndWaitForSingleObjectPtr)(HANDLE HandleToSignal, HANDLE HandleToWait, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

#define WAIT_FOR_MULTIPLE_OBJECTS 0x10E
NTSTATUS newZwWaitForMultipleObjects(ULONG HandleCount, PHANDLE Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS (*ZwWaitForMultipleObjectsPtr)(ULONG HandleCount, PHANDLE Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

#define CREATE_TIMER 0x36
NTSTATUS newZwCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType);
typedef NTSTATUS (*ZwCreateTimerPtr)(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType);

#define OPEN_TIMER 0x83
NTSTATUS newZwOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenTimerPtr)(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define CANCEL_TIMER 0x17
NTSTATUS newZwCancelTimer(HANDLE TimerHandle, PBOOLEAN PreviousState);
typedef NTSTATUS (*ZwCancelTimerPtr)(HANDLE TimerHandle, PBOOLEAN PreviousState);

#define SET_TIMER 0xF4
NTSTATUS newZwSetTimer(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext, BOOLEAN Resume, LONG Period, PBOOLEAN PreviousState);
typedef NTSTATUS (*ZwSetTimerPtr)(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext, BOOLEAN Resume, LONG Period, PBOOLEAN PreviousState);

#define QUERY_TIMER 0xAF
NTSTATUS newZwQueryTimer(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass, PVOID TimerInformation, ULONG TimerInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwQueryTimerPtr)(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass, PVOID TimerInformation, ULONG TimerInformationLength, PULONG ResultLength);

#define CREATE_EVENT 0x23
NTSTATUS newZwCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);
typedef NTSTATUS (*ZwCreateEventPtr)(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);

#define OPEN_EVENT 0x72
NTSTATUS newZwOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenEventPtr)(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define PULSE_EVENT 0x8A
NTSTATUS newZwPulseEvent(HANDLE EventHandle, PULONG PreviousState);
typedef NTSTATUS (*ZwPulseEventPtr)(HANDLE EventHandle, PULONG PreviousState);

#define RESET_EVENT 0xCA
NTSTATUS newZwResetEvent(HANDLE EventHandle, PULONG PreviousState);
typedef NTSTATUS (*ZwResetEventPtr)(HANDLE EventHandle, PULONG PreviousState);

#define CLEAR_EVENT 0x18
NTSTATUS newZwClearEvent(HANDLE EventHandle);
typedef NTSTATUS (*ZwClearEventPtr)(HANDLE EventHandle);

#define QUERY_EVENT 0x94
NTSTATUS newZwQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass, PVOID EventInformation, ULONG EventInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwQueryEventPtr)(HANDLE EventHandle, EVENT_INFORMATION_CLASS EventInformationClass, PVOID EventInformation, ULONG EventInformationLength, PULONG ResultLength);

#define CREATE_SEMAPHORE 0x33
NTSTATUS newZwCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount, LONG MaximumCount);
typedef NTSTATUS (*ZwCreateSemaphorePtr)(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount, LONG MaximumCount);

#define OPEN_SEMAPHORE 0x7E
NTSTATUS newZwOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenSemaphorePtr)(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define RELEASE_SEMAPHORE 0xBD
NTSTATUS newZwReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount);
typedef NTSTATUS (*ZwReleaseSemaphorePtr)(HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount);

#define QUERY_SEMAPHORE 0xA9
NTSTATUS newZwQuerySemaphore(HANDLE SemaphoreHandle, SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass, PVOID SemaphoreInformation, ULONG SemaphoreInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwQuerySemaphorePtr)(HANDLE SemaphoreHandle, SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass, PVOID SemaphoreInformation, ULONG SemaphoreInformationLength, PULONG ResultLength);

#define CREATE_MUTANT 0x2B
NTSTATUS newZwCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner);
typedef NTSTATUS (*ZwCreateMutantPtr)(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner);

#define OPEN_MUTANT 0x78
NTSTATUS newZwOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenMutantPtr)(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define RELEASE_MUTANT 0xBC
NTSTATUS newZwReleaseMutant(HANDLE MutantHandle, PULONG PreviousState);
typedef NTSTATUS (*ZwReleaseMutantPtr)(HANDLE MutantHandle, PULONG PreviousState);

#define QUERY_MUTANT 0xA2
NTSTATUS newZwQueryMutant(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass, PVOID MutantInformation, ULONG MutantInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwQueryMutantPtr)(HANDLE MutantHandle, MUTANT_INFORMATION_CLASS MutantInformationClass, PVOID MutantInformation, ULONG MutantInformationLength, PULONG ResultLength);

#define CREATE_IO_COMPLETION 0x26
NTSTATUS newZwCreateIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG NumberOfConcurrentThreads);
typedef NTSTATUS (*ZwCreateIoCompletionPtr)(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG NumberOfConcurrentThreads);

#define OPEN_IO_COMPLETION 0x75
NTSTATUS newZwOpenIoCompletion(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenIoCompletionPtr)(PHANDLE IoCompletionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define SET_IO_COMPLETION 0xE8
NTSTATUS newZwSetIoCompletion(HANDLE IoCompletionHandle, ULONG CompletionKey, ULONG CompletionValue, NTSTATUS Status, ULONG Information);
typedef NTSTATUS (*ZwSetIoCompletionPtr)(HANDLE IoCompletionHandle, ULONG CompletionKey, ULONG CompletionValue, NTSTATUS Status, ULONG Information);

#define REMOVE_IO_COMPLETION 0xBE
NTSTATUS newZwRemoveIoCompletion(HANDLE IoCompletionHandle, PULONG CompletionKey, PULONG CompletionValue, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER Timeout);
typedef NTSTATUS (*ZwRemoveIoCompletionPtr)(HANDLE IoCompletionHandle, PULONG CompletionKey, PULONG CompletionValue, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER Timeout);

#define QUERY_IO_COMPLETION 0x9F
NTSTATUS newZwQueryIoCompletion(HANDLE IoCompletionHandle, IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass, PVOID IoCompletionInformation, ULONG IoCompletionInformationLength, PULONG ResultLength);
typedef NTSTATUS (*ZwQueryIoCompletionPtr)(HANDLE IoCompletionHandle, IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass, PVOID IoCompletionInformation, ULONG IoCompletionInformationLength, PULONG ResultLength);

#define CREATE_EVENT_PAIR 0x24
NTSTATUS newZwCreateEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwCreateEventPairPtr)(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define OPEN_EVENT_PAIR 0x73
NTSTATUS newZwOpenEventPair(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS (*ZwOpenEventPairPtr)(PHANDLE EventPairHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

#define WAIT_LOW_EVENT_PAIR 0x111
NTSTATUS newZwWaitLowEventPair(HANDLE EventPairHandle);
typedef NTSTATUS (*ZwWaitLowEventPairPtr)(HANDLE EventPairHandle);

#define WAIT_HIGH_EVENT_PAIR 0x110
NTSTATUS newZwWaitHighEventPair(HANDLE EventPairHandle);
typedef NTSTATUS (*ZwWaitHighEventPairPtr)(HANDLE EventPairHandle);

#define SET_LOW_WAIT_HIGH_EVENT_PAIR 0xEB
NTSTATUS newZwSetLowWaitHighEventPair(HANDLE EventPairHandle);
typedef NTSTATUS (*ZwSetLowWaitHighEventPairPtr)(HANDLE EventPairHandle);

#define SET_HIGH_WAIT_LOW_EVENT_PAIR 0xDE
NTSTATUS newZwSetHighWaitLowEventPair(HANDLE EventPairHandle);
typedef NTSTATUS (*ZwSetHighWaitLowEventPairPtr)(HANDLE EventPairHandle);

#define SET_LOW_EVENT_PAIR 0xEA
NTSTATUS newZwSetLowEventPair(HANDLE EventPairHandle);
typedef NTSTATUS (*ZwSetLowEventPairPtr)(HANDLE EventPairHandle);

#define SET_HIGH_EVENT_PAIR 0xDD
NTSTATUS newZwSetHighEventPair(HANDLE EventPairHandle);
typedef NTSTATUS (*ZwSetHighEventPairPtr)(HANDLE EventPairHandle);

#define SET_SYSTEM_TIME 0xF2
NTSTATUS newZwSetSystemTime(PLARGE_INTEGER NewTime, PLARGE_INTEGER OldTime);
typedef NTSTATUS (*ZwSetSystemTimePtr)(PLARGE_INTEGER NewTime, PLARGE_INTEGER OldTime);

#define QUERY_PERFORMANCE_COUNTER 0xA5
NTSTATUS newZwQueryPerformanceCounter(PLARGE_INTEGER PerformanceCount, PLARGE_INTEGER PerformanceFrequency);
typedef NTSTATUS (*ZwQueryPerformanceCounterPtr)(PLARGE_INTEGER PerformanceCount, PLARGE_INTEGER PerformanceFrequency);

#define SET_TIMER_RESOLUTION 0xF5
NTSTATUS newZwSetTimerResolution(ULONG RequestedResolution, BOOLEAN Set, PULONG ActualResolution);
typedef NTSTATUS (*ZwSetTimerResolutionPtr)(ULONG RequestedResolution, BOOLEAN Set, PULONG ActualResolution);

#define QUERY_TIMER_RESOLUTION 0xB0
NTSTATUS newZwQueryTimerResolution(PULONG CoarsestResolution, PULONG FinestResolution, PULONG ActualResolution);
typedef NTSTATUS (*ZwQueryTimerResolutionPtr)(PULONG CoarsestResolution, PULONG FinestResolution, PULONG ActualResolution);

#define YIELD_EXECUTION 0x116
NTSTATUS newZwYieldExecution();
typedef NTSTATUS (*ZwYieldExecutionPtr)();

#define SET_INTERVAL_PROFILE 0xE7
NTSTATUS newZwSetIntervalProfile(ULONG Interval, KPROFILE_SOURCE Source);
typedef NTSTATUS (*ZwSetIntervalProfilePtr)(ULONG Interval, KPROFILE_SOURCE Source);

#define QUERY_INTERVAL_PROFILE 0x9E
NTSTATUS newZwQueryIntervalProfile(KPROFILE_SOURCE Source, PULONG Interval);
typedef NTSTATUS (*ZwQueryIntervalProfilePtr)(KPROFILE_SOURCE Source, PULONG Interval);

#define STOP_PROFILE 0xFC
NTSTATUS newZwStopProfile(HANDLE ProfileHandle);
typedef NTSTATUS (*ZwStopProfilePtr)(HANDLE ProfileHandle);

#define PRIVILEGE_CHECK 0x86
NTSTATUS newZwPrivilegeCheck(HANDLE TokenHandle, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result);
typedef NTSTATUS (*ZwPrivilegeCheckPtr)(HANDLE TokenHandle, PPRIVILEGE_SET RequiredPrivileges, PBOOLEAN Result);

#define PRIVILEGE_OBJECT_AUDIT_ALARM 0x87
NTSTATUS newZwPrivilegeObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE TokenHandle, ACCESS_MASK DesiredAccess, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted);
typedef NTSTATUS (*ZwPrivilegeObjectAuditAlarmPtr)(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE TokenHandle, ACCESS_MASK DesiredAccess, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted);

#define PRIVILEGED_SERVICE_AUDIT_ALARM 0x88
NTSTATUS newZwPrivilegedServiceAuditAlarm(PUNICODE_STRING SubsystemName, PUNICODE_STRING ServiceName, HANDLE TokenHandle, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted);
typedef NTSTATUS (*ZwPrivilegedServiceAuditAlarmPtr)(PUNICODE_STRING SubsystemName, PUNICODE_STRING ServiceName, HANDLE TokenHandle, PPRIVILEGE_SET Privileges, BOOLEAN AccessGranted);

#define ACCESS_CHECK_BY_TYPE 0x03
NTSTATUS newZwAccessCheckByType(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE TokenHandle, ULONG DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PULONG AccessStatus);
typedef NTSTATUS (*ZwAccessCheckByTypePtr)(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE TokenHandle, ULONG DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength, PACCESS_MASK GrantedAccess, PULONG AccessStatus);

#define ACCESS_CHECK_BY_TYPE_AND_AUDIT_ALARM 0x04
NTSTATUS newZwAccessCheckByTypeAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PULONG AccessStatus, PBOOLEAN GenerateOnClose);
typedef NTSTATUS (*ZwAccessCheckByTypeAndAuditAlarmPtr)(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccess, PULONG AccessStatus, PBOOLEAN GenerateOnClose);

#define ACCESS_CHECK_BY_TYPE_RESULT_LIST 0x05
NTSTATUS newZwAccessCheckByTypeResultList(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength);
typedef NTSTATUS (*ZwAccessCheckByTypeResultListPtr)(PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, HANDLE TokenHandle, ACCESS_MASK DesiredAccess, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, PPRIVILEGE_SET PrivilegeSet, PULONG PrivilegeSetLength);

#define ACCESS_CHECK_BY_TYPE_RESULT_LIST_AND_AUDIT_ALARM 0x06
NTSTATUS newZwAccessCheckByTypeResultListAndAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccessList, PULONG AccessStatusList, PULONG GenerateOnClose);
typedef NTSTATUS (*ZwAccessCheckByTypeResultListAndAuditAlarmPtr)(PUNICODE_STRING SubsystemName, PVOID HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccessList, PULONG AccessStatusList, PULONG GenerateOnClose);

#define ACCESS_CHECK_BY_TYPE_RESULT_LIST_AND_AUDIT_ALARM_BY_HANDLE 0x07
NTSTATUS newZwAccessCheckByTypeResultListAndAuditAlarmByHandle(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE TokenHandle, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccessList, PULONG AccessStatusList, PULONG GenerateOnClose);
typedef NTSTATUS (*ZwAccessCheckByTypeResultListAndAuditAlarmByHandlePtr)(PUNICODE_STRING SubsystemName, PVOID HandleId, HANDLE TokenHandle, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, PSID PrincipalSelfSid, ACCESS_MASK DesiredAccess, AUDIT_EVENT_TYPE AuditType, ULONG Flags, POBJECT_TYPE_LIST ObjectTypeList, ULONG ObjectTypeListLength, PGENERIC_MAPPING GenericMapping, BOOLEAN ObjectCreation, PACCESS_MASK GrantedAccessList, PULONG AccessStatusList, PULONG GenerateOnClose);

#define OPEN_OBJECT_AUDIT_ALARM 0x79
NTSTATUS newZwOpenObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID *HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE TokenHandle, ACCESS_MASK DesiredAccess, ACCESS_MASK GrantedAccess, PPRIVILEGE_SET Privileges, BOOLEAN ObjectCreation, BOOLEAN AccessGranted, PBOOLEAN GenerateOnClose);
typedef NTSTATUS (*ZwOpenObjectAuditAlarmPtr)(PUNICODE_STRING SubsystemName, PVOID *HandleId, PUNICODE_STRING ObjectTypeName, PUNICODE_STRING ObjectName, PSECURITY_DESCRIPTOR SecurityDescriptor, HANDLE TokenHandle, ACCESS_MASK DesiredAccess, ACCESS_MASK GrantedAccess, PPRIVILEGE_SET Privileges, BOOLEAN ObjectCreation, BOOLEAN AccessGranted, PBOOLEAN GenerateOnClose);

#define CLOSE_OBJECT_AUDIT_ALARM 0x1A
NTSTATUS newZwCloseObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose);
typedef NTSTATUS (*ZwCloseObjectAuditAlarmPtr)(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose);

#define DELETE_OBJECT_AUDIT_ALARM 0x40
NTSTATUS newZwDeleteObjectAuditAlarm(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose);
typedef NTSTATUS (*ZwDeleteObjectAuditAlarmPtr)(PUNICODE_STRING SubsystemName, PVOID HandleId, BOOLEAN GenerateOnClose);

#define REQUEST_WAKEUP_LATENCY 0xC9
NTSTATUS newZwRequestWakeupLatency(LATENCY_TIME Latency);
typedef NTSTATUS (*ZwRequestWakeupLatencyPtr)(LATENCY_TIME Latency);

#define REQUEST_DEVICE_WAKEUP 0xC6
NTSTATUS newZwRequestDeviceWakeup(HANDLE DeviceHandle);
typedef NTSTATUS (*ZwRequestDeviceWakeupPtr)(HANDLE DeviceHandle);

#define CANCEL_DEVICE_WAKEUP_REQUEST 0x15
NTSTATUS newZwCancelDeviceWakeupRequest(HANDLE DeviceHandle);
typedef NTSTATUS (*ZwCancelDeviceWakeupRequestPtr)(HANDLE DeviceHandle);

#define IS_SYSTEM_RESUME_AUTOMATIC 0x5F
NTSTATUS newZwIsSystemResumeAutomatic();
typedef NTSTATUS (*ZwIsSystemResumeAutomaticPtr)();

#define SET_THREAD_EXECUTION_STATE 0xF3
NTSTATUS newZwSetThreadExecutionState(EXECUTION_STATE ExecutionState, PEXECUTION_STATE PreviousExecutionState);
typedef NTSTATUS (*ZwSetThreadExecutionStatePtr)(EXECUTION_STATE ExecutionState, PEXECUTION_STATE PreviousExecutionState);

#define GET_DEVICE_POWER_STATE 0x56
NTSTATUS newZwGetDevicePowerState(HANDLE DeviceHandle, PDEVICE_POWER_STATE DevicePowerState);
typedef NTSTATUS (*ZwGetDevicePowerStatePtr)(HANDLE DeviceHandle, PDEVICE_POWER_STATE DevicePowerState);

#define SET_SYSTEM_POWER_STATE 0xF1
NTSTATUS newZwSetSystemPowerState(POWER_ACTION SystemAction, SYSTEM_POWER_STATE MinSystemState, ULONG Flags);
typedef NTSTATUS (*ZwSetSystemPowerStatePtr)(POWER_ACTION SystemAction, SYSTEM_POWER_STATE MinSystemState, ULONG Flags);

#define INITIATE_POWER_ACTION 0x5D
NTSTATUS newZwInitiatePowerAction(POWER_ACTION SystemAction, SYSTEM_POWER_STATE MinSystemState, ULONG Flags, BOOLEAN Asynchronous);
typedef NTSTATUS (*ZwInitiatePowerActionPtr)(POWER_ACTION SystemAction, SYSTEM_POWER_STATE MinSystemState, ULONG Flags, BOOLEAN Asynchronous);

#define POWER_INFORMATION 0x85
NTSTATUS newZwPowerInformation(POWER_INFORMATION_LEVEL PowerInformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
typedef NTSTATUS (*ZwPowerInformationPtr)(POWER_INFORMATION_LEVEL PowerInformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

#define RAISE_EXCEPTION 0xB5
NTSTATUS newZwRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context, BOOLEAN SearchFrames);
typedef NTSTATUS (*ZwRaiseExceptionPtr)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context, BOOLEAN SearchFrames);
/**
#define CONTINUE 0x20
NTSTATUS newZwContinue(PCONTEXT Context, BOOLEAN TestAlert);
typedef NTSTATUS (*ZwContinuePtr)(PCONTEXT Context, BOOLEAN TestAlert);*/

#define CALLBACK_RETURN 0x14
NTSTATUS newZwCallbackReturn(PVOID Result, ULONG ResultLength, NTSTATUS Status);
typedef NTSTATUS (*ZwCallbackReturnPtr)(PVOID Result, ULONG ResultLength, NTSTATUS Status);

#define LOAD_DRIVER 0x61
NTSTATUS newZwLoadDriver(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS (*ZwLoadDriverPtr)(PUNICODE_STRING DriverServiceName);

#define UNLOAD_DRIVER 0x106
NTSTATUS newZwUnloadDriver(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS (*ZwUnloadDriverPtr)(PUNICODE_STRING DriverServiceName);

#define FLUSH_WRITE_BUFFER 0x51
NTSTATUS newZwFlushWriteBuffer();
typedef NTSTATUS (*ZwFlushWriteBufferPtr)();

#define SET_DEFAULT_LOCALE 0xD8
NTSTATUS newZwSetDefaultLocale(BOOLEAN ThreadOrSystem, LCID Locale);
typedef NTSTATUS (*ZwSetDefaultLocalePtr)(BOOLEAN ThreadOrSystem, LCID Locale);

#define QUERY_DEFAULT_UI_LANGUAGE 0x90
NTSTATUS newZwQueryDefaultUILanguage(PLANGID LanguageId);
typedef NTSTATUS (*ZwQueryDefaultUILanguagePtr)(PLANGID LanguageId);

#define SET_DEFAULT_UI_LANGUAGE 0xD9
NTSTATUS newZwSetDefaultUILanguage(LANGID LanguageId);
typedef NTSTATUS (*ZwSetDefaultUILanguagePtr)(LANGID LanguageId);

#define QUERY_INSTALL_UI_LANGUAGE 0x9D
NTSTATUS newZwQueryInstallUILanguage(PLANGID LanguageId);
typedef NTSTATUS (*ZwQueryInstallUILanguagePtr)(PLANGID LanguageId);

#define ALLOCATE_LOCALLY_UNIQUE_ID 0x0E
NTSTATUS newZwAllocateLocallyUniqueId(PLUID Luid);
typedef NTSTATUS (*ZwAllocateLocallyUniqueIdPtr)(PLUID Luid);

#define ALLOCATE_UUIDS 0x10
NTSTATUS newZwAllocateUuids(PLARGE_INTEGER UuidLastTimeAllocated, PULONG UuidDeltaTime, PULONG UuidSequenceNumber, PUCHAR UuidSeed);
typedef NTSTATUS (*ZwAllocateUuidsPtr)(PLARGE_INTEGER UuidLastTimeAllocated, PULONG UuidDeltaTime, PULONG UuidSequenceNumber, PUCHAR UuidSeed);

#define SET_UUID_SEED 0xF6
NTSTATUS newZwSetUuidSeed(PUCHAR UuidSeed);
typedef NTSTATUS (*ZwSetUuidSeedPtr)(PUCHAR UuidSeed);

#define RAISE_HARD_ERROR 0xB6
NTSTATUS newZwRaiseHardError(NTSTATUS Status, ULONG NumberOfArguments, ULONG StringArgumentsMask, PULONG Arguments, HARDERROR_RESPONSE_OPTION ResponseOption, PHARDERROR_RESPONSE Response);
typedef NTSTATUS (*ZwRaiseHardErrorPtr)(NTSTATUS Status, ULONG NumberOfArguments, ULONG StringArgumentsMask, PULONG Arguments, HARDERROR_RESPONSE_OPTION ResponseOption, PHARDERROR_RESPONSE Response);

#define SET_DEFAULT_HARD_ERROR_PORT 0xD7
NTSTATUS newZwSetDefaultHardErrorPort(HANDLE PortHandle);
typedef NTSTATUS (*ZwSetDefaultHardErrorPortPtr)(HANDLE PortHandle);

#define DISPLAY_STRING 0x43
NTSTATUS newZwDisplayString(PUNICODE_STRING String);
typedef NTSTATUS (*ZwDisplayStringPtr)(PUNICODE_STRING String);

#define CREATE_PAGING_FILE 0x2D
NTSTATUS newZwCreatePagingFile(PUNICODE_STRING FileName, PULARGE_INTEGER InitialSize, PULARGE_INTEGER MaximumSize, ULONG Reserved);
typedef NTSTATUS (*ZwCreatePagingFilePtr)(PUNICODE_STRING FileName, PULARGE_INTEGER InitialSize, PULARGE_INTEGER MaximumSize, ULONG Reserved);

#define ADD_ATOM 0x08
NTSTATUS newZwAddAtom(PWSTR String, ULONG StringLength, PUSHORT Atom);
typedef NTSTATUS (*ZwAddAtomPtr)(PWSTR String, ULONG StringLength, PUSHORT Atom);

#define FIND_ATOM 0x4C
NTSTATUS newZwFindAtom(PWSTR String, ULONG StringLength, PUSHORT Atom);
typedef NTSTATUS (*ZwFindAtomPtr)(PWSTR String, ULONG StringLength, PUSHORT Atom);

#define DELETE_ATOM 0x3C
NTSTATUS newZwDeleteAtom(USHORT Atom);
typedef NTSTATUS (*ZwDeleteAtomPtr)(USHORT Atom);

#define QUERY_INFORMATION_ATOM 0x96
NTSTATUS newZwQueryInformationAtom(USHORT Atom, ATOM_INFORMATION_CLASS AtomInformationClass, PVOID AtomInformation, ULONG AtomInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*ZwQueryInformationAtomPtr)(USHORT Atom, ATOM_INFORMATION_CLASS AtomInformationClass, PVOID AtomInformation, ULONG AtomInformationLength, PULONG ReturnLength);

#define SET_LDT_ENTRIES 0xE9
NTSTATUS newZwSetLdtEntries(ULONG Selector1, LDT_ENTRY LdtEntry1, ULONG Selector2, LDT_ENTRY LdtEntry2);
typedef NTSTATUS (*ZwSetLdtEntriesPtr)(ULONG Selector1, LDT_ENTRY LdtEntry1, ULONG Selector2, LDT_ENTRY LdtEntry2);

#define VDM_CONTROL 0x10C
NTSTATUS newZwVdmControl(ULONG ControlCode, PVOID ControlData);
typedef NTSTATUS (*ZwVdmControlPtr)(ULONG ControlCode, PVOID ControlData);

#define SET_BOOT_ENTRY_ORDER 0xD3
NTSTATUS newNtSetBootEntryOrder(PULONG Ids,PULONG Count);
typedef NTSTATUS (*NtSetBootEntryOrderPtr)(PULONG Ids,PULONG Count);

#define COMPACT_KEYS 0x1B
NTSTATUS newNtCompactKeys(ULONG NrOfKeys, HANDLE KeysArray[]);
typedef NTSTATUS (*NtCompactKeysPtr)(ULONG NrOfKeys, HANDLE KeysArray[]);

#define COMPARE_TOKENS 0x1C
NTSTATUS newNtCompareTokens(HANDLE FirstTokenHandle, HANDLE SecondTokenHandle, PBOOLEAN Equal);
typedef NTSTATUS (*NtCompareTokensPtr)(HANDLE FirstTokenHandle, HANDLE SecondTokenHandle, PBOOLEAN Equal);

#define COMPRESS_KEY 0x1E
NTSTATUS newNtCompressKey(HANDLE Key);
typedef NTSTATUS (*NtCompressKeyPtr)(HANDLE Key);

#define CREATE_DEBUG_OBJECT 0x21
NTSTATUS newNtCreateDebugObject(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);
typedef NTSTATUS (*NtCreateDebugObjectPtr)(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);

#define CREATE_JOB_SET 0x28
NTSTATUS newNtCreateJobSet(ULONG NumJob, PJOB_SET_ARRAY UserJobSet, ULONG Flags);
typedef NTSTATUS (*NtCreateJobSetPtr)(ULONG NumJob, PJOB_SET_ARRAY UserJobSet, ULONG Flags);

#define DEBUG_ACTIVE_PROCESS 0x39
NTSTATUS newNtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
typedef NTSTATUS (*NtDebugActiveProcessPtr)(HANDLE ProcessHandle, HANDLE DebugObjectHandle);

#define DEBUG_CONTINUE 0x3A
NTSTATUS newNtDebugContinue(HANDLE DebugObject, PCLIENT_ID AppClientId, NTSTATUS ContinueStatus);
typedef NTSTATUS (*NtDebugContinuePtr)(HANDLE DebugObject, PCLIENT_ID AppClientId, NTSTATUS ContinueStatus);

#define ENUMERATE_SYSTEM_ENVIRONMENT_VALUES_EX 0x48
NTSTATUS newNtEnumerateSystemEnvironmentValuesEx(ULONG InformationClass, PVOID Buffer, ULONG BufferLength);
typedef NTSTATUS (*NtEnumerateSystemEnvironmentValuesExPtr)(ULONG InformationClass, PVOID Buffer, ULONG BufferLength);

#define IS_PROCESS_IN_JOB 0x5E
NTSTATUS newNtIsProcessInJob(HANDLE ProcessHandle,HANDLE JobHandle);
typedef NTSTATUS (*NtIsProcessInJobPtr)(HANDLE ProcessHandle,HANDLE JobHandle);

#define LOCK_PRODUCT_ACTIVATION_KEYS 0x65
NTSTATUS newNtLockProductActivationKeys(PULONG pPrivateVer, PULONG pSafeMode);
typedef NTSTATUS (*NtLockProductActivationKeysPtr)(PULONG pPrivateVer, PULONG pSafeMode);

#define LOCK_REGISTRY_KEY 0x66
NTSTATUS newNtLockRegistryKey(HANDLE KeyHandle);
typedef NTSTATUS (*NtLockRegistryKeyPtr)(HANDLE KeyHandle);

#define MAKE_PERMANENT_OBJECT 0x68
NTSTATUS newNtMakePermanentObject(HANDLE ObjectHandle);
typedef NTSTATUS (*NtMakePermanentObjectPtr)(HANDLE ObjectHandle);

#define DELETE_BOOT_ENTRY 0x3D
NTSTATUS newNtDeleteBootEntry(ULONG Id);
typedef NTSTATUS (*NtDeleteBootEntryPtr)(ULONG Id);

#define QUERY_DEBUG_FILTER_STATE 0x8E
NTSTATUS newNtQueryDebugFilterState(ULONG ComponentId, ULONG Level);
typedef NTSTATUS (*NtQueryDebugFilterStatePtr)(ULONG ComponentId, ULONG Level);

#define REMOVE_PROCESS_DEBUG 0xBF
NTSTATUS newNtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
typedef NTSTATUS (*NtRemoveProcessDebugPtr)(HANDLE ProcessHandle, HANDLE DebugObjectHandle);

#define RENAME_KEY 0xC0
NTSTATUS newNtRenameKey(HANDLE KeyHandle, PUNICODE_STRING NewName);
typedef NTSTATUS (*NtRenameKeyPtr)(HANDLE KeyHandle, PUNICODE_STRING NewName);

#define RESUME_PROCESS 0xCD
NTSTATUS newNtResumeProcess(HANDLE ProcessHandle);
typedef NTSTATUS (*NtResumeProcessPtr)(HANDLE ProcessHandle);

#define SET_DEBUG_FILTER_STATE 0xD6
NTSTATUS newNtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State);
typedef NTSTATUS (*NtSetDebugFilterStatePtr)(ULONG ComponentId, ULONG Level, BOOLEAN State);

#define SET_EVENT_BOOST_PRIORITY 0xDC
NTSTATUS newNtSetEventBoostPriority(HANDLE EventHandle);
typedef NTSTATUS (*NtSetEventBoostPriorityPtr)(HANDLE EventHandle);

#define SET_INFORMATION_DEBUG_OBJECT 0xDF
NTSTATUS newNtSetInformationDebugObject(HANDLE DebugObjectHandle, DEBUGOBJECTINFOCLASS DebugObjectInformationClass, PVOID DebugInformation, ULONG DebugInformationLength, PULONG ReturnLength);
typedef NTSTATUS (*NtSetInformationDebugObjectPtr)(HANDLE DebugObjectHandle, DEBUGOBJECTINFOCLASS DebugObjectInformationClass, PVOID DebugInformation, ULONG DebugInformationLength, PULONG ReturnLength);

#define SUSPEND_PROCESS 0xFD
NTSTATUS newNtSuspendProcess(HANDLE Process);
typedef NTSTATUS (*NtSuspendProcessPtr)(HANDLE Process);

#define TRACE_EVENT 0x104
NTSTATUS newNtTraceEvent(HANDLE TraceHandle, ULONG Flags, ULONG FieldSize, PVOID Fields);
typedef NTSTATUS (*NtTraceEventPtr)(HANDLE TraceHandle, ULONG Flags, ULONG FieldSize, PVOID Fields);

#define TRANSLATE_FILE_PATH 0x105
NTSTATUS newNtTranslateFilePath(PFILE_PATH InputFilePath, ULONG OutputType, PFILE_PATH OutputFilePath, ULONG OutputFilePathLength);
typedef NTSTATUS (*NtTranslateFilePathPtr)(PFILE_PATH InputFilePath, ULONG OutputType, PFILE_PATH OutputFilePath, ULONG OutputFilePathLength);

#define WAIT_FOR_DEBUG_EVENT 0x10D
NTSTATUS newNtWaitForDebugEvent(HANDLE DebugObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout, PVOID WaitStateChange);
typedef NTSTATUS (*NtWaitForDebugEventPtr)(HANDLE DebugObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout, PVOID WaitStateChange);

#define CREATE_KEYED_EVENT 0x117
NTSTATUS newNtCreateKeyedEvent(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr, ULONG flags);
typedef NTSTATUS (*NtCreateKeyedEventPtr)(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr, ULONG flags);

#define OPEN_KEYED_EVENT 0x118
NTSTATUS newNtOpenKeyedEvent(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr);
typedef NTSTATUS (*NtOpenKeyedEventPtr)(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr);

#define RELEASE_KEYED_EVENT 0x119
NTSTATUS newNtReleaseKeyedEvent(HANDLE handle, PVOID key, BOOLEAN alertable, PLARGE_INTEGER mstimeout);
typedef NTSTATUS (*NtReleaseKeyedEventPtr)(HANDLE handle, PVOID key, BOOLEAN alertable, PLARGE_INTEGER mstimeout);

#define WAIT_FOR_KEYED_EVENT 0x11A
NTSTATUS newNtWaitForKeyedEvent(HANDLE handle, PVOID key, BOOLEAN alertable, PLARGE_INTEGER mstimeout);
typedef NTSTATUS (*NtWaitForKeyedEventPtr)(HANDLE handle, PVOID key, BOOLEAN alertable, PLARGE_INTEGER mstimeout);

#define QUERY_PORT_INFORMATION_PROCESS 0x11B
NTSTATUS newNtQueryPortInformationProcess();
typedef NTSTATUS (*NtQueryPortInformationProcessPtr)();


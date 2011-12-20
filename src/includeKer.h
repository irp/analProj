/* This stuff: minifilter object, functions prototypes */
#ifndef __INCLUDEKER_H__
#define __INCLUDEKER_H__

#include <fltKernel.h>
#include <dontuse.h>
#include <ntddk.h>

#include <suppress.h>
#include <structsKer.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Controllo PREfast non valido per filter driver")

typedef struct _STRUCT_MINIFILTER {

	PDRIVER_OBJECT DriverObject;
	PFLT_FILTER Filter;

	PFLT_PORT ServerPort;
	PFLT_PORT ClientPort;
	LIST_ENTRY Head;
	KSPIN_LOCK SpinLock;

	NPAGED_LOOKASIDE_LIST BufferAvailable;
	LONG MaxAllocation;
    __volatile LONG Allocated;  

	PVOID StaticBuffer[MAX_SPACE/sizeof(PVOID)];

	__volatile LONG UsingStaticBuffer;

	PEPROCESS Process;

}STRUCT_MINIFILTER, *PSTRUCT_MINIFILTER;

const _FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_STREAMHANDLE_CONTEXT,     
      0,
      NULL,
      MAXUSHORT, //sizeof(SCANNER_STREAM_HANDLE_CONTEXT),  
      'dump' },

    { FLT_CONTEXT_END }

};

extern "C" NTSTATUS NTAPI FilterUnload(
  __in FLT_FILTER_UNLOAD_FLAGS Flags
);

extern "C" NTSTATUS NTAPI InstanceSetupCallback(                            
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType);

extern "C" NTSTATUS NTAPI InstanceQueryTeardownCallback(                             
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags);

extern "C" FLT_PREOP_CALLBACK_STATUS NTAPI PreCreate (
    __inout PFLT_CALLBACK_DATA CallbackData,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext 
	); 

extern "C" FLT_POSTOP_CALLBACK_STATUS NTAPI PostCreate(
	__inout PFLT_CALLBACK_DATA CallbackData,
	__in PCFLT_RELATED_OBJECTS FltObject,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

#define PORT_NAME                       L"\\PortProva"
#define FLAG_NORMAL                     0x00000000
#define FLAG_NULL_BUFFER                0x10000000
#define FLAG_NO_MORE_ROOMS_FOR_MEM      0x20000000	
#define FLAG_STATIC                     0x80000000
#define MAX_SPACE                       512      
#define DEFAULT_MAX_RECORDS_TO_ALLOCATE 500
#define ENTRY_SIZE                      512
#define POOL_TAG                        'pTag'   

extern "C" NTSTATUS NTAPI DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    );

extern "C" NTSTATUS NTAPI ConnectNotifyCallback(
           __in PFLT_PORT ClientPort,
           __in PVOID ServerPortCookie,
           __in PVOID ConnectionContext,
           __in ULONG SizeOfContext,
           __out PVOID *ConnectionPortCookie
      );

extern "C" VOID NTAPI DisconnectNotifyCallback(
	__in_opt PVOID ConnectionCookie
	);

extern "C" NTSTATUS NTAPI MessageNotifyCallback(
    __in PVOID ConnectionCookie,
    __in PVOID InputBuffer,
    __in ULONG InputBufferSize,
    __out PULONG OutputBuffer,
    __in ULONG OutputBufferSize,
    __out PULONG ReturnOutputBufferLength
    );

PLIST AllocateBuffer (
    __out PULONG FlagValue
    );

VOID FreeAllocatedBuffer(
    __in PVOID Buffer
	);

PLIST AllocateRecordData(
	);

VOID FreeRecordData(
	__in PLIST Entry
	);

VOID PreLog(
    __inout PLIST pList,
	__inout PFLT_CALLBACK_DATA CallbackData
	);

VOID Log(
	__in PLIST pList
	);

NTSTATUS PrepareLogBuffer(
    __out PULONG BufferForUser,
    __in ULONG BufferForUserLength
    );

/* */

const _FLT_OPERATION_REGISTRATION  OperationRegistration[] = {

	{ IRP_MJ_CREATE,
	  0,
      PreCreate,
	  PostCreate },

	  { IRP_MJ_WRITE,
	  0,
      PreCreate,
	  PostCreate },

	  { IRP_MJ_READ,
	  0,
      PreCreate,
	  PostCreate },

	{ IRP_MJ_OPERATION_END }

};
const _FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         
    FLT_REGISTRATION_VERSION,           
    0,                                   
    ContextRegistration,                
    OperationRegistration,                         
    FilterUnload,                      
    InstanceSetupCallback,              
    InstanceQueryTeardownCallback,               
    NULL,                               
    NULL,                               
    NULL,                              
    NULL,                               
    NULL       

};

#endif
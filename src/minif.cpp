/* Minifilter */

#include <ntifs.h>
#include <fltKernel.h>
#include <includeKer.h>
#include <structsKer.h>
 
#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Controllo PREfast non valido per filter driver")    

NTSTATUS ntstatus;
STRUCT_MINIFILTER StructMinifilter;   
PFLT_CALLBACK_DATA CallbackData;     
//extern "C" DRIVER_INITIALIZE NTAPI DriverEntry; //serve per lo Static Driver Verifier

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)     
#pragma alloc_text(PAGE, ConnectNotifyCallback)
#pragma alloc_text(PAGE, DisconnectNotifyCallback)
#pragma alloc_text(PAGE, FilterUnload)
#pragma alloc_text(PAGE, InstanceSetupCallback)
#pragma alloc_text(PAGE, InstanceQueryTeardownCallback)
#pragma alloc_text(PAGE, MessageNotifyCallback)
#endif 

extern "C" NTSTATUS NTAPI DriverEntry(
	__in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
	) {

		UNICODE_STRING uniS;
		//PCWSTR portName;
		OBJECT_ATTRIBUTES InitializedAttributes;
        UNICODE_STRING ObjectName;
        PSECURITY_DESCRIPTOR SecurityDescriptor;
		PLIST pList;

		__try {

		StructMinifilter.MaxAllocation = DEFAULT_MAX_RECORDS_TO_ALLOCATE;
        StructMinifilter.Allocated = 0;

		InitializeListHead(&StructMinifilter.Head);
        KeInitializeSpinLock(&StructMinifilter.SpinLock);  
		
		ExInitializeNPagedLookasideList(&StructMinifilter.BufferAvailable,
			                            NULL,
										NULL,
										0,
										ENTRY_SIZE,
										POOL_TAG,
										0);
			
		ntstatus = FltRegisterFilter(DriverObject,                        
                                     &FilterRegistration,                 
                                     &StructMinifilter.Filter);         

		
		if (!NT_SUCCESS(ntstatus)) {   

			DbgPrint("FltRegisterFilter failed with code: %08x\n", ntstatus);

			__leave; } 

		ntstatus = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);

		if(!NT_SUCCESS(ntstatus)) {

			DbgPrint("Cannot build security descriptor\n");

			__leave; }

        RtlInitUnicodeString(&ObjectName, L"\\PortName");

		InitializeObjectAttributes(&InitializedAttributes,
			                       &ObjectName,
								   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,  
								   NULL,
								   SecurityDescriptor);

		ntstatus = FltCreateCommunicationPort(StructMinifilter.Filter,
                                              &StructMinifilter.ServerPort,   
											  &InitializedAttributes,
											  NULL,
											  ConnectNotifyCallback,      
											  DisconnectNotifyCallback,   
											  (PFLT_MESSAGE_NOTIFY)MessageNotifyCallback,
											  1);
		
	    FltFreeSecurityDescriptor(SecurityDescriptor);  

		if(!NT_SUCCESS(ntstatus)) {

			DbgPrint("Cannot create communication port\n");

			__leave; }

		ntstatus = FltStartFiltering(StructMinifilter.Filter);  }

		__finally {
			
		if(!NT_SUCCESS(ntstatus)) {

			if(StructMinifilter.ServerPort != NULL) {

				FltCloseCommunicationPort(StructMinifilter.ServerPort); }

			if(StructMinifilter.Filter != NULL) {

				FltUnregisterFilter(StructMinifilter.Filter); }

		ExDeleteNPagedLookasideList(&StructMinifilter.BufferAvailable); }

		}

        return ntstatus;
				                                
}

extern "C" NTSTATUS NTAPI ConnectNotifyCallback(
           __in PFLT_PORT ClientPort,
           __in PVOID ServerPortCookie,
           __in PVOID ConnectionContext,
           __in ULONG SizeOfContext,
           __out PVOID *ConnectionPortCookie
      ) { 
	
		  PAGED_CODE();

		  ASSERT(StructMinifilter.ClientPort == NULL);
		  StructMinifilter.ClientPort = ClientPort;

		  return STATUS_SUCCESS;
}

extern "C" VOID NTAPI DisconnectNotifyCallback(
	__in_opt PVOID ConnectionCookie
	) {

		PAGED_CODE();

		FltCloseClientPort(StructMinifilter.Filter, 
			               &StructMinifilter.ClientPort);


}

extern "C" NTSTATUS NTAPI FilterUnload(
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    ) {

	PAGED_CODE();

	FltCloseCommunicationPort(StructMinifilter.ServerPort);
	FltUnregisterFilter(StructMinifilter.Filter);

	return STATUS_SUCCESS;

}

NTSTATUS NTAPI InstanceSetupCallback(
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags,
	__in DEVICE_TYPE VolumeDeviceType,
	__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
	) {

		PAGED_CODE();

		ASSERT(FltObjects->Filter == StructMinifilter.Filter);
	
		return STATUS_SUCCESS;

}

extern "C" NTSTATUS NTAPI InstanceQueryTeardownCallback(                            
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in FLT_INSTANCE_SETUP_FLAGS Flags
	) {

		PAGED_CODE();

		return STATUS_SUCCESS;

}

extern "C" FLT_PREOP_CALLBACK_STATUS NTAPI PreCreate(
	__inout PFLT_CALLBACK_DATA CallbackData,        
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    ) {

		PLIST list;

		/*
		StructMinifilter.Process = PsGetCurrentProcess(); 

		if (IoThreadToProcess(CallbackData->Thread) == StructMinifilter.Process) {   

			DbgPrint("Our thread is requesting io\n");

			return FLT_PREOP_SUCCESS_NO_CALLBACK; }  */ 

	   list = AllocateRecordData();

	   if (list) {

		   DbgPrint("Allocated\n");

		   PreLog(list, CallbackData);

		   *CompletionContext = list; 
	        
		   return FLT_PREOP_SUCCESS_WITH_CALLBACK; }

	   return FLT_PREOP_SUCCESS_NO_CALLBACK;
	
}

extern "C" FLT_POSTOP_CALLBACK_STATUS NTAPI PostCreate(
	__inout PFLT_CALLBACK_DATA CallbackData,
	__in PCFLT_RELATED_OBJECTS FlteObject,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	) {

		PLIST list;

		DbgPrint("PostCreate\n");

		if (!NT_SUCCESS(CallbackData->IoStatus.Status)) {

		DbgPrint("Ops\n");

        return FLT_POSTOP_FINISHED_PROCESSING; }   

		list = (PLIST)CompletionContext;

		if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {

		DbgPrint("No driver instances\n");

        FreeRecordData(list);
        return FLT_POSTOP_FINISHED_PROCESSING; }

		Log(list); 

		return FLT_POSTOP_FINISHED_PROCESSING;

}

extern "C" NTSTATUS NTAPI MessageNotifyCallback(
    __in PVOID ConnectionCookie,
    __in PVOID InputBuffer,
    __in ULONG InputBufferSize,
    __out PULONG OutputBuffer,
    __in ULONG OutputBufferSize,
    __out PULONG ReturnOutputBufferLength
    ) {

		PAGED_CODE();

		STRUCT_COMMAND command;
		NTSTATUS ntstatus;

		DbgPrint("FltSendMessage() received\n");

		if(InputBuffer != NULL) {

			__try {

				command = ((PCOMMAND_MESSAGE)InputBuffer)->Command; }

		    __except(EXCEPTION_EXECUTE_HANDLER) {

            return GetExceptionCode(); }

			switch(command) {

			case FillBufferForUser: 

				if ((OutputBuffer == NULL) || (OutputBufferSize == 0)) {

					DbgPrint("Empty buffer!\n");

                    ntstatus = STATUS_INVALID_PARAMETER;
                    break;

                }

				ntstatus = PrepareLogBuffer(OutputBuffer,
					                        OutputBufferSize);

				break;
				
			case about:

				DbgPrint("About\n");

				ntstatus = STATUS_SUCCESS;

				break;

			} }


		else {

			DbgPrint("No input buffer!\n");

			ntstatus = STATUS_INVALID_PARAMETER; }

		return ntstatus;

}

PLIST AllocateBuffer(
    __out PULONG FlagValue
    ) {

		ULONG newRecordFlagValue = FLAG_NORMAL;
		PLIST buffer;

		if(StructMinifilter.Allocated < StructMinifilter.MaxAllocation) {   

			InterlockedIncrement(&StructMinifilter.Allocated);  

			buffer = (PLIST)ExAllocateFromNPagedLookasideList(&StructMinifilter.BufferAvailable); 

			if(buffer == NULL) {

				InterlockedDecrement(&StructMinifilter.Allocated);  
				newRecordFlagValue = FLAG_NULL_BUFFER; } }

		else {
			
            newRecordFlagValue = FLAG_NO_MORE_ROOMS_FOR_MEM;
			buffer = NULL; } 

        *FlagValue = newRecordFlagValue;

        return buffer;

}

VOID FreeAllocatedBuffer(
    __in PVOID Buffer
	) {
  
    InterlockedDecrement(&StructMinifilter.Allocated);
    ExFreeToNPagedLookasideList(&StructMinifilter.BufferAvailable, Buffer);

}

PLIST AllocateRecordData(
	) {

	ULONG iFlagValue;
	PLIST Entry;

    Entry = AllocateBuffer(&iFlagValue);

	if(Entry == NULL) { 

		if(!InterlockedExchange(&StructMinifilter.UsingStaticBuffer, TRUE)) {

		    Entry = (PLIST)StructMinifilter.StaticBuffer;  
                                                           
		    iFlagValue = iFlagValue |= FLAG_STATIC; } }

	if (Entry != NULL) {

		Entry->LogRecord.FlagValue = iFlagValue;
		Entry->LogRecord.Length = sizeof(LOG_RECORD);
        RtlZeroMemory(&Entry->LogRecord.Data, sizeof(RECORD_DATA)); } 

    return Entry;
}

VOID FreeRecordData(
	__in PLIST Entry
	) {

	if(FlagOn(Entry->LogRecord.FlagValue, FLAG_STATIC)) { 

		ASSERT(StructMinifilter.UsingStaticBuffer);
		StructMinifilter.UsingStaticBuffer = FALSE; }

	else {

		FreeAllocatedBuffer(Entry); }

}

VOID PreLog(
    __inout PLIST pList,
    __inout PFLT_CALLBACK_DATA CallbackData
	) {

		PRECORD_DATA recordData = &pList->LogRecord.Data;
		PEPROCESS pProc;
		ULONG pID;
		HANDLE hpID;

		pProc = IoThreadToProcess(CallbackData->Thread);
		hpID = PsGetProcessId(pProc);
		pID = (ULONG)hpID;
		DbgPrint("Process Id From CallbackData %8x\n", pID);
		recordData->ProcessId = pID;

}

VOID Log(
	__in PLIST pList
	) {

		KIRQL OldIrql;
		KeAcquireSpinLock(&StructMinifilter.SpinLock, 
			              &OldIrql);

		InsertTailList(&StructMinifilter.Head, 
			           &pList->ListEntry); 

		KeReleaseSpinLock(&StructMinifilter.SpinLock, 
			             OldIrql);

		PRECORD_DATA recordData = &pList->LogRecord.Data;

		DbgPrint("ProcessId In list %d\n", recordData->ProcessId);

}

NTSTATUS PrepareLogBuffer (
    __out PULONG BufferForUser,
    __in ULONG BufferForUserLength
    ) {

		PLIST_ENTRY pList;  
		PLOG_RECORD pLogRecord;
		PLIST pListForUser;
		ULONG bytesOutput = 0;
		KIRQL OldIrql;

		KeAcquireSpinLock(&StructMinifilter.SpinLock, 
			              &OldIrql);

		while (!IsListEmpty(&StructMinifilter.Head) && BufferForUserLength > 0) {  

			pList = RemoveHeadList(&StructMinifilter.Head); 

			pListForUser = CONTAINING_RECORD(pList, 
				                             LIST, 
											 ListEntry);

			pLogRecord = &pListForUser->LogRecord;

			if (BufferForUserLength < pLogRecord->Length) {

				InsertHeadList(&StructMinifilter.Head, pList);

				break; }

			KeReleaseSpinLock(&StructMinifilter.SpinLock, OldIrql);

			__try {
            
			    RtlCopyMemory(BufferForUser, 
					          pLogRecord, 
							  pLogRecord->Length);

			}

			__except (EXCEPTION_EXECUTE_HANDLER) {

				KeAcquireSpinLock(&StructMinifilter.SpinLock, 
					              &OldIrql);

				InsertHeadList(&StructMinifilter.Head, 
					           pList);

				KeReleaseSpinLock(&StructMinifilter.SpinLock, 
					              OldIrql); 
			    
			    return GetExceptionCode(); }

			bytesOutput += pLogRecord->Length;
			BufferForUserLength -= pLogRecord->Length;
			BufferForUser += pLogRecord->Length;

			FreeRecordData(pListForUser);

			KeAcquireSpinLock(&StructMinifilter.SpinLock, 
				              &OldIrql); }

		KeReleaseSpinLock(&StructMinifilter.SpinLock, 
			              OldIrql);

		if (bytesOutput == NULL) {

			ntstatus = STATUS_BUFFER_TOO_SMALL; }

		else if (bytesOutput > 0) {

			ntstatus = STATUS_SUCCESS; }

		return ntstatus;

}

VOID FreeLogBuffer(
	) {

		PLIST_ENTRY pList;
		KIRQL OldIrql;
		PLIST pRecord;

		KeAcquireSpinLock(&StructMinifilter.SpinLock, 
					      &OldIrql);

		while(!IsListEmpty(&StructMinifilter.Head)) {

			pList = RemoveHeadList(&StructMinifilter.Head);

			KeReleaseSpinLock(&StructMinifilter.SpinLock, 
			                  OldIrql);

			pRecord = CONTAINING_RECORD(pList,
				                        LIST, 
										ListEntry);
				                        
			FreeRecordData(pRecord);

			KeAcquireSpinLock(&StructMinifilter.SpinLock, 
					          &OldIrql);

		}

		KeReleaseSpinLock(&StructMinifilter.SpinLock, 
			              OldIrql);

}
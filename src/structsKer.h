#ifndef __STRUCTSKER_H__
#define __STRUCTSKER_H__

#define MAX_SPACE                       512
#define ENTRY_SIZE                      512

/*
#ifdef ALLOC_DATA_PRAGMA
    #pragma data_seg("INIT")
    #pragma const_seg("INIT")
#endif
	*/

/* Commands */

typedef enum _STRUCT_COMMAND {

	about,
	FillBufferForUser

}STRUCT_COMMAND;

typedef struct _COMMAND_MESSAGE {

    STRUCT_COMMAND Command;
 
}COMMAND_MESSAGE, *PCOMMAND_MESSAGE;

/* */

/* List */

typedef struct _RECORD_DATA {

    ULONG_PTR ProcessId;

} RECORD_DATA, *PRECORD_DATA;

typedef struct _LOG_RECORD {

    ULONG Length;            
    ULONG SequenceNumber;    

    ULONG FlagValue;            
  
    RECORD_DATA Data;          

} LOG_RECORD, *PLOG_RECORD;

typedef struct _LIST {

    LIST_ENTRY ListEntry;  

    LOG_RECORD LogRecord;

} LIST, *PLIST;

/* */ 

#ifdef ALLOC_DATA_PRAGMA
    #pragma data_seg()
    #pragma const_seg()
#endif

#endif
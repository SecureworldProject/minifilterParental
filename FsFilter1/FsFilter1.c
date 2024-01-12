/*++

Module p_file_path:

    FsFilter1.c

Abstract:

    This is the main module of the FsFilter1 miniFilter driver.

Environment:

    Kernel mode

--*/


///////////////////////////////////////////
/////          FILE INCLUDES          /////
///////////////////////////////////////////
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddk.h>
#include <stdio.h>
#include <stdlib.h>





///////////////////////////////////////////
/////             MACROS              /////
///////////////////////////////////////////
#define SECUREWORLD_FILENAME_TAG 'SWfn'
#define SECUREWORLD_PRE2POST_TAG 'SWpp'
#define SECUREWORLD_VOLUME_CONTEXT_TAG 'SWvx'
//#define SECUREWORLD_FILE_CONTEXT_TAG 'SWfx' // Not implemented yet. Possible optimization for filename retrieving
#define SECUREWORLD_VOLUME_NAME_TAG 'SWvn'
#define SECUREWORLD_REQUESTOR_NAME_TAG 'SWrn'
#define FILE_POOL_TAG 'SWft'
#define FORBIDDEN_FOLDER_POOL_TAG 'SWpt'
#define AUXILIAR 'SWax'

#define MEMORY 4000

#define MIN_SECTOR_SIZE 0x200

#define MAX_FILEPATH_LENGTH 520     // 260 is enough? The correct way to do it is ask twice the function, first with buffer = 0 and then with the length the function returned (slower)

#define DEBUG_MODE 1                // Affects the PRINT() function. If 0 does not print anything. If 1 debug traces are printed.
#define CHECK_FILENAME 1            // Affects is_special_folder_get_file_name() function. If 0 function always return 0 and null filename pointer. If 1 behaves normally.
#define PROCESS_CREATE_OPERATION 1  // If 0 create operations are not processed. If 1 create operations are processed.
#define PROCESS_READ_OPERATION 1    // If 0 read operations are not processed. If 1 read operations are processed and buffer swapped.
#define PROCESS_WRITE_OPERATION 1   // If 0 write operations are not processed. If 1 write operations are processed and buffer swapped.
//TO DO    #define BUFFER_SWAP 1               // If 0 skips the buffer swap (note this is only valid for same length encription algorithms). If 1 does the buffer swap.

#define PRINT(...) do { if (DEBUG_MODE) DbgPrint(__VA_ARGS__); } while (0)

#define NOOP ((void)0);             // No-operation





///////////////////////////////////////////
/////        TYPE DEFINITIONS         /////
///////////////////////////////////////////

//typedef enum { false, true } bool;    // false = 0,  true = 1

typedef struct _VOLUME_CONTEXT {
    UNICODE_STRING Name;        // Holds the name to display
    ULONG SectorSize;           // Holds sector size for this volume
} VOLUME_CONTEXT, *PVOLUME_CONTEXT;

typedef struct _PRE_2_POST_CONTEXT {
    PVOLUME_CONTEXT VolCtx;     // Volume context to be freed on post-operation (in DPC: can't be got, but can be released)
    PVOID SwappedBuffer;        // Swapped buffer to be freed on post-operation
} PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;

// Defines the type QUERY_INFO_PROCESS as a pointer to a function that returns NTSTATUS and takes as parameters the provided fields
typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
);





///////////////////////////////////////////
/////       FUNCTION PROTOTYPES       /////
///////////////////////////////////////////

NTSTATUS instance_setup(_In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
void cleanup_volume_context(_In_ PFLT_CONTEXT ctx, _In_ FLT_CONTEXT_TYPE ctx_type);
NTSTATUS mini_unload(FLT_FILTER_UNLOAD_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS mini_pre_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context);
FLT_POSTOP_CALLBACK_STATUS mini_post_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags);

BOOLEAN is_in_folder(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name, WCHAR* folder);
BOOLEAN is_in_folders(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name, WCHAR folders[10][MAX_FILEPATH_LENGTH], const int len);
BOOLEAN is_in_forbidden_folders(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name);
BOOLEAN is_special_folder_get_file_name(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name);
NTSTATUS get_requestor_process_image_path(_In_ PFLT_CALLBACK_DATA data, _Out_ PUNICODE_STRING img_path);
NTSTATUS get_process_image_path(_In_ HANDLE pid, _Out_ PUNICODE_STRING img_path);
//int fill_forbidden_folders(WCHAR* input, WCHAR*** folders, int* len);
int fill_forbidden_folders(WCHAR* input);
int fill_forbidden_folders_and_challenges_by_folder(WCHAR* input);
int fill_config_path(WCHAR* input);

///////////////////////////////////////////
/////        GLOBAL VARIABLES         /////
///////////////////////////////////////////

PFLT_FILTER filter_handle = NULL;

NPAGED_LOOKASIDE_LIST pre2post_context_list;

QUERY_INFO_PROCESS ZwQueryInformationProcess;


//const WCHAR* p_secure_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside"; // Length = 59 characters
//const WCHAR* p_secure_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside\\"; // Length = 60 characters
const WCHAR* p_secure_path = L"\\Device\\HarddiskVolume4\\"; // Length = 24 characters
const WCHAR* internal_drives[] = {L"C:"};   // Drives with letter that have been always attached to the machine (not pendriver,external drives, etc.)
const WCHAR* forbidden_folder = L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\prueba";

//Support for 10 paths max
int forbidden_folders_len = 0;
WCHAR forbidden_folders[10][MAX_FILEPATH_LENGTH];

int challenges_by_folder_len[10];
WCHAR challenges_by_folder[10][10][MAX_FILEPATH_LENGTH];

WCHAR config_path[MAX_FILEPATH_LENGTH];

const WCHAR* securemirror_minifilter_config = L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\SECUREMIRROR_MINIFILTER_CONFIG.txt";

const WCHAR* rutasparentales_file = L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\parental_paths.txt"; //OK

BOOLEAN escenario_empresarial = FALSE;


const FLT_OPERATION_REGISTRATION callbacks[] = {
   #if PROCESS_CREATE_OPERATION
    {IRP_MJ_CREATE, 0, mini_pre_create, mini_post_create},
   #endif

    //{IRP_MJ_SET_INFORMATION, 0, mini_pre_set_information, NULL},

    {IRP_MJ_OPERATION_END}
};

// Context definitions we currently care about. The system will create a lookAside list for the volume context because an explicit size of the context is specified.
const FLT_CONTEXT_REGISTRATION contexts[] = {
    { FLT_VOLUME_CONTEXT, 0, cleanup_volume_context, sizeof(VOLUME_CONTEXT), SECUREWORLD_VOLUME_CONTEXT_TAG },
    //{ FLT_FILE_CONTEXT, 0, cleanup_file_context, sizeof(FILE_CONTEXT), SECUREWORLD_FILE_CONTEXT_TAG },         // Not implemented yet. Possible optimization for filename retrieving
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION filter_registration = {
    sizeof(FLT_REGISTRATION),       // Size
    FLT_REGISTRATION_VERSION,       // Version
    0,                              // Flags
    contexts,                       // Context
    callbacks,                      // Calbacks
    mini_unload,                    // Unload
    instance_setup,                 // InstanceSetup
    NULL,                           // InstanceQueryTeardown
    NULL,                           // InstanceTeardownStart
    NULL,                           // InstanceTeardownComplete
    NULL,                           // GenerateFileName
    NULL,                           // GenerateDestinationFileName
    NULL                            // NormalizeNameComponent
};





///////////////////////////////////////////
/////    FUNCTION IMPLEMENTATIONS     /////
///////////////////////////////////////////

/////     MINIFILTER CALLBACKS     /////
/**
* The filter manager calls this routine on the first operation after a new volume is mounted. Checks if the minifilter is allowed to be attached to the volume.
* Tries to attach to all volumes. Tries to get a "DOS" name for the given volume, if it es not posssible, tries with the "NT" name for the volume (which is what happens on network volumes).  If a name is retrieved a volume context will be created with that name.
*
* @param PCFLT_RELATED_OBJECTS flt_objects
*       The callback operation data.
* @param FLT_INSTANCE_SETUP_FLAGS flags
*       Bitmask of flags that indicate why the instance is being attached
* @param DEVICE_TYPE volume_device_type
*       Device type of the file system volume (CD/Disk/Network)
* @param FLT_FILESYSTEM_TYPE volume_filesystem_type
*       File system type of the volume (unknown, RAW, NTFS, etc.)
* 
* @return NTSTATUS
*       STATUS_SUCCESS - Minifilter attaches to the volume
*       STATUS_FLT_DO_NOT_ATTACH - Minifilter does not attach to the volume
*/
NTSTATUS instance_setup(_In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ FLT_INSTANCE_SETUP_FLAGS flags, _In_ DEVICE_TYPE volume_device_type, _In_ FLT_FILESYSTEM_TYPE volume_filesystem_type)
{
    PDEVICE_OBJECT dev_obj = NULL;
    PVOLUME_CONTEXT ctx = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ret_len;
    PUNICODE_STRING working_name;
    USHORT size;
    UCHAR vol_prop_buffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
    PFLT_VOLUME_PROPERTIES vol_prop = (PFLT_VOLUME_PROPERTIES)vol_prop_buffer;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(volume_device_type);
    UNREFERENCED_PARAMETER(volume_filesystem_type);

    try
    {
        // Allocate a volume context structure.
        status = FltAllocateContext(flt_objects->Filter, FLT_VOLUME_CONTEXT, sizeof(VOLUME_CONTEXT), NonPagedPool, &ctx);
        if (!NT_SUCCESS(status)) {
            leave;
        }

        // Get volume properties
        status = FltGetVolumeProperties(flt_objects->Volume, vol_prop, sizeof(vol_prop_buffer), &ret_len);
        if (!NT_SUCCESS(status)) {
            leave;
        }

        // Save the sector size in the context for later use
        FLT_ASSERT((vol_prop->SectorSize == 0) || (vol_prop->SectorSize >= MIN_SECTOR_SIZE));
        ctx->SectorSize = max(vol_prop->SectorSize, MIN_SECTOR_SIZE);

        // Init the buffer field (which may be allocated later).
        ctx->Name.Buffer = NULL;

        // Get the storage device object we want a name for.
        status = FltGetDiskDeviceObject(flt_objects->Volume, &dev_obj);
        if (NT_SUCCESS(status)) {
            // Try to get the DOS name. If it succeeds we will have an allocated name buffer. If not, it will be NULL
            status = IoVolumeDeviceToDosName(dev_obj, &ctx->Name);
        }

        // If we could not get a DOS name, get the NT name.
        if (!NT_SUCCESS(status)) {
            FLT_ASSERT(ctx->Name.Buffer == NULL);

            // Figure out which name to use from the properties
            if (vol_prop->RealDeviceName.Length > 0) {
                working_name = &vol_prop->RealDeviceName;
            }
            else if (vol_prop->FileSystemDeviceName.Length > 0) {
                working_name = &vol_prop->FileSystemDeviceName;
            }
            else {
                // No name, don't save the context
                status = STATUS_FLT_DO_NOT_ATTACH;
                leave;
            }

            // Get size of buffer to allocate. This is the length of the string plus room for a trailing colon.
            size = working_name->Length + sizeof(WCHAR);

            // Now allocate a buffer to hold this name
#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "ctx->Name.Buffer will not be leaked because it is freed in cleanup_volume_context")
            ctx->Name.Buffer = ExAllocatePoolWithTag(NonPagedPool, size, SECUREWORLD_VOLUME_NAME_TAG);
            if (ctx->Name.Buffer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }

            // Init the rest of the fields
            ctx->Name.Length = 0;
            ctx->Name.MaximumLength = size;

            // Copy the name in, and add a colon (just for visual purpose)
            RtlCopyUnicodeString(&ctx->Name, working_name);
            RtlAppendUnicodeToString(&ctx->Name, L":");
        }

        // Set the context (already defined is OK)
        status = FltSetVolumeContext(flt_objects->Volume, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL);
        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            status = STATUS_SUCCESS;
        }

        /////////////////////////////////////////////
        // If volume is not letter "T:" do not attach
        //SW: InstanceSetup:     Real SectSize=0x0000, Used SectSize=0x0200, Name="\Device\Mup:"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="C:"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="\\?\Volume{55679090-0000-0000-0000-100000000000}"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="\\?\Volume{55679090-0000-0000-0000-d05f0c000000}"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="K:"
        //--------------------------------------------------------------------------------
        // K:               \\?\Volume{820c6478-0000-0000-0000-100000000000}\
        // C:               \\?\Volume{55679090-0000-0000-0000-300300000000}\
        // System reserved  \\?\Volume{55679090-0000-0000-0000-100000000000}\
        // Recovery         \\?\Volume{55679090-0000-0000-0000-d05f0c000000}\
        // \Device\Mup: (Multiple UNC Provider) Kernel-mode component that uses UNC names to channel remote file system accesses to a network redirector (UNC provider) cappable of handling them.
        /*
        //If volume is not T:
        if (RtlCompareUnicodeString(&ctx->Name, L"T:", FALSE))
        {
            if (wcscmp(ctx->Name.Buffer, L"K:") == 0)
            {
                status = STATUS_SUCCESS;
                PRINT("SW: InstanceSetup:       K:      -->  Attached");
            }
            else {
                status = STATUS_FLT_DO_NOT_ATTACH;
                PRINT("SW: InstanceSetup:       Not K:  -->  Not attached");
            }

            PRINT("SW: InstanceSetup:   VOLUME Name = \"%wZ\", Len=%hu, MaxLen=%hu\n", &ctx->Name, ctx->Name.Length, ctx->Name.MaximumLength);
            // By default no not attach
            status = STATUS_FLT_DO_NOT_ATTACH;
        }
        */
        /*
        // Check if name length is a letter plus colon (2 wide characters = 4 Bytes)
        if (ctx->Name.Length == 4)
        {
            // Attach by default if it is a letter drive
            status = STATUS_SUCCESS;

            // Check if it is internal drive, if it is, do not attach
            int internal_drives_length = sizeof internal_drives / sizeof *internal_drives;
            for (size_t i = 0; i < internal_drives_length; i++)
            {
                if (wcscmp(ctx->Name.Buffer, internal_drives[i]) == 0)
                {
                    status = STATUS_FLT_DO_NOT_ATTACH;
                }
            }
        }
        */
        // Check if name length is a letter plus colon (2 wide characters = 4 Bytes)
        if (ctx->Name.Length == 4)
        {
            // No attach by default if it is a letter drive
            status = STATUS_FLT_DO_NOT_ATTACH;

            // Check if it is internal drive, if it is, do attach
            int internal_drives_length = sizeof internal_drives / sizeof * internal_drives;
            for (size_t i = 0; i < internal_drives_length; i++)
            {
                if (wcscmp(ctx->Name.Buffer, internal_drives[i]) == 0)
                {
                    status = STATUS_SUCCESS;
                }
            }
        }


        PRINT("SW: InstanceSetup:   Attached=%s, Name=\"%wZ\", Real SectSize=0x%04x, Used SectSize=0x%04x\n", (status == STATUS_SUCCESS ? "Yes" : "No "), &ctx->Name, vol_prop->SectorSize, ctx->SectorSize);

    }
    finally {

        // Always release the context. If the set failed, it will free the context. If not, it will remove the reference added by the set.
        // Note that the name buffer in the ctx will get freed by the context cleanup routine.
        if (ctx) {
            FltReleaseContext(ctx);
        }

        // Remove the reference added to the device object by FltGetDiskDeviceObject
        if (dev_obj) {
            ObDereferenceObject(dev_obj);
        }
    }

    return status;
}

/**
* Frees the name buffer associated to the volume context
*
* @param PFLT_CONTEXT ctx
*       The context being freed
* @param FLT_CONTEXT_TYPE ctx_type
*       The context type.
*/
VOID cleanup_volume_context(_In_ PFLT_CONTEXT ctx, _In_ FLT_CONTEXT_TYPE ctx_type) {
    PVOLUME_CONTEXT vol_ctx = ctx;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ctx_type);

    FLT_ASSERT(ctx_type == FLT_VOLUME_CONTEXT);

    if (vol_ctx->Name.Buffer != NULL) {
        ExFreePool(vol_ctx->Name.Buffer);
        vol_ctx->Name.Buffer = NULL;
    }
}

NTSTATUS mini_unload(FLT_FILTER_UNLOAD_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    PRINT("SW: Driver unload \r\n");
    FltUnregisterFilter(filter_handle);

    // Delete lookaside list for pre2post
    ExDeleteNPagedLookasideList(&pre2post_context_list);
    return STATUS_SUCCESS;
};

FLT_PREOP_CALLBACK_STATUS mini_pre_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context) {
    UNREFERENCED_PARAMETER(completion_context);
    UNICODE_STRING img_path;
    NTSTATUS status = STATUS_SUCCESS;

    
    WCHAR* p_file_name = NULL;
    
    int block_access = 0;

    PRINT("1");
    //Read rutas_parentales_file. En este fichero se describen las rutas que hay que bloquear
    //junto con los ficheros de challenges asociados a las mismas.
    //Se bloqueara una ruta m�s adelante si no se han activado todos sus challenges
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objectAttributes;

    PVOID fileObject;
    UNICODE_STRING myUnicodeStr;
    RtlInitUnicodeString(&myUnicodeStr, rutasparentales_file);
    InitializeObjectAttributes(&objectAttributes,
        &myUnicodeStr,
        OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
        NULL,
        NULL);
    IO_STATUS_BLOCK ioStatus;

    status = FltCreateFile(flt_objects->Filter, flt_objects->Instance, &fileHandle, GENERIC_READ,
        &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SEQUENTIAL_ONLY,
        NULL, 0, 0);
    if (!NT_SUCCESS(status)){
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }   

    PRINT("2");
    status = ObReferenceObjectByHandle(fileHandle, GENERIC_READ, NULL, KernelMode,
        &fileObject,
        NULL);
    if (!NT_SUCCESS(status))
    {
        //ObDereferenceObject(fileObject);
        FltClose(fileHandle);
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }    


    PRINT("3");
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    ULONG bytes_read;
    bytes_read = 0;
    char result[4000];

    //PRINT("File object       (%ws)\r\n", (((PFILE_OBJECT)(fileObject))->FileName).Buffer); //OK
        //Comprobamos si est� accediendo a los ficheros sobre los que se har� FltRead. Sino, romperia
    status = FltReadFile(flt_objects->Instance, (PFILE_OBJECT)fileObject, &offset, MEMORY, result,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
        &bytes_read, NULL, NULL); //OK  //Falla si se accede a rutas_parentales
    ObDereferenceObject(fileObject);
    FltClose(fileHandle);
    if (!NT_SUCCESS(status))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }  

    //PRINT("Content       (%.*s)\r\n",bytes_read, (char*)result);
    WCHAR wText[4000];

    mbstowcs(wText, (char*)result, bytes_read);
    wText[bytes_read] = L'\0';
    //PRINT("Antes de llamar a la funcion %ws", wText);
    //PRINT("Size antes de llamar a la funcion %d", (int)size);
    //int out = fill_forbidden_folders(wText, &forbidden_folders, &forbidden_folders_len);
    int out = fill_forbidden_folders_and_challenges_by_folder(wText);/*
    for (int i = 0; i < 10; i++)
    {
        PRINT("Forbidden_folders   %d    (%ws)\n", i,forbidden_folders[i]);
    }*/
    //Hasta aqui est� OK
    
    
    //Read SECUREMIRROR_MINIFILTER_CONFIG para obtener la carpeta donde se ubicar�n los challenges
    // HANDLE fileHandle2 = NULL;

    //OBJECT_ATTRIBUTES objectAttributes2;
    //UNICODE_STRING myUnicodeStr2;
    RtlInitUnicodeString(&myUnicodeStr, securemirror_minifilter_config);
    InitializeObjectAttributes(&objectAttributes,
        &myUnicodeStr,
        OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
        NULL,
        NULL);
    //IO_STATUS_BLOCK ioStatus2;
    status = FltCreateFile(flt_objects->Filter, flt_objects->Instance, &fileHandle, GENERIC_READ,
        &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SEQUENTIAL_ONLY,
        NULL, 0, 0);
    //Hasta aqui est� OK
    if (!NT_SUCCESS(status)){
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }   
    
   
    PRINT("4");
    status = ObReferenceObjectByHandle(fileHandle, GENERIC_READ, NULL, KernelMode,
        &fileObject,
        NULL);
    if (!NT_SUCCESS(status))
    {
        //ObDereferenceObject(fileObject);
        FltClose(fileHandle);
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }   
    //Hasta aqui esta OK
    
    //PRINT("File object       (%ws)\r\n", (((PFILE_OBJECT)(fileObject))->FileName).Buffer);

    PRINT("5");
    //LARGE_INTEGER offset2;
    //offset2.QuadPart = 0;
    //ULONG bytes_read2;
    //bytes_read2 = 0;

    //char result2[4000];

    PRINT("File object       (%ws)\r\n", (((PFILE_OBJECT)(fileObject))->FileName).Buffer); //OK

    status = FltReadFile(flt_objects->Instance, (PFILE_OBJECT)fileObject, &offset, MEMORY, result,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
        &bytes_read, NULL, NULL);  
    ObDereferenceObject(fileObject);
    FltClose(fileHandle);
    if (!NT_SUCCESS(status))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
    } 
    
    //Hasta aqui esta OK

    PRINT("6");
    PRINT("Bytes read: %d", bytes_read);
    mbstowcs(config_path, result, bytes_read);
    config_path[bytes_read] = L'\0';
    PRINT("Antes de llamar a la funcion %ws", config_path);
    //Hasta aqui esta OK
    //Comprobar si el proceso es Securemirror. Si es, se permite todo
    if(!NT_SUCCESS(get_requestor_process_image_path(data, &img_path)) || wcscmp(img_path.Buffer, L"securemirror.exe") == 0)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    PRINT("7");
    
    for (int i = 0; i < forbidden_folders_len; i++) //Para cada carpeta
    {
        for (int j = 0; j < challenges_by_folder_len[i]; j++) //Para cada challenge asociado a esa carpeta
        {
            
            WCHAR* challenge = challenges_by_folder[i][j];
            PRINT("Challenge %ws", challenge); //OK
            WCHAR challenge_ruta_absoluta[MAX_FILEPATH_LENGTH];
            WCHAR* aux = NULL;
            //Componer la ruta con la carpeta config_path+challenge
            wcsncpy(challenge_ruta_absoluta, config_path, wcslen(config_path)); //Copiamos el config_path sin el \0
            aux = challenge_ruta_absoluta + wcslen(config_path);
            if (challenge[wcslen(challenge) - 1] == L':')
            {
                //PRINT("Encuentra el caracter %lc", challenge[wcslen(challenge) - 1]);
                wcsncpy(aux, challenge, wcslen(challenge) - 1);
                aux = aux + wcslen(challenge) - 1;
            }
            else
            {
                wcsncpy(aux, challenge, wcslen(challenge));
                aux = aux + wcslen(challenge);
            }
            *aux = L'\0';
            aux = NULL;
            challenge = NULL;
            PRINT("8");
            //Hasta aqui OK
            PRINT("Ruta completa %ws",challenge_ruta_absoluta);
            //IO_STATUS_BLOCK ioStatus3;
            //HANDLE fileHandle3 = NULL;
            //OBJECT_ATTRIBUTES objectAttributes3;
            //UNICODE_STRING myUnicodeStr3;

            RtlInitUnicodeString(&myUnicodeStr, challenge_ruta_absoluta);
            InitializeObjectAttributes(&objectAttributes,
                &myUnicodeStr,
                OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
                NULL,
                NULL);
            //Necesito la ruta absoluta de cada challenge
            status = FltCreateFile(flt_objects->Filter, flt_objects->Instance, &fileHandle, GENERIC_READ,
                &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SEQUENTIAL_ONLY,
                NULL, 0, 0);
            
            
            PRINT("9");
            //Hasta aqui OK

            if (!NT_SUCCESS(status)) //Si no existe
            {
                PRINT("10");
                
                PRINT("Bloquear acceso a %ws", forbidden_folders[i]);
                //Bloquear acceso si el usuario intenta acceder a esa carpeta
                //
                p_file_name = NULL;
                if (is_in_folder(data, &p_file_name, forbidden_folders[i]))
                {
                    PRINT("11");
                    block_access = 1;
                    ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
                }
                

            }else
            {FltClose(fileHandle);}
            
        }
    }


    block_access=0;
    if (block_access == 1)
    {
        DbgPrint("[CUSTOM] INTERCEPTING OPERATION");

        status = STATUS_ACCESS_DENIED;
        data->IoStatus.Status = status;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    else
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
};

FLT_POSTOP_CALLBACK_STATUS mini_post_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(flt_objects);
    UNREFERENCED_PARAMETER(completion_context);
    WCHAR* p_file_name = NULL;
    //NTSTATUS status = STATUS_SUCCESS;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PostCreate in special folder          (%ws)\r\n", p_file_name);

            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
};

FLT_PREOP_CALLBACK_STATUS mini_pre_set_information(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context) {
    UNREFERENCED_PARAMETER(completion_context);
    UNREFERENCED_PARAMETER(flt_objects);
    WCHAR *p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PreSetInformtion in special folder    (%ws)\r\n", p_file_name);

            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
            //return FLT_PREOP_SUCCESS_WITH_CALLBACK; // Operation continues processing and will call the post filter
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK; // Operation continues processing but will not call the post filter
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PRINT("SW: Driver entry\r\n");

    // Initialize look aside list for pre2post
    ExInitializeNPagedLookasideList(&pre2post_context_list, NULL, NULL, 0, sizeof(PRE_2_POST_CONTEXT), SECUREWORLD_PRE2POST_TAG, 0);

    status = FltRegisterFilter(DriverObject, &filter_registration, &filter_handle);
    if (NT_SUCCESS(status)) {
        PRINT("SW: Driver entry register success\r\n");
        
        status = FltStartFiltering(filter_handle);
        if (!NT_SUCCESS(status)) {
            PRINT("SW: Driver entry start filtering success\r\n");
            FltUnregisterFilter(filter_handle);
        }
    }

    return status;
}



/////     CUSTOM FUNCTIONS     /////


/**
* Checks if file is in folder.
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param WCHAR **pp_file_name
*       Empty pointer used to output the name if the function returns TRUE.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);".
*
* @return BOOLEAN
*       If file is in folder.
*/
BOOLEAN is_in_folder(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name, WCHAR* folder) {
    if (!CHECK_FILENAME) {
        *pp_file_name = NULL;
        return TRUE;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info;
    NTSTATUS status;
    WCHAR p_file_path[MAX_FILEPATH_LENGTH] = { 0 };
    WCHAR* p_path_match = NULL;
    BOOLEAN ret_value = FALSE;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name_info);


    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(file_name_info);
        if (NT_SUCCESS(status)) {
            if (file_name_info->Name.MaximumLength < MAX_FILEPATH_LENGTH) {
                RtlCopyMemory(p_file_path, file_name_info->Name.Buffer, file_name_info->Name.MaximumLength);

                p_path_match = wcsstr(p_file_path, folder);
                if (p_path_match != NULL && p_path_match == p_file_path) {
                    ret_value = TRUE;   // Match

                    *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    //WCHAR pp_file_name[MAX_FILEPATH_LENGTH];

                    if (*pp_file_name) {
                        const size_t forbidden_folder_len = wcslen(folder);
                        size_t file_name_len = wcslen(p_file_path) - forbidden_folder_len;

                        wcsncpy(*pp_file_name, &p_file_path[forbidden_folder_len], file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';

                        //PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                        //PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
                    }
                }
                else {
                    ret_value = FALSE;  // NO match

                    *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    if (*pp_file_name) {
                        size_t file_name_len = wcslen(p_file_path);

                        wcsncpy(*pp_file_name, p_file_path, file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';
                    }
                } // Check filename matches secure path
                FltReleaseFileNameInformation(file_name_info);
                return ret_value;
            }// length >260  buffer not big enough
        }
        else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    return ret_value;
}


/**
* Checks if file is in the list of forbidden folders.
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param WCHAR **pp_file_name
*       Empty pointer used to output the name if the function returns TRUE.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);".
*
* @return BOOLEAN
*       If file is in folder.
*/
BOOLEAN is_in_folders(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name, WCHAR folders[10][MAX_FILEPATH_LENGTH], const int len) {
    if (!CHECK_FILENAME) {
        *pp_file_name = NULL;
        return TRUE;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info;
    NTSTATUS status;
    WCHAR p_file_path[MAX_FILEPATH_LENGTH] = { 0 };
    WCHAR* p_path_match = NULL;
    BOOLEAN ret_value = FALSE;
    size_t folder_len;
    size_t file_name_len;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name_info);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(file_name_info);
        if (NT_SUCCESS(status)) {
            if (file_name_info->Name.MaximumLength < MAX_FILEPATH_LENGTH) {
                RtlCopyMemory(p_file_path, file_name_info->Name.Buffer, file_name_info->Name.MaximumLength);
                int i = 0;
                while (i < len && ret_value==FALSE)
                {
                    p_path_match = wcsstr(p_file_path, folders[i]);
                    if (p_path_match != NULL && p_path_match == p_file_path) {
                        ret_value = TRUE;   // Match

                        *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                        //WCHAR pp_file_name[MAX_FILEPATH_LENGTH];

                        if (*pp_file_name) {
                            folder_len = wcslen(folders[i]);
                            file_name_len = wcslen(p_file_path) - folder_len;

                            wcsncpy(*pp_file_name, &p_file_path[folder_len], file_name_len);
                            (*pp_file_name)[file_name_len] = L'\0';

                            //PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                            //PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
                        }
                    }
                    else {
                        ret_value = FALSE;  // NO match

                        *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                        if (*pp_file_name) {
                            file_name_len = wcslen(p_file_path);

                            wcsncpy(*pp_file_name, p_file_path, file_name_len);
                            (*pp_file_name)[file_name_len] = L'\0';
                        }
                    }
                    i++;
                }
                FltReleaseFileNameInformation(file_name_info);
                return ret_value;
            }
        }
        else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    return ret_value;
}

BOOLEAN is_in_forbidden_folders(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name) {
    if (!CHECK_FILENAME) {
        *pp_file_name = NULL;
        return TRUE;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info;
    NTSTATUS status;
    WCHAR p_file_path[MAX_FILEPATH_LENGTH] = { 0 };
    WCHAR* p_path_match = NULL;
    BOOLEAN ret_value = FALSE;
    size_t folder_len;
    size_t file_name_len;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name_info);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(file_name_info);
        if (NT_SUCCESS(status)) {
            if (file_name_info->Name.MaximumLength < MAX_FILEPATH_LENGTH) {
                RtlCopyMemory(p_file_path, file_name_info->Name.Buffer, file_name_info->Name.MaximumLength); //Almacenamos en p_file_path la ruta completa 
                                                                                                             //del fichero que tratamos de acceder
                int i = 0;
                while (i < forbidden_folders_len && ret_value == FALSE) //Para cada ruta prohibida
                {
                    p_path_match = wcsstr(p_file_path, forbidden_folders[i]); //Devolvemos un puntero a la primera aparicion de la ruta prohibida en el path completo al que tratamos de acceder
                    if (p_path_match != NULL && p_path_match == p_file_path) {
                        ret_value = TRUE;   // Si hay Match

                        *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                        //WCHAR pp_file_name[MAX_FILEPATH_LENGTH];

                        if (*pp_file_name) {
                            folder_len = wcslen(forbidden_folders[i]); //Calculamos la longitud de la carpeta prohibida
                            file_name_len = wcslen(p_file_path) - folder_len; //Calculamos la longitud de del nombre del fichero a bloquear (dentro de la ruta prohibida)

                            wcsncpy(*pp_file_name, &p_file_path[folder_len], file_name_len);
                            (*pp_file_name)[file_name_len] = L'\0';

                            //PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                            //PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
                        }
                    }
                    else {
                        ret_value = FALSE;  // NO match

                        *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                        if (*pp_file_name) {
                            file_name_len = wcslen(p_file_path);

                            wcsncpy(*pp_file_name, p_file_path, file_name_len);
                            (*pp_file_name)[file_name_len] = L'\0';
                        }
                    }
                    i++;
                }
                FltReleaseFileNameInformation(file_name_info);
                return ret_value;
            }
        }
        else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    return ret_value;
}



/**
* Checks if the operation is taking place in the secure folder or not.
* 
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param WCHAR **pp_file_name
*       Empty pointer used to output the name if the function returns TRUE.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);".
* 
* @return BOOLEAN
*       If the operation is taking place in the secure folder.
*/
BOOLEAN is_special_folder_get_file_name(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR **pp_file_name) {
    if (!CHECK_FILENAME) {
        *pp_file_name = NULL;
        return TRUE;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info;
    NTSTATUS status;
    WCHAR p_file_path[MAX_FILEPATH_LENGTH] = { 0 };
    WCHAR *p_path_match = NULL;
    BOOLEAN ret_value = FALSE;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name_info);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(file_name_info);
        if (NT_SUCCESS(status)) {
            if (file_name_info->Name.MaximumLength < MAX_FILEPATH_LENGTH) {
                RtlCopyMemory(p_file_path, file_name_info->Name.Buffer, file_name_info->Name.MaximumLength);

                p_path_match = wcsstr(p_file_path, p_secure_path);
                if (p_path_match!=NULL && p_path_match==p_file_path) {
                    ret_value = TRUE;   // Match

                    *pp_file_name = (WCHAR *)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH *sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    //WCHAR pp_file_name[MAX_FILEPATH_LENGTH];

                    if (*pp_file_name) {
                        const size_t secure_path_len = wcslen(p_secure_path);
                        size_t file_name_len = wcslen(p_file_path) - secure_path_len;

                        wcsncpy(*pp_file_name, &p_file_path[secure_path_len], file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';

                        //PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                        //PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
                    }
                } else {
                    ret_value = FALSE;  // NO match

                    *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    if (*pp_file_name) {
                        size_t file_name_len = wcslen(p_file_path);

                        wcsncpy(*pp_file_name, p_file_path, file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';
                    }
                } // Check filename matches secure path
                FltReleaseFileNameInformation(file_name_info);
                return ret_value;
            }// length >260  buffer not big enough
        } else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    return ret_value;
}

/**
* Gets the full image path of the process which pid is passed by parameter
*
* @param PFLT_CALLBACK_DATA data
*       The callback data of the pre/post operation which caller process path wants to be retrieved.
* @param PUNICODE_STRING p_img_path
*       Empty pointer used to output the name if the function returns a valid status.
*       May be NULL if allocation failed (when STATUS_INSUFFICIENT_RESOURCES is returned).
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_img_path->Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);".
*
* @return NTSTATUS
*       A status corresponding to the success or failure of the operation.
*/
NTSTATUS get_requestor_process_image_path(_In_ PFLT_CALLBACK_DATA data, _Out_ PUNICODE_STRING p_img_path) {
    NTSTATUS status;
    PEPROCESS obj_process = NULL;
    HANDLE proc_handle;

    obj_process = IoThreadToProcess(data->Thread);

    proc_handle = PsGetProcessId(obj_process);

    p_img_path->Length = 0;
    p_img_path->MaximumLength = MAX_FILEPATH_LENGTH;
    p_img_path->Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, MAX_FILEPATH_LENGTH, SECUREWORLD_REQUESTOR_NAME_TAG);
    if (NULL!=p_img_path->Buffer) {
        status = get_process_image_path(proc_handle, p_img_path);
        if (NT_SUCCESS(status)) {
            NOOP
            //PRINT("SW: ---> requestor: %wZ", p_img_path);
        } else{
            ExFreePoolWithTag(p_img_path->Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);
        }
    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
        p_img_path->Buffer = NULL;
    }

    return status;
}

/**
* Gets the full image path of the process which pid is passed by parameter
* Copied from: https://stackoverflow.com/a/40507407/7505211
*
* @param HANDLE pid
*       A handle (process ID) of the process which path wants to be retrieved.
* @param PUNICODE_STRING p_img_path
*       Empty pointer used to output the name if the function returns a valid status.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_img_path->Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);".
*
* @return NTSTATUS
*       A status corresponding to the success or failure of the operation.
*/
NTSTATUS get_process_image_path(_In_ HANDLE pid, _Out_ PUNICODE_STRING p_img_path) {
    NTSTATUS status;
    ULONG returned_length;
    ULONG buffer_length;
    HANDLE h_process = NULL;
    PVOID buffer;
    PEPROCESS p_eprocess;
    PUNICODE_STRING p_tmp_img_path;

    PAGED_CODE(); // This eliminates the possibility of the IDLE Thread/Process

    status = PsLookupProcessByProcessId(pid, &p_eprocess);

    if (NT_SUCCESS(status)) {
        status = ObOpenObjectByPointer(p_eprocess, 0, NULL, 0, 0, KernelMode, &h_process);
        if (NT_SUCCESS(status)) {
        } else {
            PRINT("SW: ObOpenObjectByPointer Failed: %08x\n", status);
        }
        ObDereferenceObject(p_eprocess);
    } else {
        PRINT("SW: PsLookupProcessByProcessId Failed: %08x\n", status);
    }

    if (NULL == ZwQueryInformationProcess) {
        UNICODE_STRING routine_name;
        RtlInitUnicodeString(&routine_name, L"ZwQueryInformationProcess");

        ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routine_name);

        if (NULL == ZwQueryInformationProcess) {
            PRINT("SW: Cannot resolve ZwQueryInformationProcess\n");
        }
    }

    // Query the actual size of the process path
    status = ZwQueryInformationProcess(h_process, ProcessImageFileName, NULL, 0, &returned_length);

    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        return status;
    }

    // Check if there is enough space to store the actual process path when it is found. If not return an error with the required size
    buffer_length = returned_length - sizeof(UNICODE_STRING);
    if (p_img_path->MaximumLength < buffer_length) {
        p_img_path->MaximumLength = (USHORT)buffer_length;
        return STATUS_BUFFER_OVERFLOW;
    }

    // Allocate a temporary buffer to store the path name
    buffer = ExAllocatePoolWithTag(NonPagedPool, returned_length, SECUREWORLD_REQUESTOR_NAME_TAG);

    if (NULL == buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Retrieve the process path from the handle to the process
    status = ZwQueryInformationProcess(h_process, ProcessImageFileName, buffer, returned_length, &returned_length);

    if (NT_SUCCESS(status)) {
        // Copy the path name
        p_tmp_img_path = (PUNICODE_STRING)buffer;
        RtlCopyUnicodeString(p_img_path, p_tmp_img_path);
    }

    // Free the temp buffer which stored the path
    ExFreePoolWithTag(buffer, SECUREWORLD_REQUESTOR_NAME_TAG);

    return status;
}

/*
int fill_config_path(WCHAR* input)
{
    //int i = 0;
    //size_t len = 0;
    size_t input_len = wcslen(input);

    wcsncpy(config_path, input, input_len);  //Copiamos todo menos el \n
    //config_path[input_len - 1] = L'\0'; //Le ponemos un /0 al final porque wcsncpy no lo hace. hay que hacerlo en el -2 por el \n
    //PRINT("Config path: %ws", config_path);
    return 0;
}
*/

int fill_forbidden_folders(WCHAR* input)
{
    int i = 0;
    size_t len = 0;
    size_t input_len = wcslen(input);
    forbidden_folders_len = 0;
    WCHAR* aux=input;
    while (i < (int)input_len)
    {
        len++;
        //PRINT(" Letra: %lc", input[i]);
        if (input[i] == L'\n') //Si encuentra un salto de linea
        {
            //PRINT("Encuentra el caracter %lc", input[i]);
            //PRINT("Input    (%ws)\r\n", input); //Ruta a guardar
            wcsncpy(forbidden_folders[forbidden_folders_len], aux, len-1);  //Copiamos todo menos el ;
            forbidden_folders[forbidden_folders_len][len-2] = L'\0'; //Le ponemos un /0 al final porque wcsncpy no lo hace
            //PRINT("Carpeta prohibida numero %d,   (%ws)\r\n", forbidden_folders_len, forbidden_folders[forbidden_folders_len]); //Carpeta prohibida
            //PRINT("Forbidden_folders   0    (%ws)\n", forbidden_folders[0]);
            //PRINT("Forbidden_folders   1    (%ws)\n", forbidden_folders[1]);
            forbidden_folders_len++;
            if (i+1 < (int)input_len) //Si no es el ultimo caracter
            {
                aux = input + i + 1; //Actualizamos Aux para que apunte a la siguiente ruta, solo si no se ha llegado al final
                //PRINT("QUEDA OTRA RUTA");
            }
            len = 0;
        }
        i++;
    }
    //aux = NULL;
    return 0;
}

int fill_forbidden_folders_and_challenges_by_folder(WCHAR* input)
{
    int i = 0;
    int challenge_number = 0;
    size_t len_folder = 0;
    size_t len_challenge = 0;
    size_t input_len = wcslen(input);
    forbidden_folders_len = 0;
    //Inicializamos el numero de challenges de cada carpeta a 0 
    for (int idx = 0; idx < 10; idx++)
    {
        challenges_by_folder_len[idx] = 0;
    }
    WCHAR* aux = input;
    while (i < (int)input_len)
    {
        len_folder++;
        if (input[i] == L':') //Si encuentra :, guarda hasta ah� en forbidden_folders
        {
            wcsncpy(forbidden_folders[forbidden_folders_len], aux, len_folder - 1);  //Copiamos todo menos el ;
            forbidden_folders[forbidden_folders_len][len_folder - 1] = L'\0'; //Le ponemos un /0 al final porque wcsncpy no lo hace
            //PRINT("Forbidden_folders   0    (%ws)\n", forbidden_folders[0]);
            //PRINT("Forbidden_folders   1    (%ws)\n", forbidden_folders[1]);
            aux= input + i + 1; //Actualizamos Aux para que apunte al primer challenge
            len_folder = 0;  //Siguiente carpeta a guardar
            //Ahora rellenamos los challenges asociados a la carpeta prohibida
            i++;
            while (input[i] != L'\n') //Hasta que no se llegue al final de la l�nea
            {
                len_challenge++;
                if (input[i] == L':') //Si encuentra :, rellena un challenge asociado a esa carpeta
                {
                    wcsncpy(challenges_by_folder[forbidden_folders_len][challenge_number], aux, len_challenge - 1);  //Copiamos todo menos el ;
                    if (i + 3 < (int)input_len) //Si no es el ultimo caracter
                    {
                        challenges_by_folder[forbidden_folders_len][challenge_number][len_challenge - 1] = L'\0';
                    }
                    else //Si es el �ltimo, workaround para eliminar el :
                    {
                        challenges_by_folder[forbidden_folders_len][challenge_number][len_challenge - 2] = L'\0';
                    }
                    //PRINT("Challenge  %d de la carpeta %d    (%ws)\n", 
                    //    challenge_number, 
                    //    forbidden_folders_len, 
                    //    challenges_by_folder[forbidden_folders_len][challenge_number]);
                    challenge_number++; //siguiente challenge a guardar
                    len_challenge = 0;
                    aux = input + i + 1; //Actualizamos Aux para que apunte al siguiente challenge
                    challenges_by_folder_len[forbidden_folders_len]++; //Anotamos que hay un challenge mas en esa carpeta
                }
                i++;
            }
            if (i + 3 < (int)input_len) //Si no es el ultimo caracter
            {
                aux = input + i + 1; //Actualizamos Aux para que apunte a la siguiente ruta, solo si no se ha llegado al final
                //PRINT("QUEDA OTRA RUTA");
            }
            challenge_number = 0; //Reseteamos el identificador de challenge
            forbidden_folders_len++; //Siguiente carpeta a guardar
        }
        i++;
    }
    aux = NULL;
    return 0;
}

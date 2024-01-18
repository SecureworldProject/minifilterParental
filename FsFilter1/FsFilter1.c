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

// Memory allocation tags
#define SECUREWORLD_FILENAME_TAG 'SWfn'
#define SECUREWORLD_PRE2POST_TAG 'SWpp'
#define SECUREWORLD_VOLUME_CONTEXT_TAG 'SWvx'
#define SECUREWORLD_VOLUME_NAME_TAG 'SWvn'
#define SECUREWORLD_REQUESTOR_NAME_TAG 'SWrn'

// Size of the read buffer for the configuration files. NOTE: if the file is bigger, only first MAX_READ_SIZE bytes will be taken into account.
#define MAX_READ_SIZE 4096

#define MIN_SECTOR_SIZE 0x200

#define MAX_FILEPATH_LENGTH 520     // 260 is enough? The correct way to do it is ask twice the function, first with buffer = 0 and then with the length the function returned (slower)

#define DEBUG_MODE 1                // Affects the PRINT() function. If 0 does not print anything. If 1 debug traces are printed.

#define PRINT(...) do { if (DEBUG_MODE) DbgPrint(__VA_ARGS__); } while (0)

#define NOOP ((void)0);             // No-operation





///////////////////////////////////////////
/////        TYPE DEFINITIONS         /////
///////////////////////////////////////////

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

// Minifilter callback functions

NTSTATUS instance_setup(_In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
void cleanup_volume_context(_In_ PFLT_CONTEXT ctx, _In_ FLT_CONTEXT_TYPE ctx_type);
NTSTATUS mini_unload(FLT_FILTER_UNLOAD_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS mini_pre_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context);
FLT_POSTOP_CALLBACK_STATUS mini_post_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags);

// Custom functions

NTSTATUS configure_minifilter(_In_ PCFLT_RELATED_OBJECTS flt_objects);
void fill_forbidden_folders_and_challenges_by_folder(_In_ WCHAR* input);
void rewrite_challenge_filenames_as_absolute_paths();

NTSTATUS get_requestor_process_image_path(_In_ PFLT_CALLBACK_DATA data, _Out_ PUNICODE_STRING img_path);
NTSTATUS get_process_image_path(_In_ HANDLE pid, _Out_ PUNICODE_STRING img_path);

BOOLEAN is_folder_access_allowed(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects);
BOOLEAN is_in_folder(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name, WCHAR* folder);





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

const WCHAR* securemirror_minifilter_config_filepath = L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\SECUREMIRROR_MINIFILTER_CONFIG.txt";

const WCHAR* parental_paths_filepath = L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\parental_paths.txt"; //OK

BOOLEAN escenario_empresarial = FALSE;


const FLT_OPERATION_REGISTRATION callbacks[] = {
    {IRP_MJ_CREATE, 0, mini_pre_create, mini_post_create},
    {IRP_MJ_OPERATION_END}
};

// Context definitions we currently care about. The system will create a lookAside list for the volume context because an explicit size of the context is specified.
const FLT_CONTEXT_REGISTRATION contexts[] = {
    { FLT_VOLUME_CONTEXT, 0, cleanup_volume_context, sizeof(VOLUME_CONTEXT), SECUREWORLD_VOLUME_CONTEXT_TAG },
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
* Tries to attach to all volumes. Tries to get a "DOS" name for the given volume, if it is not posssible, tries with the "NT" name for the volume (which is what happens on network volumes).  If a name is retrieved a volume context will be created with that name.
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
NTSTATUS instance_setup(_In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ FLT_INSTANCE_SETUP_FLAGS flags, _In_ DEVICE_TYPE volume_device_type, _In_ FLT_FILESYSTEM_TYPE volume_filesystem_type) {
    PDEVICE_OBJECT dev_obj = NULL;
    PVOLUME_CONTEXT ctx = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ret_len;
    PUNICODE_STRING working_name;
    USHORT size;
    UCHAR vol_prop_buffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
    PFLT_VOLUME_PROPERTIES vol_prop = (PFLT_VOLUME_PROPERTIES)vol_prop_buffer;
    BOOLEAN configured = FALSE;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(volume_device_type);
    UNREFERENCED_PARAMETER(volume_filesystem_type);

    try {
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
            } else if (vol_prop->FileSystemDeviceName.Length > 0) {
                working_name = &vol_prop->FileSystemDeviceName;
            } else {
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

        //////////////////////////////////////////////////
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
        //////////////////////////////////////////////////
        /*
        //If volume is not T:
        if (RtlCompareUnicodeString(&ctx->Name, L"T:", FALSE)) {
            if (wcscmp(ctx->Name.Buffer, L"K:") == 0) {
                status = STATUS_SUCCESS;
                PRINT("SW: InstanceSetup:       K:      -->  Attached");
            } else {
                status = STATUS_FLT_DO_NOT_ATTACH;
                PRINT("SW: InstanceSetup:       Not K:  -->  Not attached");
            }

            PRINT("SW: InstanceSetup:   VOLUME Name = \"%wZ\", Len=%hu, MaxLen=%hu\n", &ctx->Name, ctx->Name.Length, ctx->Name.MaximumLength);
            // By default no not attach
            status = STATUS_FLT_DO_NOT_ATTACH;
        }
        */

        // Check if name length is a letter plus colon (2 wide characters = 4 Bytes)
        if (ctx->Name.Length == 4) {
            // No attach by default if it is a letter drive
            status = STATUS_FLT_DO_NOT_ATTACH;

            // Check if it is internal drive, if it is, do attach
            int internal_drives_length = sizeof internal_drives / sizeof * internal_drives;
            for (size_t i = 0; i < internal_drives_length; i++) {
                if (wcscmp(ctx->Name.Buffer, internal_drives[i]) == 0) {
                    status = STATUS_SUCCESS;
                }
            }
        }
        PRINT("SW: InstanceSetup:   Attached=%s, Name=\"%wZ\", Real SectSize=0x%04x, Used SectSize=0x%04x\n", (status == STATUS_SUCCESS ? "Yes" : "No "), &ctx->Name, vol_prop->SectorSize, ctx->SectorSize);
    } finally {
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

    // Return if there was an error
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Configure the minifilter by reading the minifilter configuration files
    status = configure_minifilter(flt_objects);
    PRINT("The minifilter %s configured", NT_SUCCESS(status) ? "has been correctly" : "COULD NOT be");

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

    // Check what program is making the operation. If it is not possible to get or it is securemirror, allow operation, otherwise, block
    status = get_requestor_process_image_path(data, &img_path);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (wcscmp(img_path.Buffer, L"securemirror.exe") == 0) {
        ExFreePoolWithTag(img_path.Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check what program is making the operation. If it is not possible to get or it is securemirror, allow operation, otherwise, block
    if (is_folder_access_allowed(data, flt_objects)) {
        //PRINT("ALLOWING ACCESS");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PRINT("BLOCKING ACCESS");
    data->IoStatus.Status = STATUS_ACCESS_DENIED;
    data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
};

FLT_POSTOP_CALLBACK_STATUS mini_post_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(flt_objects);
    UNREFERENCED_PARAMETER(completion_context);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
};


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
* Opens the configuration files and prepares the minifilter to act in consequence.
* Notes:
*       - The file in "securemirror_minifilter_config_filepath" describes the folder in which the parental paths file and the files associated to the protected folders can be found.
*       - The file in "parental_paths_filepath" describes the parental protected folders and the associated challenges.
*
* @return NTSTATUS
*       STATUS_SUCCESS if everything went fine. A warning or error status code otherwise (STATUS_DATA_ERROR).
*/
NTSTATUS configure_minifilter(_In_ PCFLT_RELATED_OBJECTS flt_objects) {

    PRINT("Starting configuration of the parental minifilter");

    NTSTATUS status = STATUS_SUCCESS;
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;

    PVOID fileObject;
    UNICODE_STRING myUnicodeStr;

    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    ULONG bytes_read = 0;
    char result[MAX_READ_SIZE];
    WCHAR wText[MAX_READ_SIZE];


    ///// Read and process parental_paths_filepath /////

    // Write parental_paths_filepath into an unicode string
    RtlInitUnicodeString(&myUnicodeStr, parental_paths_filepath);
    InitializeObjectAttributes(&objectAttributes,
        &myUnicodeStr,
        OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
        NULL,
        NULL);

    // Get a file handle
    status = FltCreateFile(flt_objects->Filter, flt_objects->Instance, &fileHandle, GENERIC_READ,
        &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SEQUENTIAL_ONLY,
        NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Get object reference
    status = ObReferenceObjectByHandle(fileHandle, GENERIC_READ, NULL, KernelMode, &fileObject, NULL);
    if (!NT_SUCCESS(status)) {
        //ObDereferenceObject(fileObject);  // Not done because status was not success
        FltClose(fileHandle);
        return status;
    }


    PRINT("Obtained handle object reference from file '%ws'", parental_paths_filepath);

    //PRINT("File object       (%ws)\r\n", (((PFILE_OBJECT)(fileObject))->FileName).Buffer);

    // Read the file
    status = FltReadFile(flt_objects->Instance, (PFILE_OBJECT)fileObject, &offset, MAX_READ_SIZE, result,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
        &bytes_read, NULL, NULL);
    PRINT("Read %lu Bytes (max %d Bytes) from file '%ws'", bytes_read, MAX_READ_SIZE, parental_paths_filepath);
    //PRINT("Content       (%.*s)\r\n",bytes_read, (char*)result);

    ObDereferenceObject(fileObject);
    FltClose(fileHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Transform the stream read into WCHARs
    mbstowcs(wText, (char*)result, bytes_read);
    wText[bytes_read] = L'\0';

    // Fill the global variables that contain the protected folders and their associated challenge files with the information obtained from the file
    fill_forbidden_folders_and_challenges_by_folder(wText);



    ///// Read and process securemirror_minifilter_config_filepath /////

    // Write securemirror_minifilter_config_filepath into an unicode string
    RtlInitUnicodeString(&myUnicodeStr, securemirror_minifilter_config_filepath);
    InitializeObjectAttributes(&objectAttributes,
        &myUnicodeStr,
        OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
        NULL,
        NULL);

    // Get a file handle
    status = FltCreateFile(flt_objects->Filter, flt_objects->Instance, &fileHandle, GENERIC_READ,
        &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SEQUENTIAL_ONLY,
        NULL, 0, 0);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Get object reference
    status = ObReferenceObjectByHandle(fileHandle, GENERIC_READ, NULL, KernelMode, &fileObject, NULL);
    if (!NT_SUCCESS(status)) {
        //ObDereferenceObject(fileObject);  // Not done because status was not success
        FltClose(fileHandle);
        return status;
    }

    //PRINT("File object       (%ws)\r\n", (((PFILE_OBJECT)(fileObject))->FileName).Buffer);

    // Read SECUREMIRROR_MINIFILTER_CONFIG to know the folder where the challenge files will be
    status = FltReadFile(flt_objects->Instance, (PFILE_OBJECT)fileObject, &offset, MAX_READ_SIZE, result,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
        &bytes_read, NULL, NULL);
    PRINT("Read %lu Bytes (max %d Bytes) from file '%ws'", bytes_read, MAX_READ_SIZE, securemirror_minifilter_config_filepath);
    //PRINT("Content       (%.*s)\r\n",bytes_read, (char*)result);

    ObDereferenceObject(fileObject);
    FltClose(fileHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Fill the global variable config_path with the information obtained from the file
    mbstowcs(config_path, result, bytes_read);
    config_path[bytes_read] = L'\0';
    PRINT("Configuration path set to '%ws'", config_path);



    ///// Iterate over all the challenge filenames and turn them into full paths (in-place) /////
    rewrite_challenge_filenames_as_absolute_paths();

    return status;
}

/**
* Fills the global viariables (forbidden_folders_len, forbidden_folders and challenges_by_folder) with the information read from the the parental_paths.txt file
* 
* @param WCHAR* input
*       The first MAX_READ_SIZE bytes converte into WCHAR.
*/
void fill_forbidden_folders_and_challenges_by_folder(_In_ WCHAR* input) {
    int i = 0;
    int challenge_number = 0;
    size_t len_folder = 0;
    size_t len_challenge = 0;
    size_t input_len = wcslen(input);
    forbidden_folders_len = 0;

    //Inicializamos el numero de challenges de cada carpeta a 0
    for (int idx = 0; idx < 10; idx++) {
        challenges_by_folder_len[idx] = 0;
    }
    WCHAR* aux = input;
    while (i < (int)input_len) {
        len_folder++;
        if (input[i] == L':') //Si encuentra :, guarda hasta ah� en forbidden_folders
        {
            wcsncpy(forbidden_folders[forbidden_folders_len], aux, len_folder - 1);  //Copiamos todo menos el ;
            forbidden_folders[forbidden_folders_len][len_folder - 1] = L'\0'; //Le ponemos un /0 al final porque wcsncpy no lo hace
            //PRINT("Forbidden_folders   0    (%ws)\n", forbidden_folders[0]);
            //PRINT("Forbidden_folders   1    (%ws)\n", forbidden_folders[1]);
            aux = input + i + 1; //Actualizamos Aux para que apunte al primer challenge
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
                    } else //Si es el �ltimo, workaround para eliminar el :
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
    return;
}

/**
* Gets the full path of each of the challenge files and stores them again in the same position of the global variable (challenges_by_folder).
*/
void rewrite_challenge_filenames_as_absolute_paths() {

    WCHAR* p_file_name = NULL;

    int block_access = 0;

    WCHAR* challenge_filename = NULL;
    WCHAR challenge_fullpath[MAX_FILEPATH_LENGTH] = L"";
    WCHAR* aux = NULL;

    // Iterate over each folder and each of the associated challenge files
    for (int i = 0; i < forbidden_folders_len; i++) {
        for (int j = 0; j < challenges_by_folder_len[i]; j++) {
            challenge_filename = challenges_by_folder[i][j];
            PRINT("challenge_filename = %ws", challenge_filename);

            // Compose full path (config_path + challenge_filename)
            wcsncpy(challenge_fullpath, config_path, wcslen(config_path)); // Copy config_path without '\0'
            aux = challenge_fullpath + wcslen(config_path);

            // Copy challenge_filename without ':'
            if (challenge_filename[wcslen(challenge_filename) - 1] == L':') {
                //PRINT("Encuentra el caracter %lc", challenge[wcslen(challenge) - 1]);
                wcsncpy(aux, challenge_filename, wcslen(challenge_filename) - 1);
                aux = aux + wcslen(challenge_filename) - 1;
            } else {
                wcsncpy(aux, challenge_filename, wcslen(challenge_filename));
                aux = aux + wcslen(challenge_filename);
            }
            *aux = L'\0';
            aux = NULL;
            challenge_filename = NULL;

            // Copy challenge_fullpath to challenges_by_folder
            wcscpy(challenges_by_folder[i][j], challenge_fullpath);

            PRINT("challenge_fullpath = %ws", challenge_fullpath);
        }
    }
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
    if (NULL != p_img_path->Buffer) {
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
* Originally copied from: https://stackoverflow.com/a/40507407/7505211
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


/**
* Checks if the accessed folder is inside a protected folder. If so, checks if the associated challenge files exist.
*
* @param PFLT_CALLBACK_DATA data
*       The data associated to the minifilter callback. Used to retrieve the accessed folder.
* @param PCFLT_RELATED_OBJECTS flt_objects
*       Pointer to the objects related to the filter.
*
* @return BOOLEAN
*       Returns if the requirements to allow the current operation are met, that is, if there is permission to access.
*/
BOOLEAN is_folder_access_allowed(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects) {
    WCHAR* p_file_name = NULL;
    HANDLE fileHandle;

    PVOID fileObject = NULL;
    UNICODE_STRING myUnicodeStr;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status = STATUS_SUCCESS;

    BOOLEAN allow_access = TRUE;


    // For each of the parental controlled folders (forbidden_folders)
    for (int i = 0; i < forbidden_folders_len; i++) {
        // Check if the accessed folder is in the parental controlled folder
        if (is_in_folder(data, &p_file_name, forbidden_folders[i])) {
            PRINT("is_in_folder = TRUE");

            // If it is not possible to get the name, skip everything and allow by default to avoid unexpected system blocking
            if (NULL == p_file_name) {
                break;
            }
            PRINT("Folder name: %ws\n", p_file_name);

            // For each challenge associated to the parental controlled folder
            for (int j = 0; j < challenges_by_folder_len[i]; j++) {

                // Build UnicodeString
                RtlInitUnicodeString(&myUnicodeStr, challenges_by_folder[i][j]);
                InitializeObjectAttributes(&objectAttributes,
                    &myUnicodeStr,
                    OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
                    NULL,
                    NULL);

                // Try to open the challenge file to check if it exists
                status = FltCreateFile(flt_objects->Filter, flt_objects->Instance, &fileHandle, GENERIC_READ,
                    &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SEQUENTIAL_ONLY,
                    NULL, 0, 0);

                // If it does not exist set the result to not allow access and stop checking
                if (!NT_SUCCESS(status)) {
                    allow_access = FALSE;
                    break;
                }

                // If the file existed, close the handle
                FltClose(fileHandle);
            }
        } else {
            PRINT("is_in_folder = FALSE");
        }
        // Free the string if it was allocated
        if (NULL != p_file_name) {
            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }
    return allow_access;
}

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

                    if (*pp_file_name) {
                        const size_t forbidden_folder_len = wcslen(folder);
                        size_t file_name_len = wcslen(p_file_path) - forbidden_folder_len;

                        wcsncpy(*pp_file_name, &p_file_path[forbidden_folder_len], file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';

                        PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                        PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
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
                //PRINT("returning %s\n", ret_value ? "TRUE" : "FALSE");
                return ret_value;
            }// length >260  buffer not big enough
        } else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    //PRINT("returning %s\n", ret_value ? "TRUE" : "FALSE");
    return ret_value;
}

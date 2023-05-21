#pragma once 
#ifndef LOAD_EXE_H_INCLUDED
#define LOAD_EXE_H_INCLUDED

#include <windows.h>
#include <stdio.h>

enum _fork_proc_ret_ {
	FORK_PROC_SUCCESS = 0,       // Successful execution of the fork_process function
	FORK_PROC_ERR_MALLOC,        // Error: Failed to allocate memory
	FORK_PROC_ERR_GET_DUMMY,     // Error: Failed to get the dummy process
	FORK_PROC_ERR_OPEN_DUMMY,    // Error: Failed to open the dummy process file
	FORK_PROC_ERR_DOS_HDR,       // Error: Invalid DOS header
	FORK_PROC_ERR_NT_HDR,        // Error: Invalid NT header
	FORK_PROC_ERR_FORK_DOS_HDR,  // Error: Invalid DOS header for the forking process
	FORK_PROC_ERR_FORK_NT_HDR,   // Error: Invalid NT header for the forking process
	FORK_PROC_ERR_WR_MEM_IMG,    // Error: Failed to write the image to the process memory
	FORK_PROC_ERR_WR_MEM_CTX,    // Error: Failed to write the context to the process memory
	FORK_PROC_ERR_CRE_PROC,      // Error: Failed to create the process
};

/**
 * Forks Process.
 * @param lpImage: EXE image in memory.
 * @param pCmdLine: Command line arguments for the process.
 * @param pDummyPath: Path to the dummy process.
 * @param pStartInfo: Startup information for the process.
 * @param pProcInfo: Process information for the newly created process.
 * @param pPid: Pointer to store the child process ID.
 * @param phProc: Pointer to store the handle of the child process.
*/
int fork_process(unsigned char *lpImage, char *pCmdLine, char *pDummyPath, STARTUPINFO *pStartInfo, PROCESS_INFORMATION *pProcInfo,int *pPid, HANDLE *phProc);
 
#endif // LOAD_EXE_H_INCLUDED

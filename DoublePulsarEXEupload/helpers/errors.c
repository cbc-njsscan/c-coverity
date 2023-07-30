#include <stdarg.h>
#include <string.h>
#include <Windows.h>
#include <stdio.h>
#include "errors.h"

// Prints human-readable information about the last error that occurred
void printError(const char *error_msg, ...) {
	char buf[500];

	va_list args;
	va_start(args, error_msg);
	vsnprintf(buf, sizeof(buf) - 1, error_msg, args);
	va_end(args);

	char *err = NULL;
	DWORD errCode = GetLastError();

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
		errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&err, 0, NULL
	);

	if (err != NULL) {
		_printf("\n%s:%s", buf, err);
		LocalFree(err);
	} else {
		printf("\n%s: Error code %lu", buf, errCode);
	}
}
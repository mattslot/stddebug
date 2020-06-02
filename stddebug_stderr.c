/*!
	@file stddebug_stderr.c
	@abstract Common debugging utilities
	@copyright (c) 1997-2015 by Matt Slot <mattslot@gmail.com>.
	
	Permission is hereby granted, free of charge, to any person obtaining a
	copy of this software and associated documentation files (the "Software"),
	to deal in the Software without restriction, including without limitation
	the rights to use, copy, modify, merge, publish, distribute, sublicense,
	and/or sell copies of the Software, and to permit persons to whom the
	Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
	THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
	DEALINGS IN THE SOFTWARE.


	@discussion
		Standard implementation of debug routines based on POSIX APIs.

		Specify the absolute path to a log file to direct messages there.
		Specify a short name for the log file to use the standard location:
			Mac: /var/log/name.log  -or-  ~/Library/Logs/name.log
			UNIX: /var/log/name.log  -or-  ~/log/name.log
		Pass nil to direct messages to the console via stderr.
*/ 

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#if _WIN32
	#include <io.h>
	#include <shlobj.h>
	#include <windows.h>
#else
	#include <unistd.h>
	#include <pthread.h>
	#include <sys/syslimits.h>
#endif // _WIN32

#include "stddebug.h"

#ifndef UNUSED
  #if defined(__GNUC__)
	#define	UNUSED(x)	x __attribute__((unused))
  #elif _WIN32
	#define	UNUSED(x)	__pragma(warning(suppress:4100)) x
  #else
	#error "Platform not supported"
  #endif
#endif // UNUSED

#if _WIN32
	#define MAX_PATH_LENGTH			MAX_PATH
#else
	#define MAX_PATH_LENGTH			PATH_MAX
#endif

static	bool						gPreflighted = 0;
#if ! _WIN32
	static	int						gOutputFileNo = -1;
#endif // ! _WIN32
static	FILE *						gOutputFILE = NULL;
static	char						gOutputPath[MAX_PATH_LENGTH+1] = "";
static	int							gOutputPerms = 0600;

static	bool						gDebugEnabled = 1;
static	int							gDebugLevel = 1;
static	int							gDebugMask = 0;
static	bool						gDebugStamp = 0;

#if _WIN32
	static	INIT_ONCE				gInitOnce = INIT_ONCE_STATIC_INIT; 
	static	CRITICAL_SECTION		gCriticalSection;
#else
	static	pthread_mutex_t			gMutex = PTHREAD_MUTEX_INITIALIZER;
	static	pthread_t				gMutexThread = NULL;
	static	int						gMutexRecurse = 0;
#endif // _WIN32

#if _WIN32
static BOOL CALLBACK PrepareCriticalSection(PINIT_ONCE UNUSED(once), PVOID UNUSED(param), PVOID *UNUSED(context))
{
	InitializeCriticalSection(&gCriticalSection);
	return TRUE;
}
#endif // _WIN32

static void _DebugEnter()
{
#if _WIN32
	InitOnceExecuteOnce(&gInitOnce, PrepareCriticalSection, NULL, NULL);
	EnterCriticalSection(&gCriticalSection);
#else
	if (!pthread_equal(gMutexThread, pthread_self()))
		pthread_mutex_lock(&gMutex);
	gMutexThread = pthread_self();
	gMutexRecurse++;
#endif // _WIN32
}

static void _DebugLeave()
{
#if _WIN32
	LeaveCriticalSection(&gCriticalSection);
#else
	if (!--gMutexRecurse) 
	{
		gMutexThread = NULL;
		pthread_mutex_unlock(&gMutex);
	}
#endif // _WIN32
}

static char *_DebugShortenPath(char *path)
{
	char *mark1 = strrchr(path, '@');

	// Check whether this looks like the separator between message and path
#if _WIN32
	if (mark1 && (mark1 != path) && (mark1[-1] == ' ') && (mark1[1] == ' '))
#else
	if (mark1 && ! strncmp(mark1, "@ /", 3))
#endif // _WIN32
	{
		// Slide the file name and delimiter forward in the editable buffer
#if _WIN32
		char *mark2 = strrchr(mark1, '\\');
#else
		char *mark2 = strrchr(path, '/');
#endif // _WIN32
		if (mark2)
			memmove(mark1 + 2, mark2 + 1, strlen(mark2));
	}

	return path;
}

// Generate an absolute path based on the suggested name
static void _DebugNameLogFile(const char *input, char *output, size_t maxlen)
{
	// Clear the output buffer, ensure zero terminator
	memset(output, 0, maxlen);

#if _WIN32
	if ((input[0] != '\\') &&
			((input[0] < 'A') || (input[0] > 'Z') || (input[1] != ':') || (input[2] != '\\')) &&
			((input[0] < 'a') || (input[0] > 'z') || (input[1] != ':') || (input[2] != '\\')))
	{
		char		buffer[MAX_PATH_LENGTH + 1] = "";
		
		if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, buffer) == S_OK)
			snprintf(output, maxlen, "%s\\", buffer); // Path separator
	}
#else
	if (*input != '/')
	{
		const char * home = getenv("HOME");
	
		if (! geteuid())
			snprintf(output, maxlen, "/var/log/");
		else if (home)
		{
#if __APPLE__
			snprintf(output, maxlen, "%s/Library/Logs/", home);
#else
			snprintf(output, maxlen, "%s/log/", home);
#endif // __APPLE__
			mkdir(output, 0700);
		}
	}
#endif // ! _WIN32

	strncat(output, input, maxlen - strlen(output) - 1);
	if (! strstr(input, ".log") && ! strstr(input, ".txt"))
		strncat(output, ".log", maxlen - strlen(output) - 1);
}

// Open a new file and use it's file descriptor for our logging
static void _DebugOpenLogFile()
{
	if (gOutputPath[0])
		gOutputFILE = fopen(gOutputPath, "a");
	
	if (gOutputFILE != NULL)
	{
#if _WIN32
		// Disable buffering entirely
		setvbuf(gOutputFILE, NULL, _IONBF, 0);

		// Apply the suggested (or default) file permissions
		_chmod(buffer, (gOutputPerms) ? gOutputPerms : 0600);
#else
		// Enable line buffering
		setvbuf(gOutputFILE, NULL, _IOLBF, 0);
		
		// Apply the suggested (or default) file permissions
		fchmod(gOutputFileNo, (gOutputPerms) ? gOutputPerms : 0600);

		// Cache the file number that matches the FILE
		gOutputFileNo = fileno(gOutputFILE);
#endif // _WIN32
	}
	else
	{
		// Default back to stderr
		gOutputFILE = stderr;
#if ! _WIN32
		gOutputFileNo = STDERR_FILENO;
#endif // ! _WIN32
	}
}

// Close the previous log file, if any
static void _DebugCloseLogFile()
{
	if (gOutputFILE && (gOutputFILE != stderr))
	{
		fclose(gOutputFILE);
		gOutputFILE = stderr;
#if ! _WIN32
		gOutputFileNo = STDERR_FILENO;
#endif // ! _WIN32
	}
#if ! _WIN32
	else if (gOutputFileNo && (gOutputFileNo != -1))
	{
		close(gOutputFileNo);
		gOutputFileNo = STDERR_FILENO;
	}
#endif // ! _WIN32
}

// Write a log header to the file
static void _DebugWriteHeader()
{
	time_t		now;
	char		stamp[64] = "";

	// Print a pretty header
	time(&now);
#if _WIN32
	ctime_s(stamp, sizeof(stamp), &now);
#else
	ctime_r(&now, stamp);
#endif // _WIN32
	strtok(stamp, "\n");
	fprintf(gOutputFILE, "--- Log opened %s ---\n", stamp);
}

// Write a log footer to the file
static void _DebugWriteFooter()
{
	time_t		now;
	char		stamp[64] = "";

	// Print a pretty trailer
	time(&now);
#if _WIN32
	ctime_s(stamp, sizeof(stamp), &now);
#else
	ctime_r(&now, stamp);
#endif // _WIN32
	strtok(stamp, "\n");
	fprintf(gOutputFILE, "--- Log closed %s ---\n", stamp);
}

#if 0
#pragma mark -
#endif

void DebugPreflight(const char *logname, bool UNUSED(redirect), int level, int perms)
{
	_DebugEnter();
	
	if (logname && *logname)
	{
		// If we've preflighted already, close the previous log
		_DebugCloseLogFile();

		// Determine where the new log file will go
		_DebugNameLogFile(logname, gOutputPath, sizeof(gOutputPath));
		if (perms) gOutputPerms = perms;

		// Open the new file and use it's file descriptor for our logging
		_DebugOpenLogFile();
		if (gOutputFILE == NULL) goto CLEANUP;
	}
	else if (! gPreflighted)
	{
		// Default to stderr if no name is specifieds
		gOutputFILE = stderr;
#if ! _WIN32
		gOutputFileNo = STDERR_FILENO;
#endif // ! _WIN32
	}
	
	if (! gPreflighted)
	{
		// Prefix the file with a pretty header
		_DebugWriteHeader();

		// Ensure this has been preflighted as well
		if (gDebugLevel == 1)
			SetDebugLevel(level);
		else
			DebugLevel();
		
		gPreflighted = true;
	}

CLEANUP:
	_DebugLeave();
}

void DebugPostflight()
{
	_DebugEnter();
	
	// Close the existing log, if any
	if (gPreflighted)
		_DebugWriteFooter();
	_DebugCloseLogFile();

	gPreflighted = false;

	_DebugLeave();
}

static void _DebugSwitchLogFile(const char *renameTo, const char *switchTo)
{
	// Close the existing log
	_DebugWriteFooter();
	_DebugCloseLogFile();
	
	if (renameTo)
	{
		char		renameBuffer[MAX_PATH_LENGTH + 1] = "";

		// Rename the existing log file, still output to the same path
		_DebugNameLogFile(renameTo, renameBuffer, sizeof(renameBuffer));
		rename(gOutputPath, renameBuffer); // Will unlink existing file
	}
	else if (switchTo)
	{
		// Switch our target to the indicated path
		_DebugNameLogFile(switchTo, gOutputPath, sizeof(gOutputPath));
	}

	// Open a new file and use it's file descriptor for our logging
	_DebugOpenLogFile();
	if (gOutputFILE)
		_DebugWriteHeader();
	else
		gPreflighted = false;
}

void DebugSwitchLogFile(const char *newFileName)
{
	_DebugEnter();

	if (! gPreflighted)
		DebugPreflight(newFileName, false, DEBUG_LEVEL_ERROR, 0);
	else if (newFileName)
		_DebugSwitchLogFile(NULL, newFileName);

	_DebugLeave();
}

void DebugRotateLogFile(const char *newFileName)
{
	_DebugEnter();

	if (! gPreflighted)
		DebugPreflight(newFileName, false, DEBUG_LEVEL_ERROR, 0);
	else if (newFileName)
		_DebugSwitchLogFile(newFileName, NULL);

	_DebugLeave();
}

char * CopyDebugHistory()
{
	// Unused in this implementation
	return NULL;
}

#if 0
#pragma mark -
#endif

void DebugMessage(int UNUSED(level), const char *format, ...)
{
	const char *	eol = "";
	char			stamp[24] = "";
	char *			buffer = NULL;
	size_t			length;
	va_list			args;
	
	if (gDebugEnabled)
	{
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, false, DEBUG_LEVEL_ERROR, 0);

		// Optionally prefix the entry with a timestamp
		if (gDebugStamp)
		{
			struct tm	ltime;
			time_t		now = time(NULL);

#if _WIN32
			localtime_s(&ltime, &now);
#else
			localtime_r(&now, &ltime);
#endif // _WIN32
			strftime(stamp, sizeof(stamp), "[%F %T] ", &ltime);
		}
		
		// Format the message into an editable buffer
		va_start(args, format);
		length = vsnprintf(NULL, 0, format, args);
		if ((buffer = calloc(1, length + 1)) != NULL)
			vsnprintf(buffer, length + 1, format, args);
		va_end(args);
		
		if (buffer)
		{
#if DEBUG_SHORTEN_PATHS
			// Remove the leading path components in the buffer
			_DebugShortenPath(buffer);
#endif // DEBUG_SHORTEN_PATHS

			// Append a trailing linefeed if necessary
			length = strlen(buffer);
			if (length && (buffer[length-1] != '\n'))
				eol = "\n";

			// Print out the requested message
			fprintf(gOutputFILE, "%s%s%s", stamp, buffer, eol);
			free(buffer);
		}
			
		_DebugLeave();
	}
}


void DebugData(const char *label, const void *data, size_t length)
{
	unsigned char *	bytes = (unsigned char *)data;
	char			table[] = "0123456789ABCDEF";
	char			hex[37], ascii[18];
	char *			buffer = NULL;
	size_t			i, j, k, x, y;

	if (gDebugEnabled)
	{
		// Allocate a scratch buffer for the output
		buffer = (char *) calloc((length + 15) * 80 / 16, 1);
		
		// Loop over the data, marking the end of our progress after each loop
		if (buffer) for(i=k=0; i<length; )
		{
			// Iterate the data block, processing 16 bytes of data on each line
			for(j=0, x=y=0; j<16; i++, j++)
			{
				if (i < length)
				{
					hex[x++] = table[bytes[i] >> 4];
					hex[x++] = table[bytes[i] & 0x0F];
					ascii[y++] = ((bytes[i] < 0x20) || (bytes[i] > 0x7E)) ? '*' : bytes[i];
				}
				else
				{
					hex[x++] = ':';
					hex[x++] = ':';
					ascii[y++] = ':';
				}

				if ((x+1)%9 == 0) hex[x++] = ' ';
			}

			// Now format the string nicely into our buffer, and advance our mark
			hex[x] = 0;
			ascii[y] = 0;
#if __LP64__
			k += sprintf(buffer + k, "  0x%.16" PRIXPTR " | %s| %s\n", (uintptr_t)(bytes + i), hex, ascii);
#else
			k += sprintf(buffer + k, "  0x%.8" PRIXPTR " | %s| %s\n", (uintptr_t)(bytes + i), hex, ascii);
#endif // __LP64__
		}
		
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, false, DEBUG_LEVEL_ERROR, 0);
		
		// Now that we have the data, print out the label and our buffer
		fprintf(gOutputFILE, "%s (%zu bytes):\n%s", label, length, 
				(buffer) ? buffer : " -- out of memory --\n");
			
		_DebugLeave();
		free(buffer);
	}
}

void SetDebugEnabled(int enable)
{
	gDebugEnabled = (enable) ? true : false;
}

void SetDebugTimestamp(bool showTimestamp)
{
	gDebugStamp = showTimestamp;
}

bool DebugTimestamp()
{
	return gDebugStamp;
}

void SetDebugLevel(int level)
{
	if (level > DEBUG_LEVEL_NONE)
		level = DEBUG_LEVEL_NONE;
	_DebugEnter();
	gDebugLevel = level;
	_DebugLeave();
}

int DebugLevel(void)
{
	if (gDebugLevel == 1)
	{
		// Default to highest level
		int		useLevel = DEBUG_LEVEL_FAILURE;
		
		_DebugEnter();
		
		if (gDebugLevel == 1)
		{
			// Initialize from the environment, if any
			char *level = getenv(DEBUG_LEVEL_ENV_VAR);

			if (level)
			{
				int value = (int)strtol(level, NULL, 10);
				
				if (value <= 0)
				{
					gDebugLevel = value;
					gDebugMask = 0;
				}
				else
				{
					gDebugMask = value;
					gDebugLevel = DEBUG_LEVEL_ERROR;
				}
				
				useLevel = gDebugLevel;
			}
		}
		else
			useLevel = gDebugLevel;
				
		_DebugLeave();
		
		return useLevel;
	}
	else
		return gDebugLevel;
}

void SetDebugMask(int mask)
{
	if (mask < 0)
		mask = 0;
	_DebugEnter();
	gDebugMask = mask;
	_DebugLeave();
}

int DebugMask(void)
{
	if (gDebugLevel == 1)
		DebugLevel(); // Initialize settings

	return gDebugMask;
}

bool DebugShouldLog(int value)
{
	bool shouldLog = true;
	
	_DebugEnter();
	if (value < 0)
		shouldLog = (DebugLevel() <= value) ? true : false;
	else 
		shouldLog = (DebugMask() & value) ? true : false;
	_DebugLeave();
	
	return shouldLog;
}

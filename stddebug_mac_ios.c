/*!
	@file stddebug_mac_ios.c
	@abstract Common debugging utilities
	@copyright (c) 1997-2022 by Matt Slot <mattslot@gmail.com>.
	
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
		Standard implementation of debug routines based on POSIX APIs,
		with extensions for MacOS X and iOS.

		Specify the absolute path to a log file to direct messages there.
		Specify a short name for the log file to use the standard location:
			Mac: /var/log/name.log  -or-  ~/Library/Logs/name.log
			UNIX: /var/log/name.log  -or-  ~/log/name.log
		Pass nil to direct messages to the console via stderr.
*/ 

#include "stddebug.h"

#include <TargetConditionals.h>

#if !TARGET_OS_MAC && !TARGET_OS_IPHONE
	#error "MacOS X and iOS specific implementation"
#endif // !TARGET_OS_MAC && !TARGET_OS_IPHONE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <time.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#if TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64
	#include <libproc.h>
#endif // TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64


static	bool						gPreflighted = 0;
static	int							gOutputFileNo = -1;
static	FILE *						gOutputFILE = NULL;
static	char						gOutputPath[PATH_MAX+1] = "";
static	int							gOutputPerms = 0600;

static	bool						gDebugEnabled = 1;
static	int							gDebugLevel = 1;
static	int							gDebugMask = 0;
static	unsigned					gDebugStamp = 0;

static	pthread_mutex_t				gMutex = PTHREAD_MUTEX_INITIALIZER;
static	pthread_t					gMutexThread = NULL;
static	int							gMutexRecurse = 0;

static void _DebugEnter()
{
	if (!pthread_equal(gMutexThread, pthread_self()))
		pthread_mutex_lock(&gMutex);
	gMutexThread = pthread_self();
	gMutexRecurse++;
}

static void _DebugLeave()
{
	if (!--gMutexRecurse) 
	{
		gMutexThread = NULL;
		pthread_mutex_unlock(&gMutex);
	}
}

static char *_DebugShortenPath(char *path)
{
	char *mark1 = strrchr(path, '@');
	if (mark1 && ! strncmp(mark1, "@ /", 3))
	{
		char *mark2 = strrchr(path, '/');
		memmove(mark1 + 2, mark2 + 1, strlen(mark2));
	}
	
	return path;
}

// Generate an absolute path based on the suggested name
static void _DebugNameLogFile(const char *input, char *output, size_t maxlen)
{
	// Clear the output buffer, ensure zero terminator
	memset(output, 0, maxlen);

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
		// Enable line buffering
		setvbuf(gOutputFILE, NULL, _IOLBF, 0);
		
		// Cache the file number that matches the FILE
		gOutputFileNo = fileno(gOutputFILE);

		// Apply the suggested (or default) file permissions
		if (gOutputFileNo != -1)
			fchmod(gOutputFileNo, (gOutputPerms) ? gOutputPerms : 0600);
	}
	else
	{
		// Default back to stderr
		gOutputFILE = stderr;
		gOutputFileNo = STDERR_FILENO;
	}
}

// Close the previous log file, if any
static void _DebugCloseLogFile()
{
	if (gOutputFILE && (gOutputFILE != stderr))
	{
		fclose(gOutputFILE);
		gOutputFILE = stderr;
		gOutputFileNo = STDERR_FILENO;
	}
	else if (gOutputFileNo && (gOutputFileNo != -1))
	{
		close(gOutputFileNo);
		gOutputFileNo = STDERR_FILENO;
	}
}

// Write a log header to the file
static void _DebugWriteHeader()
{
	time_t		now;
	char		stamp[64] = "";
	char		name[PATH_MAX] = "";
	char		vers[32] = "";
	CFStringRef cfstr = NULL;

	// Print a pretty header
	time(&now);
	ctime_r(&now, stamp);
	strtok(stamp, "\n");
	fprintf(gOutputFILE, "--- Log opened %s ---\n", stamp);

	// Including the bundle or executable name and version
#if TARGET_OS_MAC || TARGET_OS_IPHONE
	if ((cfstr = (CFStringRef) CFBundleGetValueForInfoDictionaryKey(
			CFBundleGetMainBundle(), CFSTR("CFBundleName"))))
		CFStringGetCString(cfstr, name, sizeof(name), kCFStringEncodingUTF8);
	if ((cfstr = (CFStringRef) CFBundleGetValueForInfoDictionaryKey(
			CFBundleGetMainBundle(), CFSTR("CFBundleVersion"))))
		CFStringGetCString(cfstr, vers, sizeof(vers), kCFStringEncodingUTF8);
	if (*name)
		fprintf(gOutputFILE, "--- %s %s ---\n", name, vers);
#endif // TARGET_OS_MAC || TARGET_OS_IPHONE
#if TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64
	else
	{
		// Handle non-bundle processes (daemons, command-line tools)
		proc_name(getpid(), name, (uint32_t) sizeof(name));
		if (*name) 
#if defined(VERSION)
			fprintf(gOutputFILE, "--- %s %s ---\n", name, VERSION);
#else
			fprintf(gOutputFILE, "--- %s ---\n", name);
#endif // VERSION
	}
#endif // TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64
}

// Write a log footer to the file
static void _DebugWriteFooter()
{
	time_t		now;
	char		stamp[64] = "";

	// Print a pretty trailer
	time(&now);
	ctime_r(&now, stamp);
	strtok(stamp, "\n");
	fprintf(gOutputFILE, "--- Log closed %s ---\n", stamp);
}

// Based on https://stackoverflow.com/a/60254428
// Pass 30 bytes of storage for microsecond accuracy.
static char * _DebugFormatTimestamp(char *buffer, size_t length, unsigned accuracy)
{
	struct timespec			ts;
	struct tm				ltime;

	if (accuracy && 
			(0 == clock_gettime(CLOCK_REALTIME, &ts)) && 
			(NULL != localtime_r(&ts.tv_sec, &ltime)))
	{
		double				scalar = 0;
		int					digits = 0;
		long				decimal = 0;

		if (accuracy >= 1000000)
			{ scalar = 1000; digits = 6; }
		else if (accuracy >= 1000)
			{ scalar = 1000000; digits = 3; }
	
		if (scalar)
		{
			char			ymdhms[24];

			// round nanoseconds to desired resolution
			if (ts.tv_nsec + scalar / 2 >= 1000000000)
				{ ts.tv_sec++; decimal = 0; }
			else
				decimal = (ts.tv_nsec + scalar / 2) / scalar;

			strftime(ymdhms, sizeof(ymdhms), "%Y-%m-%d %H:%M:%S", &ltime);
			snprintf(buffer, length, "[%s.%0*li] ", ymdhms, digits, decimal);
		}
		else
			strftime(buffer, length, "[%Y-%m-%d %H:%M:%S] ", &ltime);
	}
    else
		buffer[0] = 0;
	
	return buffer;
}

#if 0
#pragma mark -
#endif

void DebugPreflight(const char *logname, bool redirect, int level, int perms)
{
	_DebugEnter();
	
	// Ignore logfile directives on iOS -- we always go to stderr
#if !TARGET_OS_IPHONE
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
	else 
#endif // !TARGET_OS_IPHONE
	if (! gPreflighted)
	{
		// Default to stderr if no name is specifieds
		gOutputFILE = stderr;
		gOutputFileNo = STDERR_FILENO;
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
		char		renameBuffer[PATH_MAX + 1] = "";

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

__DEBUGSTR_TYPE__ CopyDebugHistory()
{
	return NULL; // Unused in this implementation
}

#if 0
#pragma mark -
#endif

void DebugMessage(int level, __DEBUGSTR_ARG__ format, ...)
{
	va_list			args;
	CFIndex			index;
	CFStringRef		cfstr = NULL;
	const char *	cstr = NULL;
	char *			buffer = NULL;
	
	if (gDebugEnabled)
	{
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, false, DEBUG_LEVEL_ERROR, 0);
		
		// Format the string, accepting %@ qualifier for CFType/NSObject
		va_start(args, format);
		cfstr = CFStringCreateWithFormatAndArguments(
				kCFAllocatorDefault, NULL, format, args);
		va_end(args);
		
		// Convert the opaque CFStringRef to a UTF8 buffer
		if (cfstr)
		{
#if ! DEBUG_SHORTEN_PATHS
			// Try for the fast case, fall back to buffering otherwise
			cstr = CFStringGetCStringPtr(cfstr, kCFStringEncodingUTF8);
#endif // ! DEBUG_SHORTEN_PATHS
			if (!cstr)
			{
				// Maximum conversion per UTF8 character = 4 bytes
				size_t buflen = CFStringGetLength(cfstr) * 4 + 1;
				if ((buffer = malloc(CFStringGetLength(cfstr) * 4 + 1)) &&
						CFStringGetCString(cfstr, buffer, buflen, kCFStringEncodingUTF8))
				{
#if DEBUG_SHORTEN_PATHS
					cstr = _DebugShortenPath(buffer);
#else
					cstr = buffer;
#endif // DEBUG_SHORTEN_PATHS
				}
			}
		}
		
		if (cstr)
		{
			char			stamp[32] = "";
			const char *	eol = "";

			// Optionally prefix the entry with a timestamp
			_DebugFormatTimestamp(stamp, sizeof(stamp), gDebugStamp);
		
			// Append a trailing linefeed if necessary
			index = CFStringGetLength(format);
			if (index && (CFStringGetCharacterAtIndex(format,index-1) != '\n'))
				eol = "\n";

			// Print out the requested message
			fprintf(gOutputFILE, "%s%s%s", stamp, cstr, eol);
		}
			
		_DebugLeave();

		// Free any allocated buffers
		if (cfstr) CFRelease(cfstr);
		free(buffer);
	}
}


void DebugData(const char *label, const void *data, size_t length)
{
	unsigned char *	bytes = (unsigned char *)data;
	char			table[] = "0123456789ABCDEF";
	char			hex[37], ascii[18];
	char			stamp[32] = "";
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
		
		// Optionally prefix the entry with a timestamp
		_DebugFormatTimestamp(stamp, sizeof(stamp), gDebugStamp);
	
		// Now that we have the data, print out the label and our buffer
		fprintf(gOutputFILE, "%s%s (%zu bytes):\n%s", stamp, label, length, 
				(buffer) ? buffer : " -- out of memory --\n");
			
		_DebugLeave();
		free(buffer);
	}
}

void SetDebugEnabled(int enable)
{
	gDebugEnabled = (enable) ? true : false;
}

void SetDebugTimestamp(unsigned showTimestamp)
{
	if (showTimestamp >= 1000000)
		gDebugStamp = 1000000; // microseconds
	else if (showTimestamp >= 1000)
		gDebugStamp = 1000; // milliseconds
	else if (showTimestamp)
		gDebugStamp = 1; // seconds
	else
		gDebugStamp = 0; // disabled
}

unsigned DebugTimestamp()
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
	bool shouldLog = false;
	
	if (value < 0)
		shouldLog = (DebugLevel() <= value) ? true : false;
	else 
		shouldLog = (DebugMask() & value) ? true : false;
	
	return shouldLog;
}

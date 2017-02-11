/*!
	@file stddebug_mac_ios_buffered.c
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
		Standard implementation of debug routines based on POSIX APIs, 
		with extensions for MacOS X and iOS. This version writes log
		messages to a memory buffer for later email/web submission.
*/ 

#include "stddebug.h"

#include <TargetConditionals.h>

#if !TARGET_OS_MAC && !TARGET_OS_IPHONE
	#error "MacOS X and iOS specific implementation"
#endif // !TARGET_OS_MAC && !TARGET_OS_IPHONE

#include <errno.h>
#include <fcntl.h>
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
static	bool						gDebugEnabled = 1;
static	CFMutableStringRef			gOutputBuffer = NULL;
static	int							gDebugLevel = 1;
static	int							gDebugMask = 0;
static	bool						gDebugStamp = 0;

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

static void _DebugPrintf(const CFStringRef format, ...)
{
	va_list			args;
	CFStringRef		cfstr = NULL;

	if (!gOutputBuffer)
		gOutputBuffer = CFStringCreateMutable(NULL, 0);
	
	va_start(args, format);
	cfstr = CFStringCreateWithFormatAndArguments(NULL, NULL, format, args);
	va_end(args);

	if (cfstr)
	{
#if TARGET_IPHONE_SIMULATOR
		char *		buffer = NULL;
		size_t		length;

		if ((buffer = (char *)CFStringGetCStringPtr(cfstr, kCFStringEncodingUTF8)))
			fprintf(stderr, "%s", buffer);
		else
		{
			length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(cfstr), kCFStringEncodingUTF8);
			buffer = calloc(sizeof(char), length + 1);
	
			if (buffer && CFStringGetCString(cfstr, buffer, length + 1, kCFStringEncodingUTF8))
				fprintf(stderr, "%s", buffer);

			free(buffer);
		}
#endif // TARGET_IPHONE_SIMULATOR

		if (gOutputBuffer)
			CFStringAppend(gOutputBuffer, cfstr);
	
		CFRelease(cfstr);
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

void DebugPreflight(const char *logname, int redirect, int level, int perms)
{
	_DebugEnter();
	
	if (!gOutputBuffer)
		gOutputBuffer = CFStringCreateMutable(NULL, 0);
	
	if (!gPreflighted)
	{
		time_t		now;
		char		stamp[26] = "";
		char		name[PATH_MAX] = "";
		char		vers[32] = "";
		CFStringRef cfstr = NULL;

		// Print a pretty header
		time(&now);
		ctime_r(&now, stamp);
		strtok(stamp, "\n");
		_DebugPrintf(CFSTR("--- Log opened %s ---\n"), stamp);

#if TARGET_OS_MAC || TARGET_OS_IPHONE
		if ((cfstr = (CFStringRef) CFBundleGetValueForInfoDictionaryKey(
				CFBundleGetMainBundle(), CFSTR("CFBundleName"))))
			CFStringGetCString(cfstr, name, sizeof(name), kCFStringEncodingUTF8);
		if ((cfstr = (CFStringRef) CFBundleGetValueForInfoDictionaryKey(
				CFBundleGetMainBundle(), CFSTR("CFBundleVersion"))))
			CFStringGetCString(cfstr, vers, sizeof(vers), kCFStringEncodingUTF8);
		if (*name)
			_DebugPrintf(CFSTR("--- %s %s ---\n"), name, vers);
#endif // TARGET_OS_MAC || TARGET_OS_IPHONE
#if TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64
		else
		{
			// Handle non-bundle processes (daemons, command-line tools)
			proc_name(getpid(), name, (uint32_t) sizeof(name));
			if (*name) 
  #if defined(VERSION)
				_DebugPrintf(CFSTR("--- %s %s ---\n"), name, VERSION);
  #else
				_DebugPrintf(CFSTR("--- %s ---\n"), name);
  #endif // VERSION
		}
#endif // TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64

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
	
	if (gPreflighted)
	{
		time_t		now;
		char		stamp[26] = "";

		// Print a pretty trailer
		time(&now);
		ctime_r(&now, stamp);
		strtok(stamp, "\n");
		_DebugPrintf(CFSTR("--- Log closed %s ---\n"), stamp);

		gPreflighted = false;
	}
	
	_DebugLeave();
}

void DebugMessage(int level, CFStringRef format, ...)
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
			char			stamp[24] = "";
			const char *	eol = "";

			// Optionally prefix the entry with a timestamp
			if (gDebugStamp)
			{
				struct tm	ltime;
				time_t		now = time(NULL);

				strftime(stamp, sizeof(stamp), "[%F %T] ", localtime_r(&now, &ltime));
			}
		
			// Append a trailing linefeed if necessary
			index = CFStringGetLength(format);
			if (index && (CFStringGetCharacterAtIndex(format,index-1) != '\n'))
				eol = "\n";
		
			// Print out the requested message
			_DebugPrintf(CFSTR("%s%s%s"), stamp, cstr, eol);
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
					hex[x++] = ':', hex[x++] = ':', ascii[y++] = ':';

				if ((x+1)%9 == 0) hex[x++] = ' ';
			}

			// Now format the string nicely into our buffer, and advance our mark
			hex[x] = 0, ascii[y] = 0;
#if __LP64__
			k += sprintf(buffer + k, "  0x%.16lX | %s| %s\n", (uintptr_t)(bytes + i), hex, ascii);
#else
			k += sprintf(buffer + k, "  0x%.8lX | %s| %s\n", (uintptr_t)(bytes + i), hex, ascii);
#endif // __LP64__
		}
		
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, false, DEBUG_LEVEL_ERROR, 0);
		
		// Now that we have the data, print out the label and our buffer
		_DebugPrintf(CFSTR("%s (%lu bytes):\n%s"), label, length, 
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
		_DebugEnter();
		
		if (gDebugLevel == 1)
		{
			char *level = getenv(DEBUG_LEVEL_ENV_VAR);
			int value = (level) ? (int)strtol(level, NULL, 10) : DEBUG_LEVEL_FAILURE;

			if (value <= 0)
				gDebugLevel = value, gDebugMask = 0;
			else
				gDebugMask = value, gDebugLevel = DEBUG_LEVEL_ERROR;
		}
		
		_DebugLeave();
	}

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
	return gDebugMask;
}

int DebugShouldLog(int value)
{
	int shouldLog = 0;
	
	_DebugEnter();
	if (value < 0)
		shouldLog = (gDebugLevel <= value) ? 1 : 0;
	else 
		shouldLog = (gDebugMask & value) ? 1 : 0;
	_DebugLeave();
	
	return shouldLog;
}

CFStringRef CopyDebugHistory(void)
{
	CFStringRef		string = NULL;
	
	_DebugEnter();
	
	if (gOutputBuffer)
		string = CFStringCreateCopy(NULL, gOutputBuffer);
	else
		string = CFSTR("");
	
	_DebugLeave();

	return string;
}

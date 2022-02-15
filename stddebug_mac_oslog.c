/*!
	@file stddebug_mac_oslog.c
	@abstract Common debugging utilities
	@copyright (c) 1997-2021 by Matt Slot <mattslot@gmail.com>.
	
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
		Standard implementation of debug routines based on macOS oslog APIs.

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

#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <os/log.h>

#include <CoreFoundation/CoreFoundation.h>
#if TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64
	#include <libproc.h>
#endif // TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64


static	bool						gPreflighted = 0;
static	os_log_t					gOutputOSLog = NULL;

static	bool						gDebugEnabled = 1;
static	int							gDebugLevel = 1;
static	int							gDebugMask = 0;

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

// Open a stream for logging
static void _DebugOpenLogStream(const char *logname)
{
	CFStringRef 	bundleID = NULL;
	char *			buffer = NULL;
	CFIndex			length = 0;
	
	if (! logname || ! *logname)
	{
		if ((bundleID = CFBundleGetIdentifier(CFBundleGetMainBundle())))
		{
			logname = CFStringGetCStringPtr(bundleID, kCFStringEncodingUTF8);
			if (! logname)
			{
				length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(bundleID), kCFStringEncodingUTF8);
				buffer = (char *)calloc(length + 1, 1);
				if (buffer && CFStringGetCString(bundleID, buffer, length + 1, kCFStringEncodingUTF8))
					logname = buffer;
			}
		}
		else
			// Fall back to a fixed string
			logname = "com.mattslot.stddebug";
	}

	if (logname && *logname)
		gOutputOSLog = os_log_create(logname, "stddebug");
	
	free(buffer);
}

// Close the logging stream
static void _DebugCloseLogStream()
{
	// No explicit close API, just forget the pointer
	gOutputOSLog = NULL;
}

// Write a log header to the file
static void _DebugWriteHeader()
{
	char		name[PATH_MAX] = "";
	char		vers[32] = "";
	CFStringRef cfstr = NULL;

	// Print a pretty header
	os_log_with_type(gOutputOSLog, OS_LOG_TYPE_DEFAULT, "--- Log opened ---");

	// Including the bundle or executable name and version
#if TARGET_OS_MAC || TARGET_OS_IPHONE
	if ((cfstr = (CFStringRef) CFBundleGetValueForInfoDictionaryKey(
			CFBundleGetMainBundle(), CFSTR("CFBundleName"))))
		CFStringGetCString(cfstr, name, sizeof(name), kCFStringEncodingUTF8);
	if ((cfstr = (CFStringRef) CFBundleGetValueForInfoDictionaryKey(
			CFBundleGetMainBundle(), CFSTR("CFBundleVersion"))))
		CFStringGetCString(cfstr, vers, sizeof(vers), kCFStringEncodingUTF8);
	if (*name)
		os_log_with_type(gOutputOSLog, OS_LOG_TYPE_DEFAULT, "--- %{public}s %{public}s ---", name, vers);
#endif // TARGET_OS_MAC || TARGET_OS_IPHONE
#if TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64
	else
	{
		// Handle non-bundle processes (daemons, command-line tools)
		proc_name(getpid(), name, (uint32_t) sizeof(name));
		if (*name) 
#if defined(VERSION)
			os_log_with_type(gOutputOSLog, OS_LOG_TYPE_DEFAULT, "--- %{public}s %{public}s ---", name, VERSION);
#else
			os_log_with_type(gOutputOSLog, OS_LOG_TYPE_DEFAULT, "--- %{public}s ---", name);
#endif // VERSION
	}
#endif // TARGET_OS_MAC && !TARGET_CPU_ARM && !TARGET_CPU_ARM64
}

// Write a log footer to the file
static void _DebugWriteFooter()
{
	// Print a pretty trailer
	os_log_with_type(gOutputOSLog, OS_LOG_TYPE_DEFAULT, "--- Log closed ---");
}

#if 0
#pragma mark -
#endif

void DebugPreflight(const char *logname, bool redirect, int level, int perms)
{
	_DebugEnter();
	
	if (logname && *logname)
		// If we've preflighted already, close the previous log
		_DebugCloseLogStream();

	// Open the new file and use it's file descriptor for our logging
	_DebugOpenLogStream(logname);
	if (gOutputOSLog) _DebugWriteHeader();

	// Ensure this has been preflighted as well
	if (gDebugLevel == 1)
		SetDebugLevel(level);
	else
		DebugLevel();

CLEANUP:
	gPreflighted = (gOutputOSLog) ? true : false;

	_DebugLeave();
}

void DebugPostflight()
{
	_DebugEnter();
	
	// Close the existing log, if any
	if (gOutputOSLog) _DebugWriteFooter();
	_DebugCloseLogStream();

	gPreflighted = false;

	_DebugLeave();
}

void DebugSwitchLogFile(const char *newLogName)
{
	_DebugEnter();

	if (! gPreflighted)
		DebugPreflight(newLogName, false, DEBUG_LEVEL_ERROR, 0);
	else if (newLogName)
	{
		// Close the existing log
		if (gOutputOSLog) _DebugWriteFooter();
		_DebugCloseLogStream();
		
		// Open a new one
		_DebugOpenLogStream(newLogName);
		if (gOutputOSLog) _DebugWriteHeader();
	}

	_DebugLeave();
}

void DebugRotateLogFile(const char *newFileName)
{
	_DebugEnter();

	if (! gPreflighted)
		DebugPreflight(newFileName, false, DEBUG_LEVEL_ERROR, 0);
	else if (newFileName)
		; // Nothing to do, we can't rotate the logs

	_DebugLeave();
}

__DEBUGSTR_TYPE__ CopyDebugHistory()
{
	return NULL; // Unused in this implementation
}

#if 0
#pragma mark -
#endif

static os_log_type_t DebugLevelToOSLogType(int level)
{
	if (level > 0)
		return OS_LOG_TYPE_DEFAULT;
	else switch(level)
	{
		case DEBUG_LEVEL_ALWAYS:
			return OS_LOG_TYPE_DEFAULT;
		case DEBUG_LEVEL_FAILURE:
			return OS_LOG_TYPE_FAULT;
		case DEBUG_LEVEL_ERROR:
			return OS_LOG_TYPE_ERROR;
		case DEBUG_LEVEL_WARN:
		case DEBUG_LEVEL_DEBUG:
			return OS_LOG_TYPE_DEBUG;
		case DEBUG_LEVEL_INFO:
		case DEBUG_LEVEL_SPAM:
		case DEBUG_LEVEL_NEVER:
			return OS_LOG_TYPE_INFO;
		default:
			return OS_LOG_TYPE_DEFAULT;
	}
}

void DebugMessage(int level, __DEBUGSTR_ARG__ format, ...)
{
	va_list			args;
	CFStringRef		cfstr = NULL;
	const char *	cstr = NULL;
	char *			buffer = NULL;
	
	if (gDebugEnabled)
	{
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, false, DEBUG_LEVEL_ERROR, 0);
		if (! gOutputOSLog)
			goto CLEANUP;
			
		
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
			os_log_with_type(gOutputOSLog, DebugLevelToOSLogType(level), "%{public}s", cstr);

CLEANUP:			
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
			k += snprintf(buffer + k, 80, "  0x%.16" PRIXPTR " | %s| %s\n", (uintptr_t)(bytes + i), hex, ascii);
		}
		
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, false, DEBUG_LEVEL_ERROR, 0);
	
		// Now that we have the data, print out the label and our buffer
		if (gOutputOSLog) os_log_with_type(gOutputOSLog, OS_LOG_TYPE_DEFAULT, 
				"%{public}s (%zu bytes):\n%{public}s", label, length, 
				(buffer) ? buffer : " -- out of memory --");
			
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
	; // Unused
}

unsigned DebugTimestamp()
{
	return 0;
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

/*!
	@file stddebug_syslog.c
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
		Standard implementation of debug routines based on syslog facility.
*/ 

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
#include <syslog.h>
#include <time.h>

#if !_WIN32
#include <unistd.h>
#endif // !_WIN32

#include "stddebug.h"


static	char *						gIdentString = NULL;
static	bool						gPreflighted = 0;
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

static int _DebugLevelToSyslogPriority(int level)
{
	// Note that level could be a bitmask or a negative constant
	switch(level)
	{
		case DEBUG_LEVEL_NONE:
			return LOG_NOTICE;
		case DEBUG_LEVEL_FATAL:
			return LOG_CRIT;
		case DEBUG_LEVEL_FAILURE:
		case DEBUG_LEVEL_ERROR:
			return LOG_ERR;
		case DEBUG_LEVEL_WARN:
			return LOG_WARNING;
		case DEBUG_LEVEL_DEBUG:
			// This constant is intended to annotate debugging details during
			// development and testing, and is higher priority than INFO, SPAM
			return LOG_NOTICE;
		case DEBUG_LEVEL_INFO:
			return LOG_INFO;
		case DEBUG_LEVEL_SPAM:
			return LOG_DEBUG;
	}
	
	return LOG_INFO;
}

#if 0
#pragma mark -
#endif

void DebugPreflight(const char *logname, bool redirect, int level, int perms)
{
	_DebugEnter();
	
	// logname = syslog "ident" string, prefixed to each line of output
	// redirect = ignored
	// level = stddebug threshold
	
	// The ident parameter is not copied by openlog(), but stashed and
	// referenced later. For safety's sake, we create a persistent copy.
	free(gIdentString);
	gIdentString = (logname) ? strdup(logname) : NULL;

	openlog(gIdentString, 0, 0);
	
	if (!gPreflighted)
	{
		time_t		now;
		char		stamp[24] = "";

		// Print a pretty header
		time(&now);
		ctime_r(&now, stamp);
		strtok(stamp, "\n");
		syslog(LOG_NOTICE, "--- Log opened %s ---\n", stamp);

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
		syslog(LOG_NOTICE, "--- Log closed %s ---\n", stamp);
		
		closelog();

		free(gIdentString);
		gIdentString = NULL;
		gPreflighted = false;
	}
	
	_DebugLeave();
}

void DebugSwitchLogFile(const char *newFileName)
{
	; // Unused in this implementation
}

void DebugRotateLogFile(const char *newFileName)
{
	; // Unused in this implementation
}

char * CopyDebugHistory()
{
	return NULL; // Unused in this implementation
}

#if 0
#pragma mark -
#endif

void DebugMessage(int level, const char *format, ...)
{
	va_list			args;
	size_t			bytes;
	char			stamp[32] = "";
	char *			buffer = NULL;
	
	if (gDebugEnabled)
	{
		int priority = _DebugLevelToSyslogPriority(level);
	
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, false, DEBUG_LEVEL_ERROR, 0);
		
		// Optionally prefix the entry with a timestamp
		_DebugFormatTimestamp(stamp, sizeof(stamp), gDebugStamp);

		// Format the message into an editable buffer
		va_start(args, format);
		length = vsnprintf(NULL, 0, format, args);
		if ((buffer = calloc(1, length + 1)))
			vsnprintf(buffer, length + 1, format, args);
		va_end(args);

		if (buffer)
		{
#if DEBUG_SHORTEN_PATHS
			// Remove the leading path components in the buffer
			_DebugShortenPath(buffer);
#endif // DEBUG_SHORTEN_PATHS

			// Print out the requested message
			syslog(priority, "%s%s", stamp, buffer);
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
		syslog(LOG_INFO, "%%s (%zu bytes):\n%s", stamp, label, length, 
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

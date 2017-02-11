/*!
	@file stddebug_syslog.c
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
		Standard implementation of debug routines based on syslog facility.
*/ 

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
static	bool						gDebugStamp = false;

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

void DebugPreflight(const char *logname, int redirect, int level, int perms)
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

void DebugMessage(int level, const char *format, ...)
{
	va_list			args;
	size_t			bytes;
	char			stamp[24] = "";
	char *			buffer = NULL;
	
	if (gDebugEnabled)
	{
		int priority = _DebugLevelToSyslogPriority(level);
	
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, false, DEBUG_LEVEL_ERROR, 0);
		
		// Optionally prefix the entry with a timestamp
		if (gDebugStamp)
		{
			struct tm	ltime;
			time_t		now = time(NULL);

			strftime(stamp, sizeof(stamp), "[%F %T] ", localtime_r(&now, &ltime));
		}

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
		syslog(LOG_INFO, "%s (%lu bytes):\n%s", label, length, 
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
	if (gDebugLevel == 1)
		DebugLevel(); // Initialize settings

	return gDebugMask;
}

int DebugShouldLog(int value)
{
	int shouldLog = 0;
	
	_DebugEnter();
	if (value < 0)
		shouldLog = (DebugLevel() <= value) ? 1 : 0;
	else 
		shouldLog = (DebugMask() & value) ? 1 : 0;
	_DebugLeave();
	
	return shouldLog;
}

char * CopyDebugHistory()
{
	return NULL;
}

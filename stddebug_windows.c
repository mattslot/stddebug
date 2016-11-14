/*!
	@file stddebug_windows.c
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
		Standard implementation of debug routines based on OutputDebugString.

		Specify the absolute path to a log file to direct messages there.
		Specify a short name for the log file to use the standard location:
			Mac: /var/log/name.log  -or-  ~/Library/Logs/name.log
			UNIX: /var/log/name.log  -or-  ~/log/name.log
		Pass nil to direct messages to the console via OutputDebugString.
*/ 

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "stddebug.h"

static	BOOL						gPreflighted = 0;
static	BOOL						gDebugEnabled = 1;
static	int							gDebugLevel = 1;
static	int							gDebugMask = 0;

static	INIT_ONCE					gInitOnce = INIT_ONCE_STATIC_INIT; 
static	CRITICAL_SECTION			gCriticalSection;

static BOOL CALLBACK PrepareCriticalSection(PINIT_ONCE once, PVOID param, PVOID *context)
{
	InitializeCriticalSection(&gCriticalSection);
	return TRUE;
}

static void _DebugEnter()
{
	InitOnceExecuteOnce(&gInitOnce, PrepareCriticalSection, NULL, NULL);
	EnterCriticalSection(&gCriticalSection);
}

static void _DebugLeave()
{
	LeaveCriticalSection(&gCriticalSection);
}

static char *_DebugShortenPath(char *path)
{
	char *mark1 = strrchr(path, '@');

	// Check whether this looks like the separator between message and path
	if (mark1 && (mark1 != path) && (mark1[-1] == ' ') && (mark1[1] == ' '))
	{
		char *mark2 = strrchr(mark1, '\\');
		if (mark2)
			memmove(mark1 + 2, mark2 + 1, strlen(mark2));
	}
	
	return path;
}

void DebugPreflight(const char *logname, int redirect, int level, int perms)
{
	_DebugEnter();
	
	if (!gPreflighted)
	{
		// Print a pretty header
		OutputDebugString("--- Log opened ---\r\n");

		// Ensure this has been preflighted as well
		if (gDebugLevel == 1)
			SetDebugLevel(level);
		else
			DebugLevel();
		
		gPreflighted = TRUE;
	}

	_DebugLeave();
}

void DebugPostflight()
{
	_DebugEnter();
	
	if (gPreflighted)
	{
		// Print a pretty trailer
		OutputDebugString("--- Log closed ---\r\n");

		gPreflighted = FALSE;
	}
	
	_DebugLeave();
}

void DebugMessage(int level, const char *format, ...)
{
	char *			buffer = NULL;
	size_t			length;
	size_t			bytes;
	va_list			args;
	
	if (gDebugEnabled)
	{
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, FALSE, DEBUG_LEVEL_ERROR, 0);

		// Format the message into an editable buffer
		va_start(args, format);
		length = _vscprintf(format, args);
		bytes = length + strlen("\r\n") + 1;
		if ((buffer = calloc(1, bytes)))
			vsnprintf_s(buffer, length + 1, length + 1, format, args);
		va_end(args);
		
		if (buffer)
		{
#if DEBUG_SHORTEN_PATHS
			// Remove the leading path components
			_DebugShortenPath(buffer);
#endif // DEBUG_SHORTEN_PATHS

			// Append a trailing linefeed if necessary
			length = strlen(format);
			if (length && (format[length-1] != '\r') && (format[length-1] != '\n'))
				strcat_s(buffer, bytes, "\r\n");

			// Print and release the string buffer
			OutputDebugString(buffer);
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
	char *			output = NULL;
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
			k += sprintf_s(buffer + k, 80, "  0x%.16lX | %s| %s\r\n", (uintptr_t)(bytes + i), hex, ascii);
#else
			k += sprintf_s(buffer + k, 80, "  0x%.8lX | %s| %s\r\n", (uintptr_t)(bytes + i), hex, ascii);
#endif // __LP64__
		}
		
		_DebugEnter();
		if (!gPreflighted)
			DebugPreflight(NULL, FALSE, DEBUG_LEVEL_ERROR, 0);
		
		// Now that we have the data, print out the label and our buffer
		i = _scprintf("%s (%lu bytes):\r\n%s", label, length, 
				(buffer) ? buffer : " -- out of memory --\r\n");
		if ((output = (char *) malloc(i+1)))
		{
			_snprintf(output, i+1, "%s (%lu bytes):\r\n%s", label, length, 
					(buffer) ? buffer : " -- out of memory --\r\n");
			OutputDebugString(output);
		}
		else
			OutputDebugString(" -- out of memory --\r\n");
			
		_DebugLeave();
		free(buffer);
		free(output);
	}
}

void SetDebugEnabled(int enable)
{
	gDebugEnabled = (enable) ? TRUE : FALSE;
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
			char *level = NULL;
			int value = DEBUG_LEVEL_FAILURE;

			_dupenv_s(&level, NULL, DEBUG_LEVEL_ENV_VAR);
			if (level) value = (int)strtol(level, NULL, 10);
			
			if (level && (value <= 0))
				gDebugLevel = value, gDebugMask = 0;
			else
				gDebugMask = value, gDebugLevel = DEBUG_LEVEL_ERROR;

			free(level);
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

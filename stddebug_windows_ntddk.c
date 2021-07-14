/*!
	@file stddebug_windows_ntddk.c
	@abstract Common debugging utilities
	@copyright (c) 1997-2017 by Matt Slot <mattslot@gmail.com>.
	
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
		Debug implementations safe for use in Windows kernel drivers.
*/ 

#include "stddebug.h"

#include <ntddk.h>
#include <Ntstrsafe.h>

#pragma comment (lib, "NtosKrnl.lib")
#pragma comment (lib, "Ntstrsafe.lib")


static	bool						gDebugEnabled = 1;
static	int							gDebugLevel = 1;
static	int							gDebugMask = 0;

static bool _IsSafeFormat(const char *string)
{
	bool		isSafe = true;

	for( ; isSafe && *string; string++)
	{
		char c0 = string[0];

		if (c0 == '%')
		{
			char c1 = string[1];
			char c2 = c1 ? string[2] : 0;

			if ((c1 == 'C') || (c1 == 'S')) 
				isSafe = FALSE;
			else if ((c1 == 'l') && ((c2 == 'c') || (c2 == 's')))
				isSafe = FALSE;
			else if ((c1 == 'w') && ((c2 == 'c') || (c2 == 's') || (c2 == 'Z'))) 
				isSafe = FALSE;

			if ((c1 == 'f') || (c1 == 'e') || (c1 == 'E') || 
				(c1 == 'g') || (c1 == 'G') || (c1 == 'a') || (c1 == 'A')) 
				return FALSE; // Not supported at all
		}
	}

	return (isSafe) ? TRUE : ((KeGetCurrentIrql() == PASSIVE_LEVEL) ? TRUE : FALSE);
}

static DWORD _GetFilterLevel(int debugLevel)
{
	switch(debugLevel)
	{
		case DEBUG_LEVEL_NONE:
			return DPFLTR_INFO_LEVEL;

		case DEBUG_LEVEL_FATAL:
		case DEBUG_LEVEL_FAILURE:
		case DEBUG_LEVEL_ERROR:
			return DPFLTR_ERROR_LEVEL;

		case DEBUG_LEVEL_WARN:
			return DPFLTR_WARNING_LEVEL;
	
		case DEBUG_LEVEL_DEBUG:
		case DEBUG_LEVEL_INFO:
			return DPFLTR_TRACE_LEVEL;

		case DEBUG_LEVEL_SPAM:
			// Lowest priority
			return DPFLTR_INFO_LEVEL;
	}

	return DPFLTR_ERROR_LEVEL;
}

void DebugPreflight(const char *logname, bool redirect, int level, int perms)
{
	(void)logname;
	(void)redirect;
	(void)perms;

	if (gDebugLevel == 1)
		SetDebugLevel(level);
	DebugLevel();
}

void DebugPostflight()
{

}

void DebugSwitchLogFile(const char *newFileName)
{
	(void)newFileName;
}

void DebugRotateLogFile(const char *newFileName)
{
	(void)newFileName;
}

char * CopyDebugHistory()
{
	return NULL;
}

#if 0
#pragma mark -
#endif

void DebugMessage(int level, const char *format, ...)
{
	if (gDebugEnabled)
	{
		// Print the requested message into a buffer
		if (_IsSafeFormat(format))
		{
			va_list		args;

			va_start(args, format);
			vDbgPrintExWithPrefix(__PREFIX__, DPFLTR_DEFAULT_ID, _GetFilterLevel(level), format, args);
			va_end(args);
		}
		else
			// Ignore the parameters, just output the raw format string
			DbgPrintEx(DPFLTR_DEFAULT_ID, _GetFilterLevel(level), "%s%s", __PREFIX__, format);
	}
}

void DebugData(const char *label, const void *data, size_t length)
{
	unsigned char *	bytes = (unsigned char *)data;
	char			table[] = "0123456789ABCDEF";
	char			hex[37], ascii[18];
	char *			buffer = NULL;
	size_t			bufferLength;
	size_t			i, j, k, x, y;

	if (gDebugEnabled)
	{
		// Allocate a scratch buffer for the output
		bufferLength = (length + 15) * 80 / 16;
		buffer = (char *) ExAllocatePoolWithTag(NonPagedPool, bufferLength, 'GBDs');
		
		// Loop over the data, marking the end of our progress after each loop
		if (buffer) for(i=k=0; i<length; )
		{
			char	line[120] = "";

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
#if _WIN64
			RtlStringCbPrintfA(line, sizeof(line), "  0x%.16llX | %s| %s\n", (unsigned long long)(bytes + i), hex, ascii);
#else
			RtlStringCbPrintfA(line, sizeof(line), "  0x%.8lX | %s| %s\n", (unsigned long)(bytes + i), hex, ascii);
#endif // _WIN64
			RtlStringCbCatNA(buffer, bufferLength, line, sizeof(line));
		}
		
		// Now that we have the data, print out the label and our buffer
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, 
				"%s (%zu bytes):\n%s", label, length, 
				(buffer) ? buffer : " -- out of memory --\n");
			
		if (buffer)
			ExFreePool(buffer);
	}
}

void SetDebugEnabled(int enable)
{
	gDebugEnabled = (enable) ? true : false;
}

void SetDebugTimestamp(unsigned showTimestamp)
{
	(void)showTimestamp; // Ignored
}

unsigned DebugTimestamp()
{
	return 0;
}

void SetDebugLevel(int level)
{
	if (level > DEBUG_LEVEL_NONE)
		level = DEBUG_LEVEL_NONE;
	gDebugLevel = level;
}

int DebugLevel(void)
{
	return gDebugLevel;
}

void SetDebugMask(int mask)
{
	if (mask < 0)
		mask = 0;
	gDebugMask = mask;
}

int DebugMask(void)
{
	return gDebugMask;
}

bool DebugShouldLog(int value)
{
	bool shouldLog = true;
	
	if (value < 0)
		shouldLog = (DebugLevel() <= value) ? true : false;
	else 
		shouldLog = (DebugMask() & value) ? true : false;
	
	return shouldLog;
}

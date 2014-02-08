/*!
	@file stddebug_kext.c
	@abstract Common debugging utilities
	@copyright (c) 1997-2014 by Matt Slot <mattslot@gmail.com>.
	
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
		Debug implementations safe for use in MacOS X kernel extension.
*/ 

#include <kern/debug.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <IOKit/IOLib.h> // For kprintf

#include "stddebug.h"

#if defined(MODULE_NAME)
	#define __PREFIX__		__MKSTR__(MODULE_NAME) " "
#else
	#define __PREFIX__		""
#endif // MODULE_NAME


static	bool						gDebugEnabled = 1;
static	int							gDebugLevel = 1;
static	int							gDebugMask = 0;

void DebugPreflight(char *logname, int redirect, int level)
{
	if (gDebugLevel == 1)
		SetDebugLevel(level);
	DebugLevel();
}

void DebugPostflight()
{

}

void DebugMessage(const char *format, ...)
{
	char buffer[512];
	va_list args;
	size_t bytes;
	
	if (gDebugEnabled)
	{
		// Print the requested message into a buffer
		va_start(args, format);
		vsnprintf(buffer, sizeof(buffer), format, args);
		va_end(args);
		
		// Append a trailing linefeed if necessary
		bytes = strlen(format);
		if (bytes && (format[bytes-1] != '\n'))
			kprintf("%s%s\n", __PREFIX__, buffer);
		else
			kprintf("%s%s", __PREFIX__, buffer);
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
		buffer = (char *) _MALLOC(bufferLength, M_TEMP, M_NOWAIT);
		
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
			k += snprintf(buffer + k, bufferLength - k, "  0x%.16lX | %s| %s\n", (uintptr_t)(bytes + i), hex, ascii);
#else
			k += snprintf(buffer + k, bufferLength - k, "  0x%.8lX | %s| %s\n", (uintptr_t)(bytes + i), hex, ascii);
#endif // __LP64__
		}
		
		// Now that we have the data, print out the label and our buffer
		kprintf("%s (%lu bytes):\n%s", label, length, 
				(buffer) ? buffer : " -- out of memory --\n");
			
		if (buffer)
			_FREE(buffer, M_TEMP);
	}
}

void SetDebugEnabled(int enable)
{
	gDebugEnabled = enable;
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

char * CopyDebugHistory()
{
	return nil;
}

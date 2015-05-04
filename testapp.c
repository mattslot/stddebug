/*!
	@file testapp.c
	@abstract Common debugging macros
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
		This is a sample application to demonstrate how to use the stddebug
		macros and logging library.
*/

// To compile on a Mac:
//    clang -o testapp testapp.c stddebug.c -DDEBUG=1 -framework CoreFoundation
// To compile on Linux:
//    gcc -o testapp testapp.c stddebug.c -DDEBUG=1

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "stddebug.h"

int main(int argc, char **argv)
{
	int			result = 0;
	char *		buffer = NULL;
	int			fd = 0;
	
	// Optional call to set up the logfile. By default, only messages at level
	// ERROR or higher will be logged, so we lower the logging level to DEBUG.
	// Pass NULL for the logfile to write error messages to stderr / console.
	DebugPreflight("testapp", 0, DEBUG_LEVEL_DEBUG);
	
	// Log a short message, no change to application flow.
	dLog(DEBUG_LEVEL_ALWAYS, "Hello stddebug");
	
	// Perform a simple memory allocation, and jump to CLEANUP if it fails.
	dFailIfNull(buffer = calloc(1, 1), 
			(void)0, DEBUG_LEVEL_ERROR, "Out of memory");
	
	// Call a library routine. Log the error and jump to CLEANUP if it fails.
	// Use the side-effect to save the error, set a flag, or clear app state.
	dFailIfTrue((fd = open("/dev/null", O_WRONLY)) < 0, 
			result = errno, DEBUG_LEVEL_ERROR, "open() failed : %i", errno);
	
	// assert() that a run-time constraint has been satisfied, or abort().
	// Typically used to check parameter or global state in API routines.
	dAssert(strlen("abc") == 3, "String constant has invalid length");
	
// CLEANUP label is the goto target for dFail() macros. 
CLEANUP:
	if (fd) close(fd);

	return result;
}

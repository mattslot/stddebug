/*!
	@file stddebug.c
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
		Wrapper to select the best implementation based on project settings.
*/ 

#include "stddebug.h"

#if __APPLE__

	#include <TargetConditionals.h>

	#if KEXT
		#include "stddebug_kext.c"
	#elif VERBOSE && TARGET_OS_IPHONE
		#include "stddebug_mac_ios_buffered.c"
	#else
		#include "stddebug_mac_ios.c"
	#endif
	
#else

	// Use POSIX APIs to output to stderr
	#include "stddebug_stderr.c"
	
#endif // __APPLE__

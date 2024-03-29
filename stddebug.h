/*!
	@file stddebug.h
	@abstract Common debugging macros
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

	@indexgroup	stdebug

	@discussion
		This header defines a series of macros used to wrap function calls, test
		for failure, log the details, and optionally modify program flow. Also
		declares the logging bottlenecks that redirct error messages to stderr
		or an application-specified logfile.
		
		There are 3 broad groups of macros:
		
		• dLogIf...() :
		
			Evaluates an expression or function and logs a formatted message.
		
		• dFailIf...() :
		
			Evaluates an expression or function and logs a formatted message.
			It then performs an optional side-effect, and then goto CLEANUP
		
		• dAssertIf...() :
		
			In Debug builds, evaluates the expression and calls abort().
			In Release builds, entire expression is optimized out.
			
*/

#ifndef __STANDARD_DEBUG_HEADER__
#define __STANDARD_DEBUG_HEADER__

#if __APPLE__
	#include <TargetConditionals.h>
#endif

#ifndef _SYS_TYPES_H_
	#include <sys/types.h>		// For size_t
#endif

#if KEXT
	#include <kern/debug.h>
	#include <sys/types.h>
	#include <sys/malloc.h>
	#include <IOKit/IOLib.h>	// For kprintf
#elif _WIN32 && _KERNEL_MODE
	typedef unsigned char bool;
	#define true 1
	#define false 0
#else
	#include <stdbool.h>
	#include <stdlib.h>			// For abort
#endif

#if defined(__arm__)
	#include <unistd.h>			// For getpid
#endif

// Compatibility with MSVC _DEBUG and DBG
#if _DEBUG && ! defined(DEBUG)
	#define DEBUG _DEBUG
#elif DBG && ! defined(DEBUG)
	#define DEBUG DBG
#endif // _DEBUG && ! DEBUG

// Preprocessor magic to convert integers to strings
#define __MKSTR__(x)			__MKVAL__(x)
#define __MKVAL__(x)			#x
#define __WHERE__				" @ " __FILE__ ":" __MKSTR__(__LINE__)

// Optional flag to shorten fullpaths when logging
#ifndef DEBUG_SHORTEN_PATHS
	#define DEBUG_SHORTEN_PATHS	1
#endif // DEBUG_SHORTEN_PATHS

// Constants for setting logging level. Use negative values only, 
// positive values (high bit clear) are reserved for bitmasks.
#define DEBUG_LEVEL_NONE		 0
#define DEBUG_LEVEL_FATAL		-1
#define DEBUG_LEVEL_FAILURE		-2
#define DEBUG_LEVEL_ERROR		-3
#define DEBUG_LEVEL_WARN		-4
#define DEBUG_LEVEL_DEBUG		-5
#define DEBUG_LEVEL_INFO		-6
#define DEBUG_LEVEL_SPAM		-7

#define DEBUG_LEVEL_NEVER		 0
#define DEBUG_LEVEL_ALWAYS		-1

#define DEBUG_LEVEL_ENV_VAR		"DEBUG_LEVEL"

// Broken out so headerdoc doesn't include it
#if ! KEXT && ( TARGET_OS_MAC || TARGET_OS_IPHONE )

	#include <CoreFoundation/CFString.h>

	#define __DEBUGSTR_CFSTRING__	1

	#define __DEBUGSTR__(s)		CFSTR(s)
	#define __DEBUGSTR_ARG__	CFStringRef
	#define __DEBUGSTR_TYPE__	CFStringRef

  #if defined(__GNUC__) && (__GNUC__*10+__GNUC_MINOR__ >= 42) && !defined(__INTEL_COMPILER) && (TARGET_OS_MAC || TARGET_OS_EMBEDDED)
	#define __DEBUG_MESSAGE_ATTRIBUTE__ __attribute__((format(__CFString__, 2, 3)))
  #else
	#define __DEBUG_MESSAGE_ATTRIBUTE__
  #endif
  
#else

	#define __DEBUGSTR__(s)		(s)
	#define __DEBUGSTR_ARG__	const char *
	#define __DEBUGSTR_TYPE__	char *

  #ifdef __printflike
	#define __DEBUG_MESSAGE_ATTRIBUTE__ __printflike(2, 3)
  #else
	#define __DEBUG_MESSAGE_ATTRIBUTE__
  #endif
  
#endif // TARGET_OS_MAC || TARGET_OS_IPHONE

// Determine if this is being run through a static analyzer
#if defined(__clang__)
	#if __clang_analyzer__
		#define __DEBUG_STATIC_ANALYZER__	1
	#endif
#elif defined(_MSC_VER)
	#if _PREFAST_
		#define __DEBUG_STATIC_ANALYZER__	1
	#endif
#endif // __GNUC__

// Hard-coded breakpoint
#if DEBUG

  #if defined(__GNUC__)
  	#if __has_builtin(__builtin_debugtrap)
  		#define DEBUGGER()	__builtin_debugtrap()
	#elif defined(__ppc__) || defined(__ppc64__)
		#define DEBUGGER()	__asm__ volatile ("trap")
	#elif defined(__i386__) || defined(__x86_64__)
		#define DEBUGGER()	__asm__ volatile ("int3")
	#elif TARGET_OS_IPHONE
		#define DEBUGGER()	kill(getpid(), SIGINT)
	#else
		#error Architecture not supported
	#endif /* __ppc__ || __ppc64__ */
  #elif _WIN32
		#define DEBUGGER()	__debugbreak()
  #else
	#error "Platform not supported"
  #endif /* __GNUC__ */

#else

	/*!
		@discussion
			In DEBUG builds, immediately stops the program in the debugger at the current line.
			
			In non-DEBUG builds, this operation is a no-op.
	*/
 	#define DEBUGGER()

#endif // DEBUG

#if defined(_MSC_VER)
	// MSVC does not support the __typeof() operator, but it does support auto
	#define __typeof(t)		auto
#endif // _MSC_VER

#if DEBUG || VERBOSE

	// Debugger and logging hooks

	#define dLogMessage(l,m,...)		do { if (DebugShouldLog(l)) DebugMessage((l), __DEBUGSTR__(m __WHERE__ "\n"), ## __VA_ARGS__); } while(0)
	#define dLogError(e,l,m,...)		do { if (DebugShouldLog(l)) DebugMessage((l), __DEBUGSTR__("ERROR %d: " m __WHERE__ "\n"), (int)(e), ## __VA_ARGS__); } while(0)
	
  #if DEBUG
	#define dAssertionFailure(m,...)	do { if (DebugShouldLog(DEBUG_LEVEL_FATAL)) DebugMessage(DEBUG_LEVEL_FATAL, __DEBUGSTR__(m __WHERE__ "\n"), ## __VA_ARGS__); DEBUGGER(); abort(); } while(0)
  #elif __DEBUG_STATIC_ANALYZER__
	#define dAssertionFailure(m,...)	do { if (DebugShouldLog(DEBUG_LEVEL_FATAL)) DebugMessage(DEBUG_LEVEL_FATAL, __DEBUGSTR__(m __WHERE__ "\n"), ## __VA_ARGS__); abort(); } while(0)
  #else
	#define dAssertionFailure(m,...)	do { if (DebugShouldLog(DEBUG_LEVEL_FATAL)) DebugMessage(DEBUG_LEVEL_FATAL, __DEBUGSTR__(m __WHERE__ "\n"), ## __VA_ARGS__); } while(0)
  #endif // DEBUG
  
#else

	// Stub implementations for release

	#define dLogMessage(l,m,...)		do { ; } while(0)
	#define dLogError(e,l,m,...)		do { ; } while(0)

	#define dAssertionFailure(m,...)	do { ; } while(0)

#endif // DEBUG || VERBOSE

#define dLogIfError(check,level,message,...)				do { __typeof(check) __ERROR__ = (check); if (__ERROR__) dLogError(__ERROR__, level, message, ## __VA_ARGS__); } while(0)
#define dLogIfTrue(check,level,message,...)					do { if (!!(check)) dLogMessage(level, message, ## __VA_ARGS__); } while(0)
#define dLogIfFalse(check,level,message,...)				do { if (!(check)) dLogMessage(level, message, ## __VA_ARGS__); } while(0)
#define dLogIfNull(check,level,message,...)					do { if ((check) == NULL) dLogMessage(level, message, ## __VA_ARGS__); } while(0)
#define dLog(level,message,...)								dLogMessage(level, message, ## __VA_ARGS__)

#define dFailIfError(check,action,level,message,...)		do { __typeof(check) __ERROR__ = (check); if (__ERROR__) { dLogError(__ERROR__, level, message, ## __VA_ARGS__); action; goto CLEANUP; } } while(0)
#define dFailIfTrue(check,action,level,message,...)			do { if (!!(check)) { dLogMessage(level, message, ## __VA_ARGS__); action; goto CLEANUP; } } while(0)
#define dFailIfFalse(check,action,level,message,...)		do { if (!(check)) { dLogMessage(level, message, ## __VA_ARGS__); action; goto CLEANUP; } } while(0)
#define dFailIfNull(check,action,level,message,...)			do { if ((check) == NULL) { dLogMessage(level, message, ## __VA_ARGS__); action; goto CLEANUP; } } while(0)
#define dFail(level,message,...)							do { dLogMessage(level, message, ## __VA_ARGS__); goto CLEANUP; } while(0)

#define dAssertIfError(check,message,...)					do { __typeof(check) __ERROR__ = (check); if (__ERROR__) dAssertionFailure(message, ## __VA_ARGS__); } while(0)
#define dAssertIfTrue(check,message,...)					do { if (!!(check)) dAssertionFailure(message, ## __VA_ARGS__); } while(0)
#define dAssertIfFalse(check,message,...)					do { if (!(check)) dAssertionFailure(message, ## __VA_ARGS__); } while(0)
#define dAssertIfNull(check,message,...)					do { if ((check) == NULL) dAssertionFailure(message, ## __VA_ARGS__); } while(0)
#define dAssert(check,message,...)							dAssertIfFalse(check, message, ## __VA_ARGS__)


#ifdef __cplusplus

	#define	dLogIfException(check,level,message,...)					do { try { check; } catch(...) { \
																			dLogMessage(level, "Exception -- " message, ## __VA_ARGS__); } } while(0)
	#define	dFailIfException(check,action,level,message,...)			do { try { check; } catch(...) { \
																			dLogMessage(level, "Exception -- " message, ## __VA_ARGS__); action; goto CLEANUP; } } while(0)
	#define	dAssertIfException(check,message,...)						do { try { check; } catch(...) { \
																			dAssertionFailure("Exception -- " message, ## __VA_ARGS__); } } while(0)

#endif // __cplusplus


#ifdef __OBJC__

	#define	dLogIfNSException(check,level,message,...)					do { @try { check; } @catch(NSException *_exception_) { \
																			dLogMessage(level, "Exception '%@' -- " message, [_exception_ reason], ## __VA_ARGS__); } } while(0)
	#define	dFailIfNSException(check,action,level,message,...)			do { @try { check; } @catch(NSException *_exception_) { \
																			dLogMessage(level, "Exception '%@' -- " message, [_exception_ reason], ## __VA_ARGS__); action; goto CLEANUP; } } while(0)
	#define	dAssertIfNSException(check,message,...)						do { @try { check; } @catch(NSException *_exception_) { \
																			dAssertionFailure("Exception '%@' -- " message, [_exception_ reason], ## __VA_ARGS__); } } while(0)

#endif // __OBJC__


#if KEXT

  #if defined(MODULE_NAME)
	#define __PREFIX__		"[" __MKSTR__(MODULE_NAME) "] "
  #else
	#define __PREFIX__		""
  #endif // MODULE_NAME

  #ifdef panic_plain
  	#define PANIC	panic_plain
  #else
    #define PANIC	panic
  #endif // panic_plain

  #if 0
	#define dPanic(m,...)									do { PANIC(__PREFIX__  "PANIC: " m __WHERE__ "\n", ## __VA_ARGS__); } while(0)
  #else
	#define dPanic(m,...)									do { kprintf(__PREFIX__ "PANIC: "      m __WHERE__ "\n", ## __VA_ARGS__); } while(0)
  #endif // DEBUG

	#define dPanicIfError(check,message,...)				do { __typeof(check) __ERROR__ = (check); if (__ERROR__) dPanic(message, ## __VA_ARGS__); } while(0)
	#define dPanicIfTrue(check,message,...)					do { if (!!(check)) dPanic(message, ## __VA_ARGS__); } while(0)
	#define dPanicIfFalse(check,message,...)				do { if (!(check)) dPanic(message, ## __VA_ARGS__); } while(0)
	#define dPanicIfNull(check,message,...)					do { if ((check) == NULL) dPanic(message, ## __VA_ARGS__); } while(0)

#elif _WIN32 && _KERNEL_MODE

  #if defined(MODULE_NAME)
	#define __PREFIX__		"[" __MKSTR__(MODULE_NAME) "] "
  #else
	#define __PREFIX__		""
  #endif // MODULE_NAME

#endif // KEXT

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __has_feature
	#define __has_feature(x) 0
#endif

#if __has_feature(objc_arc)
	#pragma arc_cf_code_audited begin
#endif // __has_feature(objc_arc)

/*!
	@abstract Specify the name of a logfile for all future debug messages.
	@param logname Name of the new logfile to use, or NULL to leave the same.
	@param redirect true to redirect stderr entirely, false to just log our own data.
	@param level Set to the default logging level, unless overridden by setenv.
	@param perms Specify the UNIX file permissions. Pass 0 to use defaults.
	@discussion
		Prepare for logging by opening the indicated file and redirecting stderr
		to the same location. Print a timestamped header to the output.
		
		This function is typically called once at the beginning of your application.
*/
extern void DebugPreflight(const char *logname, bool redirect, int level, int perms);

/*!
	@abstract Log debug messages to the console or logfile.
	@param level An integer specifying the debug level or priority of this message.
	@param format A printf() style format string, followed by an argument list.
	@discussion
		The primary bottleneck for the debugging macros, it takes formatted error messages
		and logs them either to stderr (by default) or an application-specified logfile.
*/
extern void DebugMessage(int level, __DEBUGSTR_ARG__ format, ...) __DEBUG_MESSAGE_ATTRIBUTE__;

/*!
	@abstract Log the contents of a memory block as a nicely formatted text dump.
	@param label Descriptive label for the logged data.
	@param data Pointer to a block of memory to display.
	@param length Length of the memory block to display.
	@discussion
		Create a text dump of a memory block, displaying the binary data as both hex
		and ASCII suitable for for debugging data structures, network packets, etc.
*/
extern void DebugData(const char *label, const void *data, size_t length);

/*!
	@abstract Close the logfile and release any allocated resources.
	@discussion
		Write a closing message to the logfile, and release any resources
		used by the debugging routines.
		
		This function is typically called once at the end of your application.
*/
extern void DebugPostflight(void);

/*!
	@abstract For implementations that log to a file, start logging to a new file.
	@param newFileName The suggested name of the new file to start logging to.
	@discussion
		The current log file will be closed and a new log file will be created 
		at the given path. Subsequent log entries will be written to the new file.
		This function is thread-safe.
*/
extern void DebugSwitchLogFile(const char *newFileName);

/*!
	@abstract For implementations that log to a file, swap out the existing log file.
	@param newFileName The suggested name to use for the existing log file.
	@discussion
		The current log file will be closed and renamed to the suggested name. A new
		log file will be created at the original path and subsequent log entries will 
		be written to that file.
		This function is thread-safe.
*/

extern void DebugRotateLogFile(const char *newFileName);

/*!
	@abstract For implementations that cache the logging, return that history.
	@result A string buffer (char *, CFStringRef) containing the log history.
		The caller is responsible for releasing this buffer.
	@discussion
		For implementations that log to a memory buffer instead of a file,
		this routine returns an allocated pointer or retained CFStringRef
		containing the log information.
	
*/
extern __DEBUGSTR_TYPE__ CopyDebugHistory(void);


/*!
	@abstract Toggle the debugging output on or off.
	@param enable Non-zero to enable logging, zero to disable. Default state is enabled.
*/
extern void SetDebugEnabled(int enable);

/*!
	@abstract Specify whether timestamps should be logged, and at what resoluion.
	@param timestamp Pass a non-zero number to include a timestamp with each line
		logged. Default resolution is 1 second, or pass 1000 to specify milliseconds.
	@discussion
		Not all logging implementations support higher resolution timestamps. In 
		such cases, the most accurate fallback available will be selected.
*/
extern void SetDebugTimestamp(unsigned timestamp);

/*!
	@abstract Return the current debug timestamp setting.
	@result Zero if timestamps are disabled, or a non-zero resolution.
*/
extern unsigned DebugTimestamp(void);

/*!
	@abstract Specify how much data will be logged during debugging.
	@param level A DEBUG_LEVEL_* constant indicating the new logging level.
	@discussion
		The application can change the debugging level on the fly in response to
		user configuration. This setting is shared across the entire application.
*/
extern void SetDebugLevel(int level);

/*!
	@abstract Return the current logging level setting.
	@result A DEBUG_LEVEL_* constant indicating the current logging level.
	@discussion
		This function returns the currently configured logging level, either
		from a previous call to SetDebugLevel(), the environment variable
		DEBUG_LEVEL, or software default.
*/
extern int DebugLevel(void);

/*!
	@abstract Specify that modules that will be logged during debugging.
	@param mask A bitmask constant indicating which operations should be logged.
	@discussion
		The application can change the debugging mask on the fly in response to
		user configuration. This setting is shared across the entire application.
*/
extern void SetDebugMask(int mask);

/*!
	@abstract Return the current logging mask setting.
	@result A bitmask indicating the current logging level.
	@discussion
		This function returns the currently configured logging level, either
		from a previous call to SetDebugLevel(), the environment variable
		DEBUG_LEVEL, or software default.
*/
extern int DebugMask(void);

/*!
	@abstract Should a debug message with the indicated level/mask be logged?
	@param value A DEBUG_LEVEL_* constant or bitmask of the message to log.
	@result Non-zero if the message should be logged, 0 otherwise.
	@discussion
		This function compares the indicated message level or bitmask against
		the current configuration and returns true if the message should be
		logged.
*/
extern bool DebugShouldLog(int value);

#if __has_feature(objc_arc)
	#pragma arc_cf_code_audited end
#endif // __has_feature(objc_arc)

#ifdef __cplusplus
}
#endif

#endif // __STANDARD_DEBUG_HEADER__

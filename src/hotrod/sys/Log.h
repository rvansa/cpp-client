#ifndef ISPN_HOTROD_LOG_H
#define ISPN_HOTROD_LOG_H

#include "infinispan/hotrod/types.h"
#include "infinispan/hotrod/ImportExport.h"
#include "hotrod/sys/Mutex.h"
#include "hotrod/sys/Path.h"
#include <stdexcept>
#include <iostream>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifndef TRACEBYTES_MAX
#	define TRACEBYTES_MAX 32U
#endif

#define LOG_LEVEL_TRACE	"TRACE"
#define LOG_LEVEL_DEBUG	"DEBUG"
#define LOG_LEVEL_INFO	"INFO"
#define LOG_LEVEL_WARN	"WARN"
#define LOG_LEVEL_ERROR	"ERROR"

namespace infinispan {
namespace hotrod {
namespace sys {

typedef enum LogLevel { LEVEL_TRACE, LEVEL_DEBUG, LEVEL_INFO, LEVEL_WARN, LEVEL_ERROR } LogLevel;

class HR_EXTERN Log
{
  public:
    Log() {
        const char *level = getenv("HOTROD_LOG_LEVEL");
        if (level == 0) {
            m_level = LEVEL_ERROR;
        } else if (!strcmp(level, LOG_LEVEL_TRACE)) {
            m_level = LEVEL_TRACE;
        } else if (!strcmp(level, LOG_LEVEL_DEBUG)) {
            m_level = LEVEL_DEBUG;
        } else if (!strcmp(level, LOG_LEVEL_INFO)) {
            m_level = LEVEL_INFO;
        } else if (!strcmp(level, LOG_LEVEL_WARN)) {
            m_level = LEVEL_WARN;
        } else if (!strcmp(level, LOG_LEVEL_ERROR)) {
            m_level = LEVEL_ERROR;
        } else {
            throw std::runtime_error("Invalid HOTROD_LOG_LEVEL environment variable");
        }
    }

    Log(LogLevel level) {
        m_level = level;
    }

    ~Log() {}

    void trace(const char *fname, const int lineno, const char *format, ...) { va_list vl; va_start(vl, format); log(LOG_LEVEL_TRACE, fname, lineno, format, vl); va_end(vl); }
    void trace(const char *fname, const int lineno, const char *message, const infinispan::hotrod::hrbytes &bytes) { log(LOG_LEVEL_TRACE, fname, lineno, message, bytes); }
    void debug(const char *fname, const int lineno, const char *format, ...) { va_list vl; va_start(vl, format); log(LOG_LEVEL_DEBUG, fname, lineno, format, vl); va_end(vl); }
    void info(const char *fname, const int lineno, const char *format, ...) { va_list vl; va_start(vl, format); log(LOG_LEVEL_INFO, fname, lineno, format, vl); va_end(vl); }
    void warn(const char *fname, const int lineno, const char *format, ...) { va_list vl; va_start(vl, format); log(LOG_LEVEL_WARN, fname, lineno, format, vl); va_end(vl); }
    void error(const char *fname, const int lineno, const char *format, ...) { va_list vl; va_start(vl, format); log(LOG_LEVEL_ERROR, fname, lineno, format, vl); va_end(vl); }

    bool isTraceEnabled() { return m_level == LEVEL_TRACE; }
    bool isDebugEnabled() { return m_level <= LEVEL_DEBUG; }
    bool isInfoEnabled() { return m_level <= LEVEL_INFO; }
    bool isWarnEnabled() { return m_level <= LEVEL_WARN; }
    bool isErrorEnabled() { return m_level <= LEVEL_ERROR; }
  private:
    Mutex lock;
    LogLevel m_level;

    void log(const char *level, const char *fname, const int lineno, const char *format, va_list vl) {
        char buf[2048];
        vsnprintf(buf, 2048, format, vl);
        ScopedLock<Mutex> sl(lock);

        std::cerr << level << "[" << pfname(fname) << ":" << lineno << "] " << buf << std::endl;
    }

    void log(const char *level, const char *fname, const int lineno, const char *message, const infinispan::hotrod::hrbytes &bytes) {
    	std::cerr << level << "[" << pfname(fname) << ":" << lineno << "] " << message << "%d bytes:" << bytes.length();
    	/* Check if characters are printable */
    	bool printable = true;
    	for (unsigned tbi = 0; tbi < TRACEBYTES_MAX && tbi < bytes.length() && printable; ++tbi) {
    		char byte = bytes.bytes()[tbi];
    		printable = byte >= 0x20 && byte < 0x7F;
    	}
    	if (printable) {
    		char buf[TRACEBYTES_MAX + 1];
    		strncpy(buf, bytes.bytes(), std::min(TRACEBYTES_MAX, bytes.length()));
    		buf[TRACEBYTES_MAX] = 0;
    		std::cerr << '\'' << buf << '\'';
    	} else {
			std::cerr.width(2);
			std::cerr.setf(std::ios::hex);
			std::cerr.fill('0');
			for (unsigned tbi = 0; tbi < TRACEBYTES_MAX && tbi < bytes.length(); ++tbi) {
				std::cerr << bytes.bytes()[tbi];
			}
			std::cerr.width(0);
			std::cerr.unsetf(std::ios::hex);
    	}
		if (TRACEBYTES_MAX > bytes.length()) {
			std::cerr << "... (" << (bytes.length() - TRACEBYTES_MAX) << " more)\n";
		}
    }

	const char *pfname(const char* fname) {
		const char* name = strrchr(fname, PATH_SEP);
		if (name == NULL) {
			/* Use the full fname if no separator is found. */
			return fname;
		} else {
			return name + 1;
		}
	}
};

#define TRACE(...) if (logger.isTraceEnabled()) logger.trace(__FILE__, __LINE__, __VA_ARGS__)
#define TRACEBYTES(message, bytes) if (logger.isTraceEnabled()) logger.trace(__FILE__, __LINE__, message, bytes)
#define DEBUG(...) if (logger.isDebugEnabled()) logger.debug(__FILE__, __LINE__, __VA_ARGS__)
#define INFO(...) if (logger.isInfoEnabled()) logger.info(__FILE__, __LINE__, __VA_ARGS__)
#define WARN(...) if (logger.isWarnEnabled()) logger.warn(__FILE__, __LINE__, __VA_ARGS__)
#define ERROR(...) if (logger.isErrorEnabled()) logger.error(__FILE__, __LINE__, __VA_ARGS__)

}}}

static infinispan::hotrod::sys::Log logger;

#endif  /* ISPN_HOTROD_LOG_H */


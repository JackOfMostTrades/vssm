package logging

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

type LogLevel uint

const (
	_              = iota
	FATAL LogLevel = iota
	ERROR
	WARN
	INFO
	DEBUG
)

func (l LogLevel) String() string {
	switch l {
	case FATAL:
		return "FATAL"
	case ERROR:
		return "ERROR"
	case WARN:
		return "WARN"
	case INFO:
		return "INFO"
	case DEBUG:
		return "DEBUG"
	}
	panic("Unhandled log level in String()")
}

type Log struct {
	level    LogLevel
	logTime  time.Time
	message  string
	location string
}

func (l *Log) String() string {
	return fmt.Sprintf("[%s] %s, %s: %s", l.logTime.Format(time.RFC3339),
		l.location, l.level.String(), l.message)
}

type Logger struct {
	mutex        sync.Mutex
	logs         []*Log
	logHead      int
	logTail      int
	consoleLevel LogLevel
	loggerLevel  LogLevel
}

func New(consoleLevel LogLevel, loggerLevel LogLevel) *Logger {
	return &Logger{
		logs:         make([]*Log, 10000),
		logHead:      0,
		logTail:      0,
		consoleLevel: consoleLevel,
		loggerLevel:  loggerLevel,
	}
}

func (l *Logger) GetLogs() []*Log {

	l.mutex.Lock()
	var size int
	if l.logHead == l.logTail {
		return nil
	}
	if l.logHead > l.logTail {
		size = l.logHead - l.logTail
	} else {
		size = len(l.logs) - (l.logTail - l.logHead) + 1
	}

	logs := make([]*Log, 0, size)
	if l.logHead > l.logTail {
		for i := l.logTail; i < l.logHead; i++ {
			logs = append(logs, l.logs[i])
		}
	} else {
		for i := l.logTail; i < len(l.logs); i++ {
			logs = append(logs, l.logs[i])
		}
		for i := 0; i < l.logHead; i++ {
			logs = append(logs, l.logs[i])
		}
	}

	l.mutex.Unlock()

	return logs
}

func (l *Logger) append(level LogLevel, format string, args []interface{}) {
	if level > l.consoleLevel && level > l.loggerLevel {
		return
	}

	var location string
	_, file, line, ok := runtime.Caller(2)
	if ok {
		fileParts := strings.Split(file, "/")
		var filename string
		if len(fileParts) >= 2 {
			filename = fileParts[len(fileParts)-2] + "/" + fileParts[len(fileParts)-1]
		} else {
			filename = file
		}
		location = fmt.Sprintf("%s:%d", filename, line)
	} else {
		location = "<unknown>"
	}

	log := &Log{
		level:    level,
		logTime:  time.Now(),
		message:  fmt.Sprintf(format, args...),
		location: location,
	}

	if level <= l.consoleLevel {
		fmt.Println(log.String())
	}

	if level <= l.loggerLevel {
		var writeLoc int

		l.mutex.Lock()
		nextHead := (l.logHead + 1) % len(l.logs)
		if nextHead == l.logTail {
			l.logTail = (l.logTail + 1) % len(l.logs)
		}
		writeLoc = l.logHead
		l.logHead = nextHead
		l.mutex.Unlock()

		l.logs[writeLoc] = log
	}
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.append(DEBUG, format, args)
}
func (l *Logger) Info(format string, args ...interface{}) {
	l.append(INFO, format, args)
}
func (l *Logger) Warn(format string, args ...interface{}) {
	l.append(WARN, format, args)
}
func (l *Logger) Error(format string, args ...interface{}) {
	l.append(ERROR, format, args)
}
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.append(FATAL, format, args)
}

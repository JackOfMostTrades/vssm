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

const MAX_LOGS = 10000

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

type LoggerImpl struct {
	mutex        sync.Mutex
	logs         []*Log
	logHead      int
	logSize      int
	consoleLevel LogLevel
	loggerLevel  LogLevel
}

func New(consoleLevel LogLevel, loggerLevel LogLevel) Logger {
	return &LoggerImpl{
		logs:         make([]*Log, MAX_LOGS),
		logHead:      0,
		logSize:      0,
		consoleLevel: consoleLevel,
		loggerLevel:  loggerLevel,
	}
}

func (l *LoggerImpl) GetLogs() []*Log {

	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.logSize == 0 {
		return nil
	}
	if l.logSize < MAX_LOGS {
		logs := make([]*Log, l.logSize)
		copy(logs, l.logs[0:l.logSize])
		return logs
	}

	logs := make([]*Log, 0, MAX_LOGS)
	for i := l.logHead; i < len(l.logs); i++ {
		logs = append(logs, l.logs[i])
	}
	for i := 0; i < l.logHead; i++ {
		logs = append(logs, l.logs[i])
	}

	return logs
}

func (l *LoggerImpl) append(level LogLevel, format string, args []interface{}) {
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
		l.mutex.Lock()
		writeLoc := l.logHead
		l.logHead = (l.logHead + 1) % len(l.logs)
		l.logSize += 1
		if l.logSize > MAX_LOGS {
			l.logSize = MAX_LOGS
		}
		l.mutex.Unlock()

		l.logs[writeLoc] = log
	}
}

func (l *LoggerImpl) Debug(format string, args ...interface{}) {
	l.append(DEBUG, format, args)
}
func (l *LoggerImpl) Info(format string, args ...interface{}) {
	l.append(INFO, format, args)
}
func (l *LoggerImpl) Warn(format string, args ...interface{}) {
	l.append(WARN, format, args)
}
func (l *LoggerImpl) Error(format string, args ...interface{}) {
	l.append(ERROR, format, args)
}
func (l *LoggerImpl) Fatal(format string, args ...interface{}) {
	l.append(FATAL, format, args)
}

package logging

import (
	"fmt"
	"testing"
)

func TestLoggerCounting(t *testing.T) {
	_testLogCount(t, MAX_LOGS/2)
	_testLogCount(t, MAX_LOGS-1)
	_testLogCount(t, MAX_LOGS)
	_testLogCount(t, MAX_LOGS+1)
	_testLogCount(t, MAX_LOGS*2)
}

func _testLogCount(t *testing.T, count int) {
	logger := New(FATAL, INFO)
	for i := 0; i < count; i++ {
		logger.Debug("D%d", i)
		logger.Info("I%d", i)
	}

	logs := logger.GetLogs()
	expectedCount := count
	if count > MAX_LOGS {
		expectedCount = MAX_LOGS
	}
	expectedStart := 0
	if count > MAX_LOGS {
		expectedStart = count - MAX_LOGS
	}

	if len(logs) != expectedCount {
		t.Errorf("Got wrong number of logs in _testLogCount(_, %d): %d", count, len(logs))
		return
	}

	i := expectedStart
	for _, log := range logger.GetLogs() {
		if log.level != INFO {
			t.Errorf("Log level incorrect in _testLogCount(_, %d): %s", count, log.level.String())
			return
		}
		if log.message != fmt.Sprintf("I%d", i) {
			t.Errorf("Log message incorrect in _testLogCount(_, %d): %s", count, log.message)
			return
		}
		i += 1
	}
}

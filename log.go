package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Catch struct {
	Timestamp int64             `json:"timestamp"` // Will be set automatically when logging
	Source    string            `json:"src"`
	Host      string            `json:"host"`
	Path      string            `json:"path"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body"`
}

type Logger struct {
	mu  sync.Mutex
	out *os.File
}

func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &Logger{
		out: f,
	}, nil
}

func (l *Logger) LogCatch(catch Catch) {
	l.mu.Lock()
	defer l.mu.Unlock()

	catch.Timestamp = time.Now().Unix()

	b, err := json.Marshal(catch)
	if err != nil {
		log.Printf("failed to marshal log event: %v", err)
		return
	}

	b = append(b, '\n')

	if _, err := l.out.Write(b); err != nil {
		log.Printf("failed to write log event: %v", err)
	}
}

func (l *Logger) Close() {
	err := l.out.Close()
	if err != nil {
		log.Printf("[Error] failed to close log file: %v", err)
	}
}

// Convers the net/http headers to a better format for the JSON logs
func convertHeaders(h http.Header) map[string]string {
	out := make(map[string]string)

	for key, values := range h {
		if len(values) > 0 {
			out[key] = strings.Join(values, ", ")
		} else {
			out[key] = ""
		}
	}

	return out
}

// only for stdout
const (
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	reset  = "\033[0m"
)

func colored(color, s string, v ...any) {
	s = fmt.Sprintf("%s%s%s", color, s, reset)
	fmt.Printf(s, v...)
}

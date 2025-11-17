package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef void (*scanMessageCallback)(const char*, const char*, size_t);

// Helper function to call the callback from Go
static void callScanCallback(scanMessageCallback cb, const char* event, const char* msg, size_t len) {
    if (cb != NULL) {
        cb(event, msg, len);
    }
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/rs/xid"
)

var (
	scanCallback  C.scanMessageCallback
	callbackMutex sync.RWMutex
)

type MessageType int

const (
	MessageTypeLog MessageType = iota
	MessageTypeResult
	MessageTypeError
	MessageTypeProgress
	MessageTypeStatus
)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarning
	LogLevelError
	LogLevelFatal
)

type ScanMessage struct {
	Type      MessageType     `json:"type"`
	Timestamp int64           `json:"timestamp"`
	Data      json.RawMessage `json:"data,omitempty"`
}

type LogMessage struct {
	Level   LogLevel `json:"level"`
	Message string   `json:"message"`
}

type ErrorMessage struct {
	Error string `json:"error"`
	Code  uint8  `json:"code,omitempty"`
}

type StatusMessage struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type ProgressMessage struct {
	Current int    `json:"current"`
	Total   int    `json:"total"`
	Message string `json:"message,omitempty"`
}

//export initScanCallback
func initScanCallback(cb C.scanMessageCallback) {
	callbackMutex.Lock()
	defer callbackMutex.Unlock()
	scanCallback = cb
}

func sendMessage(event string, msgType MessageType, data interface{}) {
	callbackMutex.RLock()
	cb := scanCallback
	callbackMutex.RUnlock()

	if cb == nil {
		return
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return
	}

	msg := ScanMessage{
		Type:      msgType,
		Timestamp: time.Now().Unix(),
		Data:      dataJSON,
	}

	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return
	}

	cMsg := C.CString(string(msgJSON))
	cEvent := C.CString(event)
	defer C.free(unsafe.Pointer(cMsg))
	defer C.free(unsafe.Pointer(cEvent))
	C.callScanCallback(cb, cEvent, cMsg, C.size_t(len(msgJSON)))
}

func sendLog(event string, level LogLevel, message string) {
	sendMessage(event, MessageTypeLog, LogMessage{
		Level:   level,
		Message: message,
	})
}

func sendError(event string, err error, code uint8) {
	sendMessage(event, MessageTypeError, ErrorMessage{
		Error: err.Error(),
		Code:  code,
	})
}

func sendStatus(event string, status, message string) {
	sendMessage(event, MessageTypeStatus, StatusMessage{
		Status:  status,
		Message: message,
	})
}

type CustomWriter struct {
	originalWriter writer.Writer
	event          string
}

func (cw *CustomWriter) Write(p []byte, level levels.Level) {
	var result output.ResultEvent
	if err := json.Unmarshal(p, &result); err == nil {
		sendMessage(cw.event, MessageTypeResult, result)
	} else {
		sendLog(cw.event, LogLevelInfo, string(p))
	}

	if cw.originalWriter != nil {
		cw.originalWriter.Write(p, level)
	}
}

type NucleiConfig struct {
	Targets       []string `json:"targets"`
	Templates     []string `json:"templates"`
	TemplateURLs  []string `json:"template_urls"`
	Workflows     []string `json:"workflows"`
	Tags          []string `json:"tags"`
	ExcludeTags   []string `json:"exclude_tags"`
	Severity      []string `json:"severity"`
	Output        string   `json:"output"`
	JSON          bool     `json:"json"`
	Verbose       bool     `json:"verbose"`
	Silent        bool     `json:"silent"`
	NoColor       bool     `json:"no_color"`
	RateLimit     int      `json:"rate_limit"`
	Timeout       int      `json:"timeout"`
	Retries       int      `json:"retries"`
	BulkSize      int      `json:"bulk_size"`
	Concurrency   int      `json:"concurrency"`
	Proxy         []string `json:"proxy"`
	CustomHeaders []string `json:"custom_headers"`
	InteractshURL string   `json:"interactsh_url"`
	NoInteractsh  bool     `json:"no_interactsh"`
	ProjectPath   string   `json:"project_path"`
}

//export nucleiScan
func nucleiScan(event *C.char, configJSON *C.char) *C.char {
	if configJSON == nil {
		return C.CString(`{"error": "config is null"}`)
	}

	if event == nil {
		return C.CString(`{"error": "event is null"}`)
	}

	goEvent := C.GoString(event)

	var cfg NucleiConfig
	goConfigJSON := C.GoString(configJSON)
	if err := json.Unmarshal([]byte(goConfigJSON), &cfg); err != nil {
		sendError(goEvent, fmt.Errorf("failed to parse config: %w", err), 0)
		errMsg := fmt.Sprintf(`{"error": "failed to parse config: %s"}`, err.Error())
		return C.CString(errMsg)
	}

	sendStatus(goEvent, "started", "Scan initialization started")

	go func() {
		if err := runNucleiScan(goEvent, &cfg); err != nil {
			sendError(goEvent, err, 1)
		} else {
			sendStatus(goEvent, "completed", "Scan completed successfully")
		}
	}()

	return C.CString(`{"status": "scan started"}`)
}

func runNucleiScan(event string, cfg *NucleiConfig) error {
	sendLog(event, LogLevelInfo, "Initializing nuclei options...")

	options := &types.Options{}
	config.CurrentAppMode = config.AppModeCLI

	customWriter := &CustomWriter{
		event: event,
	}
	logger := gologger.DefaultLogger
	if cfg.JSON {
		logger.SetWriter(customWriter)
	}
	options.Logger = logger

	options.Targets = cfg.Targets
	options.Templates = cfg.Templates
	options.TemplateURLs = cfg.TemplateURLs
	options.Workflows = cfg.Workflows
	options.Tags = cfg.Tags
	options.ExcludeTags = cfg.ExcludeTags
	options.Output = cfg.Output
	options.JSONL = cfg.JSON
	options.Verbose = cfg.Verbose
	options.Silent = cfg.Silent
	options.NoColor = cfg.NoColor
	options.RateLimit = cfg.RateLimit
	options.Timeout = cfg.Timeout
	options.Retries = cfg.Retries
	options.BulkSize = cfg.BulkSize
	options.TemplateThreads = cfg.Concurrency
	options.Proxy = cfg.Proxy
	options.CustomHeaders = cfg.CustomHeaders
	options.InteractshURL = cfg.InteractshURL
	options.NoInteractsh = cfg.NoInteractsh
	options.ProjectPath = cfg.ProjectPath
	options.InputFileMode = "list"

	if options.RateLimit == 0 {
		options.RateLimit = 150
	}
	if options.Timeout == 0 {
		options.Timeout = 10
	}
	if options.Retries == 0 {
		options.Retries = 1
	}
	if options.BulkSize == 0 {
		options.BulkSize = 25
	}
	if options.TemplateThreads == 0 {
		options.TemplateThreads = 25
	}

	if len(cfg.Severity) > 0 {
		if err := options.Severities.Set(cfg.Severity[0]); err != nil {
			sendLog(event, LogLevelWarning, fmt.Sprintf("Invalid severity: %s", err.Error()))
		}
	}

	options.ExecutionId = xid.New().String()
	sendLog(event, LogLevelDebug, fmt.Sprintf("Execution ID: %s", options.ExecutionId))

	sendLog(event, LogLevelInfo, "Configuring scan options...")
	if err := runner.ConfigureOptions(); err != nil {
		return fmt.Errorf("failed to configure options: %w", err)
	}

	runner.ParseOptions(options)

	sendLog(event, LogLevelInfo, "Creating nuclei runner...")
	nucleiRunner, err := runner.New(options)
	if err != nil {
		return fmt.Errorf("failed to create runner: %w", err)
	}
	if nucleiRunner == nil {
		return fmt.Errorf("runner is nil")
	}
	defer nucleiRunner.Close()

	sendLog(event, LogLevelInfo, "Starting vulnerability scan...")
	sendStatus(event, "scanning", "Enumeration in progress")

	if err := nucleiRunner.RunEnumeration(); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	sendLog(event, LogLevelInfo, "Scan enumeration completed")
	return nil
}

//export nucleiVersion
func nucleiVersion() *C.char {
	version := config.Version
	return C.CString(version)
}

//export freeString
func freeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

func main() {}

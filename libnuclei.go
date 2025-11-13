package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef void (*scanMessageCallback)(const char*, size_t);

// Helper function to call the callback from Go
static void callScanCallback(scanMessageCallback cb, const char* msg, size_t len) {
    if (cb != NULL) {
        cb(msg, len);
    }
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
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
	Code  string `json:"code,omitempty"`
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

func sendMessage(cb C.scanMessageCallback, msgType MessageType, data interface{}) {
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

	cStr := C.CString(string(msgJSON))
	defer C.free(unsafe.Pointer(cStr))
	C.callScanCallback(cb, cStr, C.size_t(len(msgJSON)))
}

func sendLog(cb C.scanMessageCallback, level LogLevel, message string) {
	sendMessage(cb, MessageTypeLog, LogMessage{
		Level:   level,
		Message: message,
	})
}

func sendError(cb C.scanMessageCallback, err error, code string) {
	sendMessage(cb, MessageTypeError, ErrorMessage{
		Error: err.Error(),
		Code:  code,
	})
}

func sendStatus(cb C.scanMessageCallback, status, message string) {
	sendMessage(cb, MessageTypeStatus, StatusMessage{
		Status:  status,
		Message: message,
	})
}

type CustomWriter struct {
	originalWriter writer.Writer
	callback       C.scanMessageCallback
}

func (cw *CustomWriter) Write(p []byte, level levels.Level) {
	var result output.ResultEvent
	if err := json.Unmarshal(p, &result); err == nil {
		sendMessage(cw.callback, MessageTypeResult, result)
	} else {
		sendLog(cw.callback, LogLevelInfo, string(p))
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
func nucleiScan(callback C.scanMessageCallback, configJSON *C.char) *C.char {
	if configJSON == nil {
		sendError(callback, fmt.Errorf("config is null"), "NULL_CONFIG")
		return C.CString(`{"error": "config is null"}`)
	}

	var cfg NucleiConfig
	goConfigJSON := C.GoString(configJSON)
	if err := json.Unmarshal([]byte(goConfigJSON), &cfg); err != nil {
		sendError(callback, fmt.Errorf("failed to parse config: %w", err), "PARSE_ERROR")
		errMsg := fmt.Sprintf(`{"error": "failed to parse config: %s"}`, err.Error())
		return C.CString(errMsg)
	}

	sendStatus(callback, "started", "Scan initialization started")

	go func() {
		if err := runNucleiScan(callback, &cfg); err != nil {
			sendError(callback, err, "SCAN_ERROR")
		} else {
			sendStatus(callback, "completed", "Scan completed successfully")
		}
	}()

	return C.CString(`{"status": "scan started"}`)
}

func runNucleiScan(callback C.scanMessageCallback, cfg *NucleiConfig) error {
	sendLog(callback, LogLevelInfo, "Initializing nuclei options...")

	options := &types.Options{}
	config.CurrentAppMode = config.AppModeCLI

	customWriter := &CustomWriter{
		callback: callback,
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
			sendLog(callback, LogLevelWarning, fmt.Sprintf("Invalid severity: %s", err.Error()))
		}
	}

	options.ExecutionId = xid.New().String()
	sendLog(callback, LogLevelDebug, fmt.Sprintf("Execution ID: %s", options.ExecutionId))

	sendLog(callback, LogLevelInfo, "Configuring scan options...")
	if err := runner.ConfigureOptions(); err != nil {
		return fmt.Errorf("failed to configure options: %w", err)
	}

	runner.ParseOptions(options)

	sendLog(callback, LogLevelInfo, "Creating nuclei runner...")
	nucleiRunner, err := runner.New(options)
	if err != nil {
		return fmt.Errorf("failed to create runner: %w", err)
	}
	if nucleiRunner == nil {
		return fmt.Errorf("runner is nil")
	}
	defer nucleiRunner.Close()

	sendLog(callback, LogLevelInfo, "Starting vulnerability scan...")
	sendStatus(callback, "scanning", "Enumeration in progress")

	if err := nucleiRunner.RunEnumeration(); err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	sendLog(callback, LogLevelInfo, "Scan enumeration completed")
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

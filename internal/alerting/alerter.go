// Package alerting dispatches detection alerts to multiple sinks:
// structured log file, optional webhook, and optional InfluxDB telemetry.
package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aliciamew/ddos-early-warning/internal/ebpfloader"
	"github.com/aliciamew/ddos-early-warning/internal/inference"
)

// Alert represents a single detection event.
type Alert struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	Score     float32   `json:"score"`
	PktCount  float32   `json:"pkt_count"`
	ByteCount float32   `json:"byte_count"`
	SYNCount  float32   `json:"syn_count"`
	Action    string    `json:"action"` // "alert" | "block"
}

// Alerter manages alert dispatch.
type Alerter struct {
	mu         sync.Mutex
	logFile    *os.File
	logger     *log.Logger
	webhookURL string
	httpClient *http.Client
}

// New creates a new Alerter with the given log file and optional webhook.
func New(logPath string, webhookURL string) (*Alerter, error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open alert log %s: %w", logPath, err)
	}

	return &Alerter{
		logFile:    f,
		logger:     log.New(f, "", 0), // we'll format our own timestamps
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// Fire processes a detection result and dispatches alerts.
func (a *Alerter) Fire(result inference.Result, action string) {
	srcIP := ebpfloader.Uint32ToIP(result.SrcIP)

	alert := Alert{
		Timestamp: time.Now().UTC(),
		SrcIP:     srcIP,
		Score:     result.Score,
		PktCount:  result.Features[0],
		ByteCount: result.Features[1],
		SYNCount:  result.Features[2],
		Action:    action,
	}

	// Log to file (JSON-lines format)
	a.logToFile(alert)

	// Log to stdout
	fmt.Printf("[%s] %s src=%s score=%.4f pkts=%.0f bytes=%.0f syns=%.0f\n",
		alert.Timestamp.Format(time.RFC3339),
		action,
		srcIP,
		alert.Score,
		alert.PktCount,
		alert.ByteCount,
		alert.SYNCount,
	)

	// Optional webhook
	if a.webhookURL != "" {
		go a.sendWebhook(alert)
	}
}

func (a *Alerter) logToFile(alert Alert) {
	a.mu.Lock()
	defer a.mu.Unlock()

	data, _ := json.Marshal(alert)
	a.logger.Println(string(data))
}

func (a *Alerter) sendWebhook(alert Alert) {
	payload, _ := json.Marshal(map[string]interface{}{
		"text": fmt.Sprintf("🚨 DDoS Alert: %s from %s (score: %.2f, pkts: %.0f)",
			alert.Action, alert.SrcIP, alert.Score, alert.PktCount),
		"alert": alert,
	})

	resp, err := a.httpClient.Post(a.webhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("webhook error: %v", err)
		return
	}
	resp.Body.Close()
}

// Close flushes and closes the log file.
func (a *Alerter) Close() {
	if a.logFile != nil {
		a.logFile.Close()
	}
}

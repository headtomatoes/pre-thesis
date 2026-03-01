// cmd/controller/main.go — Entry point for the DDoS Early Warning controller.
//
// This is the "Smart Control Plane" that:
//   1. Loads the XDP/eBPF program and attaches it to a network interface.
//   2. Polls eBPF maps every N milliseconds.
//   3. Computes feature vectors from raw counters.
//   4. Runs ONNX inference (XGBoost model) on each source IP.
//   5. Issues alerts and optionally blacklists malicious IPs via XDP_DROP.
//
// Usage:
//   sudo ./controller --config configs/config.yaml

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aliciamew/ddos-early-warning/internal/alerting"
	"github.com/aliciamew/ddos-early-warning/internal/config"
	"github.com/aliciamew/ddos-early-warning/internal/ebpfloader"
	"github.com/aliciamew/ddos-early-warning/internal/features"
	"github.com/aliciamew/ddos-early-warning/internal/inference"
	"github.com/aliciamew/ddos-early-warning/internal/metrics"
)

func main() {
	// ── Parse flags ──
	configPath := flag.String("config", "configs/config.yaml", "Path to YAML config file")
	flag.Parse()

	// ── Load configuration ──
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("DDoS Early Warning Controller starting...")
	log.Printf("  Interface:     %s", cfg.Interface)
	log.Printf("  BPF Object:    %s", cfg.BPFObject)
	log.Printf("  Poll Interval: %s", cfg.PollInterval.Duration)
	log.Printf("  Model:         %s (threshold=%.2f)", cfg.Model.Path, cfg.Model.Threshold)

	// ── Load and attach eBPF/XDP ──
	objs, err := ebpfloader.Load(cfg.BPFObject)
	if err != nil {
		log.Fatalf("Failed to load BPF object: %v", err)
	}
	defer objs.Detach()

	if err := objs.Attach(cfg.Interface); err != nil {
		log.Fatalf("Failed to attach XDP to %s: %v", cfg.Interface, err)
	}
	log.Printf("XDP program attached to %s", cfg.Interface)

	// ── Initialise ONNX inference engine ──
	engine, err := inference.NewEngine(cfg.Model.Path)
	if err != nil {
		log.Fatalf("Failed to load ONNX model: %v", err)
	}
	defer engine.Close()
	log.Printf("ONNX model loaded: %s", cfg.Model.Path)

	// ── Initialise alerting ──
	alerter, err := alerting.New(cfg.Alerting.LogFile, cfg.Alerting.WebhookURL)
	if err != nil {
		log.Fatalf("Failed to init alerter: %v", err)
	}
	defer alerter.Close()

	// ── Initialise metrics (optional InfluxDB) ──
	metricsWriter := metrics.NewWriter(cfg.InfluxDB)
	defer metricsWriter.Close()

	// ── Set up graceful shutdown ──
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// ── Main polling loop ──
	ticker := time.NewTicker(cfg.PollInterval.Duration)
	defer ticker.Stop()

	log.Printf("Entering main loop (poll every %s)...", cfg.PollInterval.Duration)
	cycleCount := 0

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutdown complete.")
			return
		case <-ticker.C:
			cycleCount++
			pollStart := time.Now()

			if err := runDetectionCycle(objs, engine, alerter, metricsWriter, cfg, cycleCount); err != nil {
				log.Printf("Cycle %d error: %v", cycleCount, err)
			}

			elapsed := time.Since(pollStart)
			if cycleCount%10 == 0 {
				log.Printf("Cycle %d completed in %s", cycleCount, elapsed)
			}
		}
	}
}

// runDetectionCycle performs one iteration of the detection pipeline:
//
//	Map Poll → Feature Extraction → Inference → Alert/Block
func runDetectionCycle(
	objs *ebpfloader.Objects,
	engine *inference.Engine,
	alerter *alerting.Alerter,
	mw *metrics.Writer,
	cfg *config.Config,
	cycle int,
) error {
	// ── 1. Read global counters ──
	gc, err := objs.GetGlobalCounters()
	if err != nil {
		return fmt.Errorf("read global counters: %w", err)
	}
	mw.WriteGlobal(gc)

	// ── 2. Iterate flow map and compute feature vectors ──
	var vectors []features.Vector

	err = objs.IterateFlows(func(key ebpfloader.FlowKey, counters ebpfloader.FlowCounters) {
		vec := features.Compute(key, counters)
		vectors = append(vectors, vec)
	})
	if err != nil {
		return fmt.Errorf("iterate flows: %w", err)
	}

	if len(vectors) == 0 {
		return nil // no traffic in this interval
	}

	// ── 3. Run ML inference ──
	results, err := engine.Predict(vectors, cfg.Model.Threshold)
	if err != nil {
		return fmt.Errorf("inference: %w", err)
	}

	// ── 4. Process results ──
	for _, result := range results {
		mw.WriteDetection(result)

		if !result.IsAttack {
			continue
		}

		action := "ALERT"
		if cfg.Blacklist.Enabled {
			action = "BLOCK"
			if err := objs.AddToBlacklist(result.SrcIP, uint64(cfg.Blacklist.TTLS.Duration)); err != nil {
				log.Printf("Failed to blacklist %s: %v", ebpfloader.Uint32ToIP(result.SrcIP), err)
			}
		}

		alerter.Fire(result, action)
	}

	// ── 5. Reset flow counters for next interval ──
	if err := objs.ClearFlowStats(); err != nil {
		return fmt.Errorf("clear flow stats: %w", err)
	}

	return nil
}

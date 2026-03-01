// Package metrics provides optional InfluxDB telemetry for the
// DDoS Early Warning dashboard (Grafana integration).
package metrics

import (
	"context"
	"fmt"
	"log"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"

	"github.com/aliciamew/ddos-early-warning/internal/config"
	"github.com/aliciamew/ddos-early-warning/internal/ebpfloader"
	"github.com/aliciamew/ddos-early-warning/internal/inference"
)

// Writer sends timestamped metrics to InfluxDB.
type Writer struct {
	client   influxdb2.Client
	writeAPI api.WriteAPIBlocking
	bucket   string
	org      string
}

// NewWriter creates an InfluxDB metrics writer. Returns nil if disabled.
func NewWriter(cfg config.InfluxConfig) *Writer {
	if !cfg.Enabled {
		return nil
	}

	client := influxdb2.NewClient(cfg.URL, cfg.Token)
	writeAPI := client.WriteAPIBlocking(cfg.Org, cfg.Bucket)

	return &Writer{
		client:   client,
		writeAPI: writeAPI,
		bucket:   cfg.Bucket,
		org:      cfg.Org,
	}
}

// WriteGlobal writes aggregate throughput metrics.
func (w *Writer) WriteGlobal(gc ebpfloader.GlobalCounters) {
	if w == nil {
		return
	}

	p := influxdb2.NewPointWithMeasurement("global_throughput").
		AddField("total_pkts", int64(gc.TotalPkts)).
		AddField("total_bytes", int64(gc.TotalBytes)).
		AddField("total_dropped", int64(gc.TotalDropped)).
		SetTime(time.Now())

	if err := w.writeAPI.WritePoint(context.Background(), p); err != nil {
		log.Printf("influxdb write error (global): %v", err)
	}
}

// WriteDetection writes per-IP detection results for dashboard visualisation.
func (w *Writer) WriteDetection(result inference.Result) {
	if w == nil {
		return
	}

	srcIP := ebpfloader.Uint32ToIP(result.SrcIP)

	p := influxdb2.NewPointWithMeasurement("detection").
		AddTag("src_ip", srcIP).
		AddTag("is_attack", fmt.Sprintf("%t", result.IsAttack)).
		AddField("score", float64(result.Score)).
		AddField("pkt_count", float64(result.Features[0])).
		AddField("byte_count", float64(result.Features[1])).
		AddField("syn_count", float64(result.Features[2])).
		AddField("syn_ack_ratio", float64(result.Features[4])).
		AddField("pkt_size_mean", float64(result.Features[5])).
		AddField("flow_duration", float64(result.Features[7])).
		AddField("iat_mean", float64(result.Features[9])).
		SetTime(time.Now())

	if err := w.writeAPI.WritePoint(context.Background(), p); err != nil {
		log.Printf("influxdb write error (detection): %v", err)
	}
}

// Close flushes pending writes and closes the InfluxDB client.
func (w *Writer) Close() {
	if w == nil {
		return
	}
	w.client.Close()
}

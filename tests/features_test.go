// tests/features_test.go — Unit tests for the feature extraction module.
//
// These tests verify that the Compute function correctly transforms
// raw eBPF counters into the 10-feature vector expected by the ONNX model.
//
// Run: go test -v ./tests/

package tests

import (
	"math"
	"testing"

	"github.com/aliciamew/ddos-early-warning/internal/ebpfloader"
	"github.com/aliciamew/ddos-early-warning/internal/features"
)

const epsilon = 1e-4 // float comparison tolerance

func TestComputeBasicCounters(t *testing.T) {
	key := ebpfloader.FlowKey{SrcIP: 0x0A000001} // 10.0.0.1

	counters := ebpfloader.FlowCounters{
		PktCount:     100,
		ByteCount:    15000,
		SYNCount:     80,
		ACKCount:     20,
		TCPCount:     100,
		UDPCount:     0,
		ICMPCount:    0,
		OtherProto:   0,
		PktSizeSumSq: 2500000,
		FirstSeenNs:  1000000000, // 1s
		LastSeenNs:   3000000000, // 3s
		IATSumNs:     2000000000, // 2s total IAT
		IATSumSqNs:   0,
	}

	vec := features.Compute(key, counters)

	// Feature 1: Packet Count
	if vec.Features[features.FeatPktCount] != 100 {
		t.Errorf("PktCount: got %f, want 100", vec.Features[features.FeatPktCount])
	}

	// Feature 2: Byte Count
	if vec.Features[features.FeatByteCount] != 15000 {
		t.Errorf("ByteCount: got %f, want 15000", vec.Features[features.FeatByteCount])
	}

	// Feature 3: SYN Count
	if vec.Features[features.FeatSYNCount] != 80 {
		t.Errorf("SYNCount: got %f, want 80", vec.Features[features.FeatSYNCount])
	}

	// Feature 4: ACK Count
	if vec.Features[features.FeatACKCount] != 20 {
		t.Errorf("ACKCount: got %f, want 20", vec.Features[features.FeatACKCount])
	}

	// Feature 5: SYN/ACK Ratio = 80/20 = 4.0
	if math.Abs(float64(vec.Features[features.FeatSYNACKRatio])-4.0) > epsilon {
		t.Errorf("SYN/ACK Ratio: got %f, want 4.0", vec.Features[features.FeatSYNACKRatio])
	}

	// Feature 6: Packet Size Mean = 15000/100 = 150
	if math.Abs(float64(vec.Features[features.FeatPktSizeMean])-150.0) > epsilon {
		t.Errorf("PktSizeMean: got %f, want 150.0", vec.Features[features.FeatPktSizeMean])
	}

	// Feature 8: Flow Duration = (3s - 1s) = 2.0 seconds
	if math.Abs(float64(vec.Features[features.FeatFlowDuration])-2.0) > epsilon {
		t.Errorf("FlowDuration: got %f, want 2.0", vec.Features[features.FeatFlowDuration])
	}

	// Feature 9: Protocol Entropy — only TCP, so entropy = 0
	if vec.Features[features.FeatProtoEntropy] != 0 {
		t.Errorf("ProtoEntropy: got %f, want 0 (single protocol)", vec.Features[features.FeatProtoEntropy])
	}
}

func TestComputeZeroPackets(t *testing.T) {
	key := ebpfloader.FlowKey{SrcIP: 0}
	counters := ebpfloader.FlowCounters{} // all zeros

	vec := features.Compute(key, counters)

	for i := 0; i < features.VectorSize; i++ {
		if vec.Features[i] != 0 {
			t.Errorf("Feature[%d] should be 0 for zero counters, got %f", i, vec.Features[i])
		}
	}
}

func TestComputeSYNACKRatioNoACK(t *testing.T) {
	key := ebpfloader.FlowKey{SrcIP: 0x0A000002}
	counters := ebpfloader.FlowCounters{
		PktCount:    50,
		ByteCount:   3000,
		SYNCount:    50,
		ACKCount:    0, // No ACKs — classic SYN flood
		TCPCount:    50,
		FirstSeenNs: 1000000000,
		LastSeenNs:  1500000000,
	}

	vec := features.Compute(key, counters)

	// When ACK=0, ratio should equal SYN count
	if vec.Features[features.FeatSYNACKRatio] != 50 {
		t.Errorf("SYN/ACK Ratio with 0 ACK: got %f, want 50", vec.Features[features.FeatSYNACKRatio])
	}
}

func TestComputeProtocolEntropy(t *testing.T) {
	key := ebpfloader.FlowKey{SrcIP: 0x0A000003}
	counters := ebpfloader.FlowCounters{
		PktCount:    100,
		ByteCount:   10000,
		TCPCount:    50,
		UDPCount:    50,
		ICMPCount:   0,
		OtherProto:  0,
		FirstSeenNs: 1000000000,
		LastSeenNs:  2000000000,
	}

	vec := features.Compute(key, counters)

	// 50/50 split between TCP and UDP → entropy = 1.0 bit
	expected := float32(1.0)
	if math.Abs(float64(vec.Features[features.FeatProtoEntropy]-expected)) > epsilon {
		t.Errorf("ProtoEntropy: got %f, want %f", vec.Features[features.FeatProtoEntropy], expected)
	}
}

func TestIPConversion(t *testing.T) {
	ip := ebpfloader.Uint32ToIP(0x0A000001)
	if ip != "10.0.0.1" {
		t.Errorf("Uint32ToIP: got %s, want 10.0.0.1", ip)
	}
}

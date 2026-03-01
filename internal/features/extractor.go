// Package features computes the "Lightweight 10" feature vector from
// raw eBPF map counters. All heavy arithmetic (variance, entropy)
// is performed here in userspace while the kernel path stays integer-only.
package features

import (
	"math"

	"github.com/aliciamew/ddos-early-warning/internal/ebpfloader"
)

// VectorSize is the number of features fed into the ONNX model.
const VectorSize = 10

// Vector holds the computed feature values for a single source IP.
// The order MUST match the training feature order in ml/scripts/train.py.
type Vector struct {
	SrcIP    uint32 // for identification, not part of the model input
	Features [VectorSize]float32
}

// FeatureIndex constants document which slot maps to which feature.
const (
	FeatPktCount     = 0 // Feature 1: Packet Count
	FeatByteCount    = 1 // Feature 2: Byte Count
	FeatSYNCount     = 2 // Feature 3: SYN Flag Count
	FeatACKCount     = 3 // Feature 4: ACK Flag Count
	FeatSYNACKRatio  = 4 // Feature 5: SYN/ACK Ratio
	FeatPktSizeMean  = 5 // Feature 6: Packet Size Mean
	FeatPktSizeVar   = 6 // Feature 7: Packet Size Variance
	FeatFlowDuration = 7 // Feature 8: Flow Duration (seconds)
	FeatProtoEntropy = 8 // Feature 9: Protocol Entropy
	FeatIATMean      = 9 // Feature 10: Inter-Arrival Time Mean (µs)
)

// Compute transforms raw eBPF counters into a normalised feature vector.
func Compute(key ebpfloader.FlowKey, c ebpfloader.FlowCounters) Vector {
	v := Vector{SrcIP: key.SrcIP}

	pktCount := float64(c.PktCount)
	if pktCount == 0 {
		return v
	}

	// Feature 1: Packet Count
	v.Features[FeatPktCount] = float32(c.PktCount)

	// Feature 2: Byte Count
	v.Features[FeatByteCount] = float32(c.ByteCount)

	// Feature 3: SYN Flag Count
	v.Features[FeatSYNCount] = float32(c.SYNCount)

	// Feature 4: ACK Flag Count
	v.Features[FeatACKCount] = float32(c.ACKCount)

	// Feature 5: SYN/ACK Ratio
	if c.ACKCount > 0 {
		v.Features[FeatSYNACKRatio] = float32(c.SYNCount) / float32(c.ACKCount)
	} else if c.SYNCount > 0 {
		v.Features[FeatSYNACKRatio] = float32(c.SYNCount) // infinity-like: all SYN, no ACK
	}

	// Feature 6: Packet Size Mean = TotalBytes / PktCount
	mean := float64(c.ByteCount) / pktCount
	v.Features[FeatPktSizeMean] = float32(mean)

	// Feature 7: Packet Size Variance
	//   Var(X) = E[X²] - (E[X])²
	//   E[X²] = PktSizeSumSq / PktCount
	if pktCount > 1 {
		eX2 := float64(c.PktSizeSumSq) / pktCount
		variance := eX2 - (mean * mean)
		if variance < 0 {
			variance = 0 // numerical guard
		}
		v.Features[FeatPktSizeVar] = float32(variance)
	}

	// Feature 8: Flow Duration (seconds)
	if c.LastSeenNs > c.FirstSeenNs {
		durationNs := float64(c.LastSeenNs - c.FirstSeenNs)
		v.Features[FeatFlowDuration] = float32(durationNs / 1e9) // → seconds
	}

	// Feature 9: Protocol Entropy (Shannon entropy over protocol distribution)
	v.Features[FeatProtoEntropy] = float32(protocolEntropy(c))

	// Feature 10: Inter-Arrival Time Mean (microseconds)
	if pktCount > 1 {
		iatMeanNs := float64(c.IATSumNs) / (pktCount - 1)
		v.Features[FeatIATMean] = float32(iatMeanNs / 1e3) // → µs
	}

	return v
}

// protocolEntropy computes Shannon entropy over the protocol distribution
// for a single source IP: H = -Σ p_i * log2(p_i)
func protocolEntropy(c ebpfloader.FlowCounters) float64 {
	total := float64(c.TCPCount + c.UDPCount + c.ICMPCount + c.OtherProto)
	if total == 0 {
		return 0
	}

	counts := []float64{
		float64(c.TCPCount),
		float64(c.UDPCount),
		float64(c.ICMPCount),
		float64(c.OtherProto),
	}

	var entropy float64
	for _, cnt := range counts {
		if cnt == 0 {
			continue
		}
		p := cnt / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// Package ebpfloader handles loading the compiled XDP/eBPF object,
// attaching it to a network interface, and providing typed access
// to the eBPF maps shared with the kernel program.
package ebpfloader

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ────────────────────────────────────────────
// Mirror structs from bpf/xdp_prog.h
// Must match exactly (size, alignment).
// ────────────────────────────────────────────

// FlowKey matches struct flow_key in xdp_prog.h.
type FlowKey struct {
	SrcIP uint32
}

// FlowCounters matches struct flow_counters in xdp_prog.h.
type FlowCounters struct {
	PktCount     uint64
	ByteCount    uint64
	SYNCount     uint64
	ACKCount     uint64
	UDPCount     uint64
	ICMPCount    uint64
	TCPCount     uint64
	OtherProto   uint64
	PktSizeSumSq uint64
	FirstSeenNs  uint64
	LastSeenNs   uint64
	IATSumNs     uint64
	IATSumSqNs   uint64
}

// GlobalCounters matches struct global_counters in xdp_prog.h.
type GlobalCounters struct {
	TotalPkts    uint64
	TotalBytes   uint64
	TotalDropped uint64
}

// BlacklistEntry matches struct blacklist_entry in xdp_prog.h.
type BlacklistEntry struct {
	BlockedAtNs uint64
	TTLNs       uint64
}

// Objects holds references to the loaded eBPF program and maps.
type Objects struct {
	Program   *ebpf.Program
	FlowStats *ebpf.Map
	Global    *ebpf.Map
	Blacklist *ebpf.Map
	xdpLink   link.Link
}

// Load compiles-loads the BPF object file and returns typed handles.
func Load(objPath string) (*Objects, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create BPF collection: %w", err)
	}

	prog := coll.Programs["xdp_ddos_detector"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("program 'xdp_ddos_detector' not found in %s", objPath)
	}

	return &Objects{
		Program:   prog,
		FlowStats: coll.Maps["flow_stats"],
		Global:    coll.Maps["global_stats"],
		Blacklist: coll.Maps["blacklist"],
	}, nil
}

// Attach attaches the XDP program to the given network interface.
func (o *Objects) Attach(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   o.Program,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
	}

	o.xdpLink = l
	return nil
}

// Detach removes the XDP program from the interface and closes all handles.
func (o *Objects) Detach() {
	if o.xdpLink != nil {
		o.xdpLink.Close()
	}
	if o.Program != nil {
		o.Program.Close()
	}
	if o.FlowStats != nil {
		o.FlowStats.Close()
	}
	if o.Global != nil {
		o.Global.Close()
	}
	if o.Blacklist != nil {
		o.Blacklist.Close()
	}
}

// ────────────────────────────────────────────
// Map access helpers
// ────────────────────────────────────────────

// IterateFlows calls fn for every source IP in the per-CPU flow_stats map.
// It aggregates per-CPU values automatically.
func (o *Objects) IterateFlows(fn func(key FlowKey, agg FlowCounters)) error {
	var (
		key  FlowKey
		vals []FlowCounters // per-CPU slice
	)

	iter := o.FlowStats.Iterate()
	for iter.Next(&key, &vals) {
		agg := aggregateCounters(vals)
		fn(key, agg)
	}
	return iter.Err()
}

// GetGlobalCounters reads and aggregates the global per-CPU counters.
func (o *Objects) GetGlobalCounters() (GlobalCounters, error) {
	var (
		key  uint32 = 0
		vals []GlobalCounters
	)

	if err := o.Global.Lookup(&key, &vals); err != nil {
		return GlobalCounters{}, err
	}

	var agg GlobalCounters
	for _, v := range vals {
		agg.TotalPkts += v.TotalPkts
		agg.TotalBytes += v.TotalBytes
		agg.TotalDropped += v.TotalDropped
	}
	return agg, nil
}

// AddToBlacklist inserts an IP into the XDP blacklist map.
func (o *Objects) AddToBlacklist(srcIP uint32, ttlNs uint64) error {
	key := FlowKey{SrcIP: srcIP}
	val := BlacklistEntry{
		BlockedAtNs: 0, // XDP program uses bpf_ktime_get_ns(); set 0 here, kernel handles
		TTLNs:       ttlNs,
	}
	return o.Blacklist.Put(&key, &val)
}

// RemoveFromBlacklist deletes an IP from the XDP blacklist map.
func (o *Objects) RemoveFromBlacklist(srcIP uint32) error {
	key := FlowKey{SrcIP: srcIP}
	return o.Blacklist.Delete(&key)
}

// ClearFlowStats deletes all entries from the flow_stats map
// (called after each polling cycle to reset counters).
func (o *Objects) ClearFlowStats() error {
	var key FlowKey
	keys := make([]FlowKey, 0, 1024)

	iter := o.FlowStats.Iterate()
	for iter.Next(&key, nil) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		_ = o.FlowStats.Delete(&k)
	}
	return nil
}

// ────────────────────────────────────────────
// Utility
// ────────────────────────────────────────────

// aggregateCounters sums per-CPU counter slices into a single struct.
func aggregateCounters(vals []FlowCounters) FlowCounters {
	var agg FlowCounters
	for _, v := range vals {
		agg.PktCount += v.PktCount
		agg.ByteCount += v.ByteCount
		agg.SYNCount += v.SYNCount
		agg.ACKCount += v.ACKCount
		agg.UDPCount += v.UDPCount
		agg.ICMPCount += v.ICMPCount
		agg.TCPCount += v.TCPCount
		agg.OtherProto += v.OtherProto
		agg.PktSizeSumSq += v.PktSizeSumSq

		// For timestamps, take earliest first_seen and latest last_seen
		if agg.FirstSeenNs == 0 || (v.FirstSeenNs > 0 && v.FirstSeenNs < agg.FirstSeenNs) {
			agg.FirstSeenNs = v.FirstSeenNs
		}
		if v.LastSeenNs > agg.LastSeenNs {
			agg.LastSeenNs = v.LastSeenNs
		}
		agg.IATSumNs += v.IATSumNs
		agg.IATSumSqNs += v.IATSumSqNs
	}
	return agg
}

// IPToUint32 converts a net.IP to a uint32 in network byte order.
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Uint32ToIP converts a uint32 in network byte order to a string.
func Uint32ToIP(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

// Ensure struct sizes match the C definitions at compile time.
func init() {
	// FlowCounters has 13 uint64 fields = 104 bytes
	if sz := unsafe.Sizeof(FlowCounters{}); sz != 104 {
		fmt.Fprintf(os.Stderr, "WARNING: FlowCounters size mismatch: got %d, expected 104\n", sz)
	}
}

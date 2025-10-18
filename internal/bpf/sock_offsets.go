package bpf

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
	"go.uber.org/zap"
)

// SockCommonOffsets stores runtime-detected offsets for sock_common struct
// This makes us immune to kernel struct layout changes, RANDSTRUCT, etc.
type SockCommonOffsets struct {
	SkcDaddr      uint32 // skc_daddr offset in bytes
	SkcRcvSaddr   uint32 // skc_rcv_saddr offset
	SkcDport      uint32 // skc_dport offset
	SkcNum        uint32 // skc_num (source port) offset
	SkcFamily     uint32 // skc_family offset
	SkcState      uint32 // skc_state offset
	SkcV6Daddr    uint32 // skc_v6_daddr offset
	SkcV6RcvSaddr uint32 // skc_v6_rcv_saddr offset
}

// DetectSockCommonOffsets uses BTF to detect runtime offsets for sock_common struct
// This protects against:
// - Kernel version changes (fields added/reordered)
// - RANDSTRUCT (randomized struct layouts)
// - Custom kernel patches
//
// Returns:
//   - *SockCommonOffsets: Detected offsets in bytes
//   - error: If BTF unavailable or critical fields not found
func DetectSockCommonOffsets(logger *zap.Logger) (*SockCommonOffsets, error) {
	// Load kernel BTF specification
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel BTF: %w", err)
	}

	offsets := &SockCommonOffsets{}

	// Find sock_common struct
	var sockCommon *btf.Struct
	if err := spec.TypeByName("sock_common", &sockCommon); err != nil {
		return nil, fmt.Errorf("sock_common type not found in BTF: %w", err)
	}

	// Track which critical fields we found
	foundFields := make(map[string]bool)
	requiredFields := []string{"skc_family", "skc_dport", "skc_num", "skc_daddr", "skc_rcv_saddr"}

	// Extract offsets for all fields we need
	for _, member := range sockCommon.Members {
		offset := member.Offset.Bytes()

		switch member.Name {
		case "skc_daddr":
			offsets.SkcDaddr = offset
			foundFields["skc_daddr"] = true
			logger.Debug("Detected skc_daddr offset", zap.Uint32("offset", offset))

		case "skc_rcv_saddr":
			offsets.SkcRcvSaddr = offset
			foundFields["skc_rcv_saddr"] = true
			logger.Debug("Detected skc_rcv_saddr offset", zap.Uint32("offset", offset))

		case "skc_dport":
			offsets.SkcDport = offset
			foundFields["skc_dport"] = true
			logger.Debug("Detected skc_dport offset", zap.Uint32("offset", offset))

		case "skc_num":
			offsets.SkcNum = offset
			foundFields["skc_num"] = true
			logger.Debug("Detected skc_num offset", zap.Uint32("offset", offset))

		case "skc_family":
			offsets.SkcFamily = offset
			foundFields["skc_family"] = true
			logger.Debug("Detected skc_family offset", zap.Uint32("offset", offset))

		case "skc_state":
			offsets.SkcState = offset
			logger.Debug("Detected skc_state offset", zap.Uint32("offset", offset))

		case "skc_v6_daddr":
			offsets.SkcV6Daddr = offset
			logger.Debug("Detected skc_v6_daddr offset", zap.Uint32("offset", offset))

		case "skc_v6_rcv_saddr":
			offsets.SkcV6RcvSaddr = offset
			logger.Debug("Detected skc_v6_rcv_saddr offset", zap.Uint32("offset", offset))
		}
	}

	// Validate that all required fields were found
	for _, field := range requiredFields {
		if !foundFields[field] {
			return nil, fmt.Errorf("required field %s not found in sock_common", field)
		}
	}

	logger.Info("Successfully detected sock_common offsets",
		zap.Uint32("skc_family", offsets.SkcFamily),
		zap.Uint32("skc_dport", offsets.SkcDport),
		zap.Uint32("skc_num", offsets.SkcNum),
		zap.Uint32("skc_daddr", offsets.SkcDaddr),
		zap.Uint32("skc_rcv_saddr", offsets.SkcRcvSaddr))

	return offsets, nil
}

// ValidateOffsets performs sanity checks on detected offsets
func (o *SockCommonOffsets) ValidateOffsets() error {
	// sock_common is typically < 256 bytes
	const maxReasonableOffset = 256

	fields := map[string]uint32{
		"skc_family":      o.SkcFamily,
		"skc_dport":       o.SkcDport,
		"skc_num":         o.SkcNum,
		"skc_daddr":       o.SkcDaddr,
		"skc_rcv_saddr":   o.SkcRcvSaddr,
		"skc_state":       o.SkcState,
		"skc_v6_daddr":    o.SkcV6Daddr,
		"skc_v6_rcv_saddr": o.SkcV6RcvSaddr,
	}

	for name, offset := range fields {
		if offset > maxReasonableOffset {
			return fmt.Errorf("%s offset %d exceeds reasonable limit %d", name, offset, maxReasonableOffset)
		}
	}

	return nil
}

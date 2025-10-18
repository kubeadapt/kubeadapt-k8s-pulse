package bpf

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
	"go.uber.org/zap"
)

// NetnsOffsets stores runtime-detected struct offsets for network namespace access
// These offsets are detected at runtime using BTF and stored in BPF maps
// for MODE 1 (strict) network namespace filtering
type NetnsOffsets struct {
	TaskNsproxy  uint32 // task_struct->nsproxy offset in bytes
	NsproxyNetNs uint32 // nsproxy->net_ns offset in bytes
	NetNsInum    uint32 // net->ns.inum offset in bytes (combined net->ns + ns->inum)
}

// DetectNetnsOffsets uses BTF to detect runtime offsets for network namespace structs
// This allows BPF programs to access task_struct->nsproxy->net_ns->ns.inum
// without CO-RE compilation dependencies
//
// Returns:
//   - *NetnsOffsets: Detected offsets in bytes
//   - error: If BTF unavailable or struct members not found
//
// Requirements:
//   - Kernel >= 5.5 with CONFIG_DEBUG_INFO_BTF=y
//   - /sys/kernel/btf/vmlinux must exist
func DetectNetnsOffsets(logger *zap.Logger) (*NetnsOffsets, error) {
	// Load kernel BTF specification
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel BTF: %w (kernel may not have CONFIG_DEBUG_INFO_BTF enabled)", err)
	}

	offsets := &NetnsOffsets{}

	// 1. Detect task_struct->nsproxy offset
	var taskStruct *btf.Struct
	if err := spec.TypeByName("task_struct", &taskStruct); err != nil {
		return nil, fmt.Errorf("task_struct type not found in BTF: %w", err)
	}

	found := false
	for _, member := range taskStruct.Members {
		if member.Name == "nsproxy" {
			offsets.TaskNsproxy = member.Offset.Bytes()
			found = true
			logger.Debug("Detected task_struct->nsproxy offset",
				zap.Uint32("offset_bytes", offsets.TaskNsproxy))
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("task_struct->nsproxy member not found in BTF")
	}

	// 2. Detect nsproxy->net_ns offset
	var nsproxyStruct *btf.Struct
	if err := spec.TypeByName("nsproxy", &nsproxyStruct); err != nil {
		return nil, fmt.Errorf("nsproxy type not found in BTF: %w", err)
	}

	found = false
	for _, member := range nsproxyStruct.Members {
		if member.Name == "net_ns" {
			offsets.NsproxyNetNs = member.Offset.Bytes()
			found = true
			logger.Debug("Detected nsproxy->net_ns offset",
				zap.Uint32("offset_bytes", offsets.NsproxyNetNs))
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("nsproxy->net_ns member not found in BTF")
	}

	// 3. Detect net->ns.inum offset (requires traversing net->ns->inum)
	var netStruct *btf.Struct
	if err := spec.TypeByName("net", &netStruct); err != nil {
		return nil, fmt.Errorf("net type not found in BTF: %w", err)
	}

	// Find net->ns member offset
	var nsOffset uint32
	found = false
	for _, member := range netStruct.Members {
		if member.Name == "ns" {
			nsOffset = member.Offset.Bytes()
			found = true
			logger.Debug("Detected net->ns offset",
				zap.Uint32("offset_bytes", nsOffset))
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("net->ns member not found in BTF")
	}

	// Find ns_common->inum offset within ns_common struct
	var nsCommonStruct *btf.Struct
	if err := spec.TypeByName("ns_common", &nsCommonStruct); err != nil {
		return nil, fmt.Errorf("ns_common type not found in BTF: %w", err)
	}

	found = false
	for _, member := range nsCommonStruct.Members {
		if member.Name == "inum" {
			inumOffset := member.Offset.Bytes()
			// Combined offset: net->ns + ns->inum
			offsets.NetNsInum = nsOffset + inumOffset
			found = true
			logger.Debug("Detected ns_common->inum offset",
				zap.Uint32("ns_offset", nsOffset),
				zap.Uint32("inum_offset", inumOffset),
				zap.Uint32("combined_offset", offsets.NetNsInum))
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("ns_common->inum member not found in BTF")
	}

	logger.Info("Successfully detected network namespace offsets",
		zap.Uint32("task_nsproxy", offsets.TaskNsproxy),
		zap.Uint32("nsproxy_net_ns", offsets.NsproxyNetNs),
		zap.Uint32("net_ns_inum", offsets.NetNsInum))

	return offsets, nil
}

// ValidateOffsets performs sanity checks on detected offsets
// Returns error if offsets are clearly invalid
func (o *NetnsOffsets) ValidateOffsets() error {
	// Offsets should be non-zero and reasonable (< 4096 bytes into struct)
	// task_struct is large but offsets shouldn't exceed a few KB
	const maxReasonableOffset = 4096

	if o.TaskNsproxy == 0 {
		return fmt.Errorf("task_nsproxy offset is zero")
	}
	if o.TaskNsproxy > maxReasonableOffset {
		return fmt.Errorf("task_nsproxy offset %d exceeds reasonable limit %d", o.TaskNsproxy, maxReasonableOffset)
	}

	if o.NsproxyNetNs == 0 {
		return fmt.Errorf("nsproxy_net_ns offset is zero")
	}
	if o.NsproxyNetNs > maxReasonableOffset {
		return fmt.Errorf("nsproxy_net_ns offset %d exceeds reasonable limit %d", o.NsproxyNetNs, maxReasonableOffset)
	}

	if o.NetNsInum == 0 {
		return fmt.Errorf("net_ns_inum offset is zero")
	}
	if o.NetNsInum > maxReasonableOffset {
		return fmt.Errorf("net_ns_inum offset %d exceeds reasonable limit %d", o.NetNsInum, maxReasonableOffset)
	}

	return nil
}

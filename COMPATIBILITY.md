# Kernel Compatibility

## Minimum Requirements

- **Kernel**: Linux 5.10+
- **Features**: IPv4 + IPv6 dual-stack support for tracking src-ip to dst-ip transferred bytes/packets

## Tested Kernels

| Kernel | Distribution | Status |
|--------|--------------|--------|
| 5.10 | LTS | ✅ |
| 5.15 | LTS | ✅ |
| 6.1 | LTS | ✅ |
| 6.6 | LTS | ✅ |
| bpf-next | Development | ✅ |
| RHEL 8.9 | Enterprise | ✅ |

## CI Testing

Kernel compatibility is automatically tested on every PR using [cilium/little-vm-helper](https://github.com/cilium/little-vm-helper). The eBPF program is loaded through the BPF verifier on each kernel version.

## BPF Features Used

| Feature | Min Kernel |
|---------|-----------|
| TC (Traffic Control) programs | 4.1 |
| `bpf_skb_load_bytes()` helper | 4.5 |
| Ringbuffer maps | 5.8 |

**Effective minimum: 5.10** (LTS with stable BPF support)

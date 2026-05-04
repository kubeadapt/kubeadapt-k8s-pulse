## Summary

<!-- Briefly describe what this PR does -->

## Related Issue

<!-- Link to the issue this PR addresses -->
Closes #

## Type of Change

<!-- Mark the relevant option with an [x] -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Refactoring (no functional changes)
- [ ] Documentation update
- [ ] CI/CD or build system change
- [ ] Performance improvement

## Changes Made

<!-- List the specific changes made in this PR -->

-
-
-

## Architecture Impact

<!-- If this PR affects the agent architecture, describe the impact -->
<!-- Reference: docs/ARCHITECTURE.md -->

- [ ] No architecture changes
- [ ] Kernel space (BPF/TC hooks) changes
- [ ] Userspace collector changes
- [ ] Prometheus metrics changes
- [ ] Configuration changes

## Kernel Compatibility

<!-- The agent supports kernels 5.10+ -->

- [ ] Tested on kernel 5.10.x
- [ ] Tested on kernel 5.15.x or newer
- [ ] No kernel-specific changes
- [ ] Requires kernel version guard (explain below)

## Checklist

<!-- Mark completed items with [x] -->

### Code Quality
- [ ] `make lint` passes (Go + C code)
- [ ] `make test` passes
- [ ] `make test-coverage` shows adequate coverage for new code
- [ ] Code follows project conventions

### BPF Changes (if applicable)
- [ ] `make generate` was run after modifying BPF code
- [ ] BPF verifier passes on supported kernels (5.10+)
- [ ] No unbounded loops or memory access
- [ ] Atomic operations used for concurrent map access

### Documentation
- [ ] Code comments added for complex logic
- [ ] README or docs updated (if needed)
- [ ] ARCHITECTURE.md updated (if architecture changed)

### Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass (`make test-integration-docker`)
- [ ] E2E tests pass (`make test-e2e`) - for significant changes

## Test Plan

<!-- Describe how you tested this change -->

1.
2.
3.

## Screenshots / Metrics Output

<!-- If applicable, add screenshots or metrics output showing the change -->

```
# Example metrics output if applicable
```

## Additional Notes

<!-- Any additional context for reviewers -->

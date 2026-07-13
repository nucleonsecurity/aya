#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{macros::fmod_ret, programs::FEntryContext};
#[cfg(not(test))]
extern crate ebpf_panic;

// Both programs attach to the kernel's `bpf_modify_return_test`, the fixed
// BPF_PROG_TEST_RUN target for BPF_MODIFY_RETURN. The tracing test-run handler
// calls `bpf_modify_return_test(1, &b)` (which does `*b += 1`) and reports
// whether that side effect happened. An fmod_ret program that returns non-zero
// short-circuits the target, so the side effect is suppressed; one that returns
// zero lets the target run normally. Comparing the two isolates the return-value
// replacement behaviour without depending on exact kernel arithmetic.
// https://github.com/torvalds/linux/blob/v7.1-rc4/net/bpf/test_run.c#L716-L732

/// Lets the target run: returning zero does not modify its return value.
#[fmod_ret(function = "bpf_modify_return_test")]
fn test_fmod_ret_allow(_ctx: FEntryContext) -> i32 {
    0
}

/// Overrides the target: returning non-zero replaces its return value and
/// short-circuits it, so its `*b += 1` side effect never happens.
#[fmod_ret(function = "bpf_modify_return_test")]
fn test_fmod_ret_override(_ctx: FEntryContext) -> i32 {
    // Arbitrary non-zero sentinel; any non-zero value triggers the override.
    42
}

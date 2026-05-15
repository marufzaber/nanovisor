#!/usr/bin/env bash
# Copyright (c) 2026 Maruf Zaber
# SPDX-License-Identifier: MIT
#
# Integration tests for nanovisor.
#
# Each test exercises one path through the syscall dispatch loop by
# selecting a different built-in guest program (see kPrograms[] in
# hyp.cpp) and asserting on the binary's stdout + exit code. The
# programs are deliberately small enough that any assertion failure
# points unambiguously at a single bug.
#
# Why a shell harness instead of a C++ test binary: the dispatch loop
# is what we want to cover, and we want to cover the dispatch loop that
# ships with the binary — not a copy of it. Subprocess + stdout/exit
# checks is the simplest way to do that without dragging the loop out
# into a separately-linked library.
#
# The expected exit codes for the error tests use the host's errno
# values (POSIX truncates to 8 bits): on macOS, EFAULT=14 and ENOSYS=78,
# so the guest's `exit(-errno)` becomes host exit 256-errno.

set -u

HYP="${HYP:-./hyp}"

if [[ ! -x "$HYP" ]]; then
    echo "error: $HYP not found or not executable (run 'make' first)" >&2
    exit 2
fi

pass=0
fail=0

run_test() {
    local name="$1"
    local expected_stdout="$2"
    local expected_exit="$3"

    local actual_stdout actual_exit
    actual_stdout="$("$HYP" "$name" 2>/dev/null)"
    actual_exit=$?

    if [[ "$actual_stdout" != "$expected_stdout" ]]; then
        printf 'FAIL %-8s stdout: got %q, want %q\n' \
            "$name" "$actual_stdout" "$expected_stdout"
        fail=$((fail+1))
        return
    fi
    if [[ "$actual_exit" -ne "$expected_exit" ]]; then
        printf 'FAIL %-8s exit:   got %d, want %d\n' \
            "$name" "$actual_exit" "$expected_exit"
        fail=$((fail+1))
        return
    fi
    printf 'ok   %-8s\n' "$name"
    pass=$((pass+1))
}

# Happy path: write(1, "hi\n", 3); exit(0).
run_test hi     "hi" 0

# SYS_exit propagates the status into the host process exit code.
run_test exit42 ""   42

# SYS_write rejects an out-of-bounds buffer with -EFAULT; guest
# forwards that value to SYS_exit.
run_test efault ""   $((256 - 14))   # EFAULT

# Unknown syscall numbers return -ENOSYS via the default switch arm.
run_test enosys ""   $((256 - 78))   # ENOSYS

# Unrecognized program-name argument must exit 2 with a clear message.
unknown_stdout="$("$HYP" definitely-not-a-program 2>/dev/null)"
unknown_exit=$?
if [[ -z "$unknown_stdout" && "$unknown_exit" -eq 2 ]]; then
    printf 'ok   %-8s\n' "argv"
    pass=$((pass+1))
else
    printf 'FAIL %-8s stdout=%q exit=%d (want empty stdout, exit 2)\n' \
        "argv" "$unknown_stdout" "$unknown_exit"
    fail=$((fail+1))
fi

echo
if [[ $fail -eq 0 ]]; then
    echo "all $pass tests passed"
    exit 0
else
    echo "$fail of $((pass+fail)) tests failed"
    exit 1
fi

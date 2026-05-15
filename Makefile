# Copyright (c) 2026 Maruf Zaber
# SPDX-License-Identifier: MIT
#
# Build the hypervisor and ad-hoc codesign it with the
# com.apple.security.hypervisor entitlement. Without that entitlement,
# hv_vm_create() returns HV_DENIED at runtime.

CXX      := clang++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDFLAGS  := -framework Hypervisor

hyp: hyp.cpp hyp.entitlements
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ hyp.cpp
	codesign --entitlements hyp.entitlements --force --sign - $@

run: hyp
	./hyp

test: hyp
	./tests.sh

clean:
	rm -f hyp

.PHONY: run test clean

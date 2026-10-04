package main

// คำสั่งนี้ทำให้เราสามารถสั่ง compile eBPF C program และ generate Go bindings ได้ง่ายๆ ด้วยคำสั่ง `go generate`
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type tcp_event -go-package main bpf bpf/tcp_monitor.bpf.c -- -I./bpf -O2 -g -Wno-missing-declarations

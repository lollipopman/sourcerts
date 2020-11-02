package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
#include <uapi/linux/ptrace.h>
#include <partial_x509.h>

struct event_t {
        u32 pid;
        char str[80];
} __attribute__((packed));

BPF_PERF_OUTPUT(sourcerts_events);

int get_return_value(struct pt_regs *ctx) {
        struct event_t event = {};
        u32 pid;
				X509 *certptr;
				X509 cert;
				X509_VAL validity;
				ASN1_TIME *asn1_timeptr;
				ASN1_TIME asn1_time;
        if (!PT_REGS_RC(ctx))
                return 0;
        pid = bpf_get_current_pid_tgid();
        event.pid = pid;
        bpf_probe_read(&cert, sizeof(cert), (void *)PT_REGS_RC(ctx));
				validity = cert.cert_info.validity;
				asn1_timeptr = validity.notAfter;
        bpf_probe_read(&asn1_time, sizeof(asn1_time), (void *)asn1_timeptr);
        bpf_probe_read_str(&event.str, 80, (void *)asn1_time.data);
        sourcerts_events.perf_submit(ctx, &event, sizeof(event));
        return 0;
}
`

type sourcertsEvent struct {
	Pid uint32
	Str [80]byte
}

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	include, err := filepath.Abs(filepath.Join(pwd, "include"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	m := bpf.NewModule(source, []string{"-I", include})
	defer m.Close()

	sourcertsUretprobe, err := m.LoadUprobe("get_return_value")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load get_return_value: %s\n", err)
		os.Exit(1)
	}

	// This only attachs to the ssl library in the current filesystem based on
	// the ldconfig? How would we query for all OpenSSL libraries across all
	// containers?  Perhaps just using `find` would suffice?
	err = m.AttachUretprobe("ssl", "SSL_get_peer_certificate", sourcertsUretprobe, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach return_value: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("sourcerts_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Printf("%10s\t%s\n", "pid", "notAfter")
	go func() {
		var event sourcertsEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			// Convert C string (null-terminated) to Go string
			notAfterStr := string(event.Str[:bytes.IndexByte(event.Str[:], 0)])
			notAfter, err := time.Parse("060102150405Z", notAfterStr)
			if err != nil {
				fmt.Printf("failed to parse time data '%s': %s\n", notAfterStr, err)
				continue
			}
			fmt.Printf("%10d\t%s\n", event.Pid, notAfter)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/markbates/pkger"

	bpf "github.com/iovisor/gobpf/bcc"
)

func init() {
	pkger.Include("/sourcerts.bpf")
}

func load(filename string) (string, error) {
	f, err := pkger.Open(filename)
	if err != nil {
		return "", err
	}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

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
	source, err := load("/sourcerts.bpf")
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

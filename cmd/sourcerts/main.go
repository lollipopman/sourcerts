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

const X509_NAME_SIZE = 512

func init() {
	pkger.Include("/sourcerts.bpf.c")
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
	Pid       uint32
	NotBefore [14]byte
	NotAfter  [14]byte
	Subject   [X509_NAME_SIZE]byte
	Issuer    [X509_NAME_SIZE]byte
}

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	include, err := filepath.Abs(filepath.Join(pwd, "include/openssl"))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	source, err := load("/sourcerts.bpf.c")
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

	fmt.Printf("Probing\n")
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
			fmt.Printf("Pid: %d\n", event.Pid)
			notBeforeStr := string(event.NotBefore[:bytes.IndexByte(event.NotBefore[:], 0)])
			notBefore, err := time.Parse("060102150405Z", notBeforeStr)
			if err != nil {
				fmt.Printf("failed to parse time data '%s': %s\n", notBeforeStr, err)
				continue
			}
			fmt.Printf("\tnotBefore:\t%s\n", notBefore)
			notAfterStr := string(event.NotAfter[:bytes.IndexByte(event.NotAfter[:], 0)])
			notAfter, err := time.Parse("060102150405Z", notAfterStr)
			if err != nil {
				fmt.Printf("failed to parse time data '%s': %s\n", notAfterStr, err)
				continue
			}
			fmt.Printf("\tnotAfter:\t%s\n", notAfter)
			SubjectStr := string(event.Subject[:bytes.IndexByte(event.Subject[:], 0)])
			fmt.Printf("\tSubject:\t%s\n", SubjectStr)
			IssuerStr := string(event.Issuer[:bytes.IndexByte(event.Issuer[:], 0)])
			fmt.Printf("\tIssuer:\t\t%s\n", IssuerStr)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}

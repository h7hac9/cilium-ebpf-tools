package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf bash_readline.c -- -I../../headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalln(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalln(fmt.Sprintf("loading objects: %s", err))
	}
	defer objs.Close()

	ex, err := link.OpenExecutable("/bin/bash")
	if err != nil {
		log.Fatalln(fmt.Sprintf("opening executable: %s", err))
	}

	up, err := ex.Uretprobe("readline", objs.UretprobeBashReadline, nil)
	if err != nil {
		log.Fatalln(fmt.Sprintf("create uretprobe: %s", err))
	}
	defer up.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	log.Printf("Listening for events..")

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		log.Printf("[Bash 命令执行监控] Pid:%d | Uid:%d | Command:%s", event.Pid, event.Uid, unix.ByteSliceToString(event.Command[:]))
	}
}

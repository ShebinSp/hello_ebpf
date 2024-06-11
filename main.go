package main

import (
	"C"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)
import (
	"bytes"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf hello_ebpf.c

// Define the event structure to match the eBPF program
type event struct {
	Pid  uint32
	Comm [100]byte
}

func main() {
	kprobeFunc := "__x64_sys_execve"
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := ebpfObjects{}

	if err := loadEbpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v\n", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(kprobeFunc, objs.HelloExecve, nil)
	if err != nil {
		log.Fatalf("Opening kprobe: %s\n", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf reader: %s\n", err)
	}
	defer rd.Close()

	/*
	   The first line is a Go compiler directive, go:generate. Here we say to the Go compiler to run the bpf2go tool from
	   the github.com/cilium/ebpf/cmd/bpf2go package, and generate a Go file from the hello_ebpf.c file.

	   	   	The generated Go files will include the Go representation of the eBPF program, the types and structs we have
	   defined in the eBPF program, etc. We then will use these representations inside our Go code to load the eBPF program
	   into the kernel, and to interact with the BPF map.

	   	   	We then use the generated types to load the eBPF program (`loadEbpfObjects`), attach to the kprobe hook
	   (`link.Kprobe`), and read the events from the BPF map (`ringbuf.NewReader`). All of these functions use the generated types.

	   It's time to interact with the kernel side:
	*/

	go func() {
		<-stopper
		log.Println("Received signal, closing ring buffer...")
		if err := rd.Close(); err != nil {
			log.Fatalf("Closing ringbuf reader: %s\n", err)
		}
	}()

	log.Println("Waiting for events...")

	var evnt event

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Printf("reading from buffer: %v\n", err)
			break
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evnt); err != nil {
			fmt.Printf("parsing ringbuf event: %s", err)
			continue
		}
		procName := string(evnt.Comm[:])

		log.Printf("pid: %d \t command: %s\n", evnt.Pid, procName)
	}
}

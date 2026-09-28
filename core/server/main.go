package main

import (
	"ThroneCore/internal/boxmain"
	"ThroneCore/internal/process"
	"ThroneCore/ipc"
	"ThroneCore/parentcheck"
	"errors"
	"fmt"
	"github.com/xtls/xray-core/core"
	"log"
	"net"
	"os"
	"runtime"
	runtimeDebug "runtime/debug"
	"runtime/metrics"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	_ "ThroneCore/internal/distro/all"
	C "github.com/sagernet/sing-box/constant"
)

const (
	// memoryPanicThreshold stays under memoryLimit: that much live under the soft limit means the GC is thrashing.
	memoryLimit           = 2 * 1024 * 1024 * 1024
	memoryPanicThreshold  = 1536 * 1024 * 1024
	memoryCheckInterval   = 2 * time.Second
	memoryForcedGCBackoff = 30 * time.Second
)

// Not HeapAlloc: it counts unswept garbage and sawtooths up to the GC target, so a bare threshold on it fires on a healthy heap.
func liveHeap() uint64 {
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}}
	metrics.Read(sample)
	return sample[0].Value.Uint64()
}

func watchMemory() {
	for {
		time.Sleep(memoryCheckInterval)

		if liveHeap() < memoryPanicThreshold {
			continue
		}

		// The metric is only as fresh as the last cycle, which during a burst can mark short-lived objects live.
		runtimeDebug.FreeOSMemory()
		live := liveHeap()
		if live < memoryPanicThreshold {
			// FreeOSMemory is stop-the-world; do not repeat it every tick while a busy core sits near the threshold.
			time.Sleep(memoryForcedGCBackoff)
			continue
		}

		log.Printf("memory watchdog: %d MiB live after a forced GC, %d goroutines",
			live>>20, runtime.NumGoroutine())
		if path, err := writeHeapProfile(); err != nil {
			log.Printf("memory watchdog: could not write heap profile: %v", err)
		} else {
			log.Printf("memory watchdog: heap profile written to %s", path)
		}
		panic(fmt.Sprintf("Live heap reached %d MiB after a forced GC, this is not normal", live>>20))
	}
}

func writeHeapProfile() (string, error) {
	// Core runs privileged: a guessable clock-derived name lets a planted symlink turn this into a root-owned write anywhere.
	f, err := os.CreateTemp("", "throne-core-heap-*.pprof")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err = pprof.WriteHeapProfile(f); err != nil {
		return "", err
	}
	return f.Name(), f.Sync()
}

// Set by desktop/scripts/build_core.py from desktop/package.json.
var appVersion string

// Stop may wait for a pending Start, a TUN release and an external core's
// cleanup; beyond this the core leaves without it.
const parentCleanupLimit = 15 * time.Second

var (
	coreConnMu sync.Mutex
	coreConn   net.Conn
)

// parentExited ends the core the way a closed channel does: dispatch sees EOF,
// drains pending requests and runs Stop, which restores DNS and ends child
// processes, and RunCore returns. exit runs only when there is no channel yet
// or that teardown outlasts limit. Before, the core exited at once, and on
// Windows its watcher always beat the EOF, so nothing was ever restored.
func parentExited(reason any, limit time.Duration, exit func()) {
	log.Println("parent exited:", reason)
	coreConnMu.Lock()
	conn := coreConn
	coreConnMu.Unlock()
	if conn == nil {
		exit()
		return
	}
	_ = conn.Close()
	time.Sleep(limit)
	log.Println("parent exited: cleanup did not finish in time")
	exit()
}

func RunCore() {
	socketName := os.Getenv("THRONE_CORE_SOCKET")
	if socketName == "" {
		log.Fatal("THRONE_CORE_SOCKET not set")
	}
	debug = os.Getenv("THRONE_CORE_DEBUG") == "1"

	parentcheck.CheckParentProcess()

	go func() {
		parent, err := os.FindProcess(parentcheck.ParentPID)
		if err != nil {
			log.Fatalln("find parent:", err)
		}
		if runtime.GOOS == "windows" {
			state, err := parent.Wait()
			parentExited(fmt.Sprint(state, " ", err), parentCleanupLimit, func() { os.Exit(1) })
		} else {
			for {
				time.Sleep(time.Second * 10)
				err = parent.Signal(syscall.Signal(0))
				if err != nil && !errors.Is(err, syscall.EPERM) {
					parentExited(err, parentCleanupLimit, func() { os.Exit(1) })
				}
			}
		}
	}()

	boxmain.DisableColor()

	var conn net.Conn
	var err error
	for i := 0; i < 10; i++ {
		conn, err = ipc.ConnectIPC(socketName, parentcheck.ParentPID)
		if err == nil {
			break
		}
		log.Printf("IPC connect attempt %d/10 failed: %v", i+1, err)
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		log.Fatalf("failed to connect to GUI socket after 10 attempts: %v", err)
	}

	coreConnMu.Lock()
	coreConn = conn
	coreConnMu.Unlock()
	fmt.Println("Core Has Successfully Connected to Throne!")
	verifyManagedParent(conn)
	runDispatch(conn)
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			// The exit code is all the GUI has to tell a panic from a clean stop.
			fmt.Fprintf(os.Stderr, "Core panicked: %v\n%s\n", err, runtimeDebug.Stack())
			os.Exit(2)
		}
	}()
	// Answered before any parent check: the application asks it of the file
	// it is about to run.
	if len(os.Args) == 2 && os.Args[1] == "--thronium-core-info" {
		if err := writeCoreInfo(os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}
	if process.GuardianMain() {
		return
	}
	if managedMain() {
		return
	}
	if appVersion != "" {
		fmt.Println("Thronium:", appVersion)
	}
	fmt.Println("sing-box:", C.Version)
	fmt.Println("Xray-core:", core.Version())
	fmt.Println()
	runtimeDebug.SetMemoryLimit(memoryLimit)
	go watchMemory()

	RunCore()
	return
}

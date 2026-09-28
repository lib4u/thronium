//go:build windows

package winservice

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

// As a worker fixture the test binary answers every request with its method
// name, and "Exit" by exiting.
func TestMain(m *testing.M) {
	if name := os.Getenv("THRONE_CORE_SOCKET"); name != "" && len(os.Args) > 1 && os.Args[len(os.Args)-1] == "--thronium-tun-worker" {
		timeout := 5 * time.Second
		conn, err := winio.DialPipe(name, &timeout)
		if err != nil {
			os.Exit(3)
		}
		for {
			f, err := readRequest(conn)
			if err != nil {
				os.Exit(0)
			}
			if f.method == "Exit" {
				os.Exit(4)
			}
			if f.method == "Hang" {
				time.Sleep(time.Hour)
			}
			_, _ = conn.Write(encodeResponse(response{f.id, 0, []byte(f.method)}))
		}
	}
	os.Exit(m.Run())
}

// Wine never completes go-winio's Accept, even within one process.
func underWine() bool {
	return windows.NewLazySystemDLL("ntdll.dll").NewProc("wine_get_version").Find() == nil
}

func ownPipeSecurity(t *testing.T) {
	if underWine() {
		t.Skip("Wine does not complete a pipe server's Accept")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	previous := workerPipeSecurity
	workerPipeSecurity = "D:P(A;;GA;;;" + user.User.Sid.String() + ")"
	t.Cleanup(func() { workerPipeSecurity = previous })
}

func launch(t *testing.T) *windowsWorker {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	w, err := startWorker(self, t.TempDir()+`\worker`, os.Stderr, make(chan struct{}))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWorkerIsTheProcessStartedInItsJobAndAnswersInOrder(t *testing.T) {
	ownPipeSecurity(t)
	w := launch(t)
	pid, created := w.identity()
	if pid == 0 || created == 0 || processCreated(pid) != created {
		t.Fatal(pid, created)
	}
	frame, err := w.exchange(request{7, "QueryStats", nil}, 5*time.Second)
	if err != nil || !bytes.Equal(frame, encodeResponse(response{7, 0, []byte("QueryStats")})) {
		t.Fatal(frame, err)
	}
	w.close()
	select {
	case <-w.exited():
	default:
		t.Fatal("worker survived close")
	}
	if processCreated(pid) == created {
		t.Fatal("worker process still exists")
	}
}

func TestAHungWorkerIsEndedByItsJob(t *testing.T) {
	ownPipeSecurity(t)
	w := launch(t)
	if _, err := w.exchange(request{1, "Hang", nil}, 200*time.Millisecond); err == nil {
		t.Fatal("hung worker answered")
	}
	start := time.Now()
	w.close()
	select {
	case <-w.exited():
	default:
		t.Fatal("hung worker survived close")
	}
	if time.Since(start) > 15*time.Second {
		t.Fatal("close took", time.Since(start))
	}
}

func TestAWorkerThatExitsIsReported(t *testing.T) {
	ownPipeSecurity(t)
	w := launch(t)
	defer w.close()
	_, _ = w.exchange(request{1, "Exit", nil}, time.Second)
	select {
	case <-w.exited():
	case <-time.After(5 * time.Second):
		t.Fatal("exit not reported")
	}
}

func TestLeftoverWorkerIsEndedOnlyWhenItIsTheJournaledProcess(t *testing.T) {
	ownPipeSecurity(t)
	w := launch(t)
	defer w.close()
	pid, created := w.identity()
	terminateLeftover(pid, created+1)
	select {
	case <-w.exited():
		t.Fatal("another process was ended")
	case <-time.After(300 * time.Millisecond):
	}
	terminateLeftover(pid, created)
	select {
	case <-w.exited():
	case <-time.After(5 * time.Second):
		t.Fatal("journaled worker survived")
	}
}

// A test binary carries no signature, so a service built like it checks the
// client's path alone.
func TestAnUnsignedExecutableHasNoPublisher(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if name, err := publisher(self); err == nil {
		t.Fatal("unsigned test binary reported publisher", name)
	}
}

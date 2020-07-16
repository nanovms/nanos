package runner

import (
	"bufio"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"testing"

	"github.com/nanovms/ops/lepton"
)

func defaultConfig() lepton.Config {
	var c lepton.Config

	c.Boot = "../../output/test/go/boot.img"
	c.Kernel = "../../output/test/go/kernel.img"
	c.Mkfs = "../../output/tools/bin/mkfs"
	c.NameServer = "8.8.8.8"

	c.Env = make(map[string]string)
	c.TargetRoot = os.Getenv("NANOS_TARGET_ROOT")
	return c
}

type runeSorter []rune

func (s runeSorter) Less(i, j int) bool {
	return s[i] < s[j]
}

func (s runeSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s runeSorter) Len() int {
	return len(s)
}

func sortString(s string) string {
	r := []rune(s)
	sort.Sort(runeSorter(r))
	return string(r)
}

const START_WAIT_TIMEOUT = time.Second * 30

func runAndWaitForString(rconfig *lepton.RunConfig, timeout time.Duration, text string, t *testing.T) lepton.Hypervisor {
	hypervisor := lepton.HypervisorInstance()
	if hypervisor == nil {
		t.Fatal("No hypervisor found on $PATH")
	}
	cmd := hypervisor.Command(rconfig)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	reader := io.TeeReader(stdoutPipe, os.Stdout)
	cmd.Stderr = os.Stderr
	cmd.Start()

	done := make(chan struct{})
	errch := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), text) {
				done <- struct{}{}
			}
		}
		if err := scanner.Err(); err != nil {
			errch <- err
		}
		errch <- errors.New("Expected text not found")
	}()

	select {
	case <-time.After(timeout):
		hypervisor.Stop()
		t.Fatal("Timed out")
	case err := <-errch:
		hypervisor.Stop()
		t.Fatal(err)
	case <-done:
		break
	}
	return hypervisor
}

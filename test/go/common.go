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

	c.Boot = "../../output/boot/boot.img"
	c.Kernel = "../../output/stage3/bin/stage3.img"
	c.Mkfs = "../../output/mkfs/bin/mkfs"
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

const START_WAIT_TIMEOUT = time.Second * 10

func runAndWaitForString(rconfig *lepton.RunConfig, timeout time.Duration, text string, t *testing.T) lepton.Hypervisor {
	hypervisor := lepton.HypervisorInstance()
	if hypervisor == nil {
		t.Error("No hypervisor found on $PATH")
		t.FailNow()
	}
	cmd := hypervisor.Command(rconfig)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Error(err)
		t.FailNow()
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
		t.Error("Timed out")
		t.FailNow()
	case err := <-errch:
		hypervisor.Stop()
		t.Error(err)
		t.FailNow()
	case <-done:
		break
	}
	return hypervisor
}

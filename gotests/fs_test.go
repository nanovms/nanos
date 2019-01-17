package runner

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nanovms/ops/lepton"
)

func defaultConfig() lepton.Config {
	var c lepton.Config
	c.Boot = "../output/boot/boot.img"
	c.Kernel = "../output/stage3/stage3.img"
	c.Mkfs = "../output/mkfs/bin/mkfs"
	c.Env = make(map[string]string)
	return c
}

func writeFile(path string) {
	var file, _ = os.Create(path)
	defer file.Close()
	file.WriteString("inside the file")
	file.Sync()
}

func prepareTestImage(finalImage string) {
	const filepath = "../examples/soop.data"
	c := defaultConfig()
	writeFile(filepath)

	c.Files = append(c.Files, "/lib/x86_64-linux-gnu/libnss_dns.so.2")
	c.Files = append(c.Files, "/etc/ssl/certs/ca-certificates.crt")
	c.Files = append(c.Files, filepath)

	c.Args = append(c.Args, "longargument")

	c.Env["USER"] = "bobby"
	c.Env["PWD"] = "password"

	c.DiskImage = finalImage
	c.Program = "../output/examples/webg"

	err := lepton.BuildImage(c)
	if err != nil {
		log.Fatal(err)
	}
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

func TestArgsAndEnv(t *testing.T) {
	const finalImage = "image"
	prepareTestImage(finalImage)
	hypervisor := lepton.HypervisorInstance()
	rconfig := lepton.RuntimeConfig(finalImage, []int{8080}, true)
	go func() {
		hypervisor.Start(&rconfig)
	}()
	time.Sleep(3 * time.Second)
	resp, err := http.Get("http://127.0.0.1:8080/args")
	if err != nil {
		t.Log(err)
		t.Errorf("failed to get 127.0.0.1:8080/args")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Log(err)
		t.Errorf("ReadAll failed")
	}
	if string(body) != "longargument" {
		t.Errorf("unexpected response:" + string(body))
	}
	resp.Body.Close()

	resp, err = http.Get("http://127.0.0.1:8080/env")
	if err != nil {
		t.Log(err)
		t.Errorf("failed to get 127.0.0.1:8080/env")
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Log(err)
		t.Errorf("ReadAll failed")
	}

	if sortString(string(body)) !=
		sortString("USER=bobbyPWD=password") {
		t.Errorf("unexpected response" + string(body))
	}
	hypervisor.Stop()
}

func TestFileSystem(t *testing.T) {
	const finalImage = "image"
	prepareTestImage(finalImage)
	hypervisor := lepton.HypervisorInstance()
	rconfig := lepton.RuntimeConfig(finalImage, []int{8080}, true)
	go func() {
		hypervisor.Start(&rconfig)
	}()
	time.Sleep(3 * time.Second)
	resp, err := http.Get("http://127.0.0.1:8080")
	if err != nil {
		t.Log(err)
		t.Errorf("failed to get 127.0.0.1:8080")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Log(err)
		t.Errorf("ReadAll failed")
	}
	if string(body) != "unibooty 0" {
		t.Errorf("unexpected response" + string(body))
	}
	hypervisor.Stop()
}

func TestHTTP(t *testing.T) {
	const finalImage = "image"
	prepareTestImage(finalImage)
	hypervisor := lepton.HypervisorInstance()
	rconfig := lepton.RuntimeConfig(finalImage, []int{8080}, true)
	go func() {
		hypervisor.Start(&rconfig)
	}()

	time.Sleep(3 * time.Second)

	resp, err := http.Get("http://127.0.0.1:8080/req")
	if err != nil {
		t.Log(err)
		t.Errorf("failed to get 127.0.0.1:8080/req")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Log(err)
		t.Errorf("ReadAll failed")
	}

	if !strings.Contains(string(body), "unikernel compilation") {
		t.Errorf("unexpected response:" + string(body))
	}
	resp.Body.Close()

	hypervisor.Stop()
}

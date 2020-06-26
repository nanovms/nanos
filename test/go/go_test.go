package runner

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nanovms/ops/lepton"
)

func writeFile(path string) {
	var file, _ = os.Create(path)
	defer file.Close()
	file.WriteString("inside the file")
	file.Sync()
}

func prepareTestImage(finalImage string) {
	const filepath = "../runtime/soop.data"
	c := defaultConfig()
	writeFile(filepath)

	c.Files = append(c.Files, "/lib/x86_64-linux-gnu/libnss_dns.so.2")
	c.Files = append(c.Files, "/etc/ssl/certs/ca-certificates.crt")
	c.Files = append(c.Files, filepath)

	c.Args = append(c.Args, "longargument")

	c.Env["USER"] = "bobby"
	c.Env["PWD"] = "password"

	c.RunConfig.Imagename = finalImage
	c.Program = "../../output/test/runtime/bin/webg"

	err := lepton.BuildImage(c)
	if err != nil {
		log.Fatal(err)
	}
}

func TestArgsAndEnv(t *testing.T) {
	const finalImage = "image"
	prepareTestImage(finalImage)
	rconfig := lepton.RuntimeConfig(finalImage, []int{8080}, true)
	hypervisor := runAndWaitForString(&rconfig, START_WAIT_TIMEOUT, "Server started", t)
	defer hypervisor.Stop()

	resp, err := http.Get("http://127.0.0.1:8080/args")
	if err != nil {
		t.Fatal("failed to get 127.0.0.1:8080/args")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("ReadAll failed")
	}
	if string(body) != "longargument" {
		t.Error("unexpected response:" + string(body))
	}

	resp, err = http.Get("http://127.0.0.1:8080/env")
	if err != nil {
		t.Fatal("failed to get 127.0.0.1:8080/env")
	}
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("ReadAll failed")
	}

	if sortString(string(body)) !=
		sortString("USER=bobbyPWD=password") {
		t.Error("unexpected response" + string(body))
	}
}

func TestFileSystem(t *testing.T) {
	const finalImage = "image"
	prepareTestImage(finalImage)
	rconfig := lepton.RuntimeConfig(finalImage, []int{8080}, true)
	hypervisor := runAndWaitForString(&rconfig, START_WAIT_TIMEOUT, "Server started", t)
	defer hypervisor.Stop()

	resp, err := http.Get("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal("failed to get 127.0.0.1:8080")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("ReadAll failed")
	}
	if string(body) != "unibooty 0" {
		t.Error("unexpected response" + string(body))
	}
}

func validateResponse(t *testing.T, finalImage string, expected string) {
	rconfig := lepton.RuntimeConfig(finalImage, []int{8080}, true)
	hypervisor := runAndWaitForString(&rconfig, START_WAIT_TIMEOUT, "Server started", t)
	defer hypervisor.Stop()

	resp, err := http.Get("http://127.0.0.1:8080/file")
	if err != nil {
		t.Fatal("failed to get 127.0.0.1:8080/file")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("ReadAll failed")
	}
	if string(body) != expected {
		t.Error("unexpected response" + string(body))
	}
	time.Sleep(time.Second * 3) // pause for fs flush - should make a request which exits server
}

func TestInstancePersistence(t *testing.T) {
	const finalImage = "instance.img"
	prepareTestImage(finalImage)
	validateResponse(t, finalImage, "something")
	validateResponse(t, finalImage, "somethingsomething")
}

func TestHTTP(t *testing.T) {
	const finalImage = "image"
	prepareTestImage(finalImage)
	rconfig := lepton.RuntimeConfig(finalImage, []int{8080}, true)
	hypervisor := runAndWaitForString(&rconfig, START_WAIT_TIMEOUT, "Server started", t)
	defer hypervisor.Stop()

	resp, err := http.Get("http://127.0.0.1:8080/req")
	if err != nil {
		t.Fatal("failed to get 127.0.0.1:8080/req")
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("ReadAll failed")
	}

	if !strings.Contains(string(body), "unikernel compilation") {
		t.Error("unexpected response:", string(body))
	}
}

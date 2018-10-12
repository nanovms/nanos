package runner

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/nanovms/nvm/lepton"
)

func defaultConfig() lepton.Config {
	var c lepton.Config
	c.Boot = "../boot/boot"
	c.Kernel = "../stage3/stage3"
	c.Mkfs = "../mkfs/mkfs"
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
	c.Files = append(c.Files, filepath)
	err := lepton.BuildImage("../examples/webs", finalImage, c)
	if err != nil {
		log.Fatal(err)
	}
}

func TestFileSystem(t *testing.T) {
	const finalImage = "image"
	prepareTestImage(finalImage)
	hypervisor := lepton.HypervisorInstance()
	go func() {
		hypervisor.Start(finalImage, 8080)
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
	if string(body) != "unibooty!" {
		t.Errorf("unexpected response" + string(body))
	}
	hypervisor.Stop()
}

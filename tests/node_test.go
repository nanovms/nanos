package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	api "github.com/nanovms/ops/lepton"
)

func unWarpConfig(file string) *api.Config {
	var c api.Config
	if file != "" {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(data, &c)
		if err != nil {
			panic(err)
		}
	}
	return &c
}

func TestNodeHelloWorld(t *testing.T) {

	const packageName = "node_v11.15.0"
	localpackage := api.DownloadPackage(packageName)
	fmt.Printf("Extracting %s...\n", localpackage)
	api.ExtractPackage(localpackage, ".staging")
	// load the package manifest
	manifest := path.Join(".staging", packageName, "package.manifest")
	if _, err := os.Stat(manifest); err != nil {
		panic(err)
	}

	c := unWarpConfig(manifest)
	c.Args = append(c.Args, "js/hello.js")
	c.RunConfig.Imagename = api.FinalImg
	c.RunConfig.Memory = "2G"
	c.Boot = "../output/boot/boot.img"
	c.Kernel = "../output/stage3/stage3.img"
	c.Mkfs = "../output/mkfs/bin/mkfs"
	c.Env = make(map[string]string)

	if err := api.BuildImageFromPackage(path.Join(".staging", packageName), *c); err != nil {
		t.Error(err)
	}

	hypervisor := api.HypervisorInstance()
	if hypervisor == nil {
		t.Error("No hypervisor found on $PATH")
	}

	cmd := hypervisor.Command(&c.RunConfig)
	waitForRegex(cmd, "hello from nodejs", t)
}

func waitForRegex(cmd *exec.Cmd, text string, t *testing.T) error {

	reader, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	done := make(chan struct{})
	scanner := bufio.NewScanner(reader)

	go func() {
		for scanner.Scan() {
			ptext := scanner.Text()
			fmt.Println(ptext)
			if ptext == text {
				done <- struct{}{}
				return
			}
		}
		t.Errorf("Expected text '%s' not found", text)
		done <- struct{}{}
	}()

	err = cmd.Start()
	if err != nil {
		return err
	}
	<-done

	var timer *time.Timer
	timer = time.AfterFunc(3*time.Second, func() {
		cmd.Process.Kill()
	})

	err = cmd.Wait()
	if err != nil {
		return err
	}

	timer.Stop()
	cmd.Process.Kill()
	return nil
}

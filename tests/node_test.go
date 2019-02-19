package runner

import (
	"bufio"
	"encoding/json"
	"errors"
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
	staging := ".staging"
	api.ExtractPackage(localpackage, staging)
	// load the package manifest
	manifest := path.Join(staging, packageName, "package.manifest")
	if _, err := os.Stat(manifest); err != nil {
		panic(err)
	}

	c := unWarpConfig(manifest)
	c.Args = append(c.Args, "js/hello.js")
	c.RunConfig.Imagename = "image"
	c.RunConfig.Memory = "2G"
	c.Boot = "../output/boot/boot.img"
	c.Kernel = "../output/stage3/stage3.img"
	c.Mkfs = "../output/mkfs/bin/mkfs"
	c.Env = make(map[string]string)
	c.DiskImage = "image"

	if err := api.BuildImageFromPackage(path.Join(staging, packageName), *c); err != nil {
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
	errch := make(chan error, 1)

	err = cmd.Start()
	if err != nil {
		return err
	}

	go func() {
		errch <- cmd.Wait()
	}()

	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			ptext := scanner.Text()
			fmt.Println(ptext)
			if ptext == text {
				done <- struct{}{}
				return
			}
		}
		errch <- errors.New("Expected text not found")
	}()

	select {

	case <-time.After(time.Second * 3):
		cmd.Process.Kill()
	case err := <-errch:
		if err != nil {
			return err
		}
	case <-done:
		cmd.Process.Kill()
		return nil
	}
	return nil
}

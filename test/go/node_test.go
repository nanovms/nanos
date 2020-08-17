package runner

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"testing"

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

	const packageName = "node_v11.5.0"
	localpackage, err := api.DownloadPackage(packageName)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Extracting %s...\n", localpackage)
	staging := ".staging"

	os.MkdirAll(staging, 0755)
	cpCmd := exec.Command("cp", "-rf", localpackage, staging)
	err = cpCmd.Run()
	if err != nil {
		t.Fatal(err)
	}

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
	c.Boot = "../../output/test/go/boot.img"
	c.Kernel = "../../output/test/go/kernel.img"
	c.Mkfs = "../../output/tools/bin/mkfs"
	c.Env = make(map[string]string)
	c.RunConfig.Imagename = "image"

	if err := api.BuildImageFromPackage(path.Join(staging, packageName), *c); err != nil {
		t.Error(err)
	}

	hypervisor := runAndWaitForString(&c.RunConfig, START_WAIT_TIMEOUT, "hello from nodejs", t)
	defer hypervisor.Stop()
}

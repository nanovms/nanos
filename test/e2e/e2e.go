package e2e

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// AsyncCmdStart runs cmd with asynchronously and returns *exec.Cmd, stdout/stderr as one or err if something blew up
func AsyncCmdStart(cmd string) (command *exec.Cmd, buffer *bytes.Buffer, err error) {
	command = exec.Command("/bin/bash", "-c", cmd)
	buffer = &bytes.Buffer{}
	command.Stdout = buffer
	command.Stderr = buffer
	command.SysProcAttr = &syscall.SysProcAttr{}
	command.SysProcAttr.Setsid = true
	err = command.Start()
	if err != nil {
		return command, buffer, err
	}
	return command, buffer, nil
}

func KillProcess(command *exec.Cmd) {
	pgid, err := syscall.Getpgid(command.Process.Pid)
	if err == nil {
		syscall.Kill(-pgid, syscall.SIGKILL)
	}
	command.Wait()
}

func goPrebuild(t *testing.T) {
	effect, err := exec.Command("/bin/bash", "-c", "go build main.go").CombinedOutput()
	if err != nil {
		t.Log(effect)
		t.Fatal(err)
	}
}

func rubyPrebuild(t *testing.T) {
	effect, err := exec.Command("/bin/bash", "-c", "mkdir -p .ruby && export GEM_HOME=.ruby && gem install sinatra --no-rdoc --no-ri").CombinedOutput()
	if err != nil {
		t.Log(effect)
		t.Fatal(err)
	}
}

func rustPrebuild(t *testing.T) {
	effect, err := exec.Command("/bin/bash", "-c", "rustc http_server.rs -o main").CombinedOutput()
	if err != nil {
		t.Log(effect)
		t.Fatal(err)
	}
}

func testPackages(t *testing.T) {
	var tests = []struct {
		name     string
		pkg      string
		dir      string
		request  string
		elf      string
		prebuild func(t *testing.T)
	}{
		{name: "python_3.6.7", pkg: "python_3.6.7", dir: "python_3.6.7", request: "http://0.0.0.0:8000"},
		{name: "node_v11.5.0", pkg: "node_v11.5.0", dir: "node_v11.5.0", request: "http://0.0.0.0:8083"},
		{name: "nginx_1.15.6", pkg: "nginx_1.15.6", dir: "nginx_1.15.6", request: "http://0.0.0.0:8084"},
		{name: "php_7.3.5", pkg: "php_7.3.5", dir: "php_7.3.5", request: "http://0.0.0.0:9501"},
		{name: "ruby_2.5.1", pkg: "ruby_2.5.1", dir: "ruby_2.5.1", request: "http://0.0.0.0:4567", prebuild: rubyPrebuild},
		{name: "go", dir: "go", request: "http://0.0.0.0:8080", elf: "main", prebuild: goPrebuild},
		{name: "rust", dir: "rust", request: "http://0.0.0.0:8080", elf: "main", prebuild: rustPrebuild},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var execcmd string
			dir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			defer os.Chdir(dir)
			err = os.Chdir(dir + "/" + tt.dir)
			if err != nil {
				t.Fatal(err)
			}
			if tt.prebuild != nil {
				t.Log("Calling prebuild", tt.name)
				tt.prebuild(t)
			}
			if tt.elf != "" {
				execcmd = fmt.Sprintf("ops run %s -c config.json", tt.elf)
			} else {
				execcmd = fmt.Sprintf("ops load %s -c config.json", tt.pkg)
			}
			p, buffer, err := AsyncCmdStart(execcmd)
			defer KillProcess(p)
			if err != nil {
				t.Logf("Output: %v", buffer)
				t.Fatal(err)
			}
			time.Sleep(time.Second * 10)
			for count := 0; count <= 5; count++ {
				resp, err := http.Get(tt.request)
				if err != nil {
					t.Logf("Output: %v", buffer)
					t.Fatal(err)
				}
				t.Log("Status code", resp.StatusCode)
				if resp.StatusCode != 200 {
					t.Logf("Output: %v", buffer)
					t.Fatalf("Expected 200 but got %v", resp.StatusCode)
				}
				if resp.ContentLength == 0 {
					t.Logf("Output: %v", buffer)
					t.Fatalf("Received empty content")
				}
			}
		})
	}
}

// RunE2ETests runs all end to end tests
func RunE2ETests(t *testing.T) {
	t.Log("Running E2E test")
	t.Run("packages", testPackages)
}

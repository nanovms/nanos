package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func AsyncCmdStart(cmd string, timeout time.Duration) (command *exec.Cmd, buffer *bytes.Buffer, ctx context.Context, cancel context.CancelFunc, err error) {
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	command = exec.CommandContext(ctx, "/bin/bash", "-c", cmd)
	buffer = &bytes.Buffer{}
	command.Stdout = buffer
	command.Stderr = buffer
	command.SysProcAttr = &syscall.SysProcAttr{}
	command.SysProcAttr.Setsid = true
	command.Cancel = func() error {
		pgid, err := syscall.Getpgid(command.Process.Pid)
		if err == nil {
			err = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		return err
	}
	err = command.Start()
	if err != nil {
		return command, buffer, ctx, cancel, err
	}
	return command, buffer, ctx, cancel, nil
}

func goPrebuild(t *testing.T) {
	effect, err := exec.Command("/bin/bash", "-c", "GOOS=linux GOARCH=amd64 go build main.go").CombinedOutput()
	if err != nil {
		t.Log(effect)
		t.Fatal(err)
	}
}

func stresstestPrebuild(t *testing.T) {
	goPrebuild(t)
	effect, err := exec.Command("/bin/bash", "-c", "ops volume create stressdisk -s 32M").CombinedOutput()
	if err != nil {
		t.Log(effect)
		t.Fatal(err)
	}
}

func stresstestPostrun(t *testing.T) {
	effect, err := exec.Command("/bin/bash", "-c", "ops volume delete stressdisk").CombinedOutput()
	if err != nil {
		t.Log(effect)
		t.Fatal(err)
	}
}

func cloudPrebuild(t *testing.T) {
	goPrebuild(t)
	go func() {
		srv := &http.Server{Addr: ":8080"}
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "{ \"VAR1\":\"Hello world!\" }")
			srv.Shutdown(context.Background())
		})
		err := http.ListenAndServe(":8080", nil)
		if err != nil {
			fmt.Println("Error starting cloud_init server", err)
		}
	}()
}

func rustPrebuild(t *testing.T) {
	effect, err := exec.Command("/bin/bash", "-c", "rustc http_server.rs -o main").CombinedOutput()
	if err != nil {
		t.Log(effect)
		t.Fatal(err)
	}
}

func retryRequest(t *testing.T, request string, attempts int, delay time.Duration) (*http.Response, error) {
	resp, err := http.Get(request)
	if err == nil {
		return resp, nil
	}

	if !(strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "EOF")) {
		return resp, err
	}

	if attempts--; attempts > 0 {
		time.Sleep(delay)
		return retryRequest(t, request, attempts, delay*2)
	}

	return resp, errors.New("unable to reach server after multiple attempts")
}

func testPackages(t *testing.T) {
	var tests = []struct {
		name     string
		pkg      string
		dir      string
		request  string
		elf      string
		prebuild func(t *testing.T)
		postrun  func(t *testing.T)
		skip     bool
		nocross  bool
		data     interface{}
	}{
		{name: "stressdisk", dir: "stressdisk", elf: "main", prebuild: stresstestPrebuild},
		{name: "stressdisk_2", dir: "stressdisk", elf: "main", postrun: stresstestPostrun},
		{name: "node_alloc", pkg: "eyberg/node:20.5.0", dir: "node_alloc"},
		{name: "ruby_alloc", pkg: "eyberg/ruby:3.1.2", dir: "ruby_alloc"},
		{name: "python_alloc", pkg: "eyberg/python:3.10.6", dir: "python_alloc"},
		{name: "cloud_init", dir: "cloud_init", elf: "main", prebuild: cloudPrebuild},
		{name: "python_3.6.7", pkg: "eyberg/python:3.6.7", dir: "python_3.6.7", request: "http://0.0.0.0:8000"},
		{name: "node_v11.5.0", pkg: "eyberg/node:v11.5.0", dir: "node_v11.5.0", request: "http://0.0.0.0:8083"},
		{name: "nginx_1.15.6", pkg: "eyberg/nginx:1.15.6", dir: "nginx_1.15.6", request: "http://0.0.0.0:8084"},
		{name: "php_7.3.5", pkg: "eyberg/php:7.3.5", dir: "php_7.3.5", request: "http://0.0.0.0:9501"},
		{name: "ruby_3.1.2", pkg: "eyberg/ruby:3.1.2", dir: "ruby_3.1.2", request: "http://0.0.0.0:4567"},
		{name: "go", dir: "go", request: "http://0.0.0.0:8080", elf: "main", prebuild: goPrebuild},
		{name: "rust", dir: "rust", request: "http://0.0.0.0:8080", elf: "main", prebuild: rustPrebuild, nocross: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Log("Skipping test")
				return
			}
			if tt.nocross {
				if runtime.GOOS != "linux" {
					t.Log(tt.name, ": no cross compile for", runtime.GOOS, "platform, skipping test")
					return
				}
			}
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
				execcmd = fmt.Sprintf("ops run %s -c config.json --smp %d", tt.elf, runtime.NumCPU())
			} else {
				execcmd = fmt.Sprintf("ops pkg load %s -c config.json --smp %d", tt.pkg, runtime.NumCPU())
			}
			timeout := 120 * time.Second
			if tt.request != "" {
				timeout = 0
			}
			p, buffer, ctx, _, err := AsyncCmdStart(execcmd, timeout)
			if err != nil {
				t.Fatal(err)
			}
			if tt.request == "" {
				var re *regexp.Regexp
				var rs string
				t.Log("Waiting for command to complete...")
				ps, err := p.Process.Wait()
				r := ps.ExitCode()
				if tt.postrun != nil {
					t.Log("Calling postrun", tt.name)
					tt.postrun(t)
				}
				if err != nil {
					goto fatalrun
				}
				if ctx.Err() != nil {
					err = ctx.Err()
					goto fatalrun
				}
				if r != 0 {
					err = fmt.Errorf("ops exit code %d", r)
					goto fatalrun
				}
				re = regexp.MustCompile("exit status [0-9]+")
				rs = re.FindString(buffer.String())
				if rs == "" || rs != "exit status 1" {
					err = errors.New(rs)
					goto fatalrun
				}
				return
			fatalrun:
				t.Logf("Output: %v", buffer.String())
				t.Fatal(err)
			} else {
				defer p.Cancel()
				for count := 0; count <= 5; count++ {
					var resp *http.Response
					if count == 0 {
						resp, err = retryRequest(t, tt.request, 5, time.Second*2)
					} else {
						resp, err = http.Get(tt.request)
					}
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
			}
		})
	}
}

// RunE2ETests runs all end to end tests
func RunE2ETests(t *testing.T) {
	t.Log("Running E2E test")
	t.Run("packages", testPackages)
}

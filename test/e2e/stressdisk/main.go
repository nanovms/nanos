package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	ZERO_DATA_DEFAULT      = false      // -z
	CLEAN_ONLY_DEFAULT     = false      // -c
	EXTRA_FILES_DEFAULT    = 0          // -f number
	WAIT_ACTION_DEFAULT    = 1          // -t seconds
	TEST_FILE_SIZE_DEFAULT = 4          // -s MiB
	TEST_DIR_DEFAULT       = "tfs_root" // -d dir
	TEST_FILE_PREFIX       = "TST_"
)

const (
	KiB = 1_024 * 1   // bytes
	MiB = 1_024 * KiB // bytes
	GiB = 1_024 * MiB // bytes
)

var (
	// flags
	testDir    = flag.String("d", TEST_DIR_DEFAULT, "Directory to use for test files")
	fileSize   = flag.Int("s", TEST_FILE_SIZE_DEFAULT, "Size (MiB) of data to write on each test file")
	extraFiles = flag.Int("f", EXTRA_FILES_DEFAULT, "Number of additional files to attempt writting to (over)fill the drive")
	waitSec    = flag.Int("t", WAIT_ACTION_DEFAULT, "Time in seconds to wait after each file r/w action") // possibly to prevent written data corruption on qemu
	cleanOnly  = flag.Bool("c", CLEAN_ONLY_DEFAULT, "Clean test files from the storage and terminate the program")
	zeroData   = flag.Bool("z", ZERO_DATA_DEFAULT, "Zero bytes on the data files (no random data generated)")
)

func main() {
	flag.Parse()
	if *fileSize <= 0 || *waitSec < 0 || *testDir == "" {
		log.Fatal("flag(s) provided but wrong value")
	}
	// from flags
	TEST_DIR := *testDir
	TEST_FILE_SIZE := *fileSize * MiB
	WAIT_SECONDS := time.Duration(*waitSec) * time.Second
	EXTRA_FILES := *extraFiles
	CLEAN_ONLY := *cleanOnly
	ZERO_DATA := *zeroData

	// disk stats
	ds := NewStatFS(TEST_DIR)

	// 1. clean-up test dir - calculate/check sha1sum and print existing data before delete
	{
		STEP := "1"
		log.Println()
		log.Printf("STEP(%s): Checking for existing data on (%s)", STEP, TEST_DIR)
		log.Println()

		// fetch disk stats
		if err := ds.Fetch(); err != nil {
			log.Fatalf("STEP(%s): %s", STEP, err)
		} else {
			ds.Print()
			log.Println()
		}

		files, err := filepath.Glob(filepath.Join(TEST_DIR, TEST_FILE_PREFIX+"*"))
		if err != nil {
			log.Fatalf("STEP(%s): %s", STEP, err)
		}

		for _, fn := range files {
			if data, err := os.ReadFile(fn); err != nil {
				log.Printf("STEP(%s): %s", STEP, err)
			} else {
				dataSHA := sha1.Sum(data)
				dataSHAHex := hex.EncodeToString(dataSHA[:])
				status := fn[len(fn)-len(dataSHAHex):] == dataSHAHex
				log.Printf("STEP(%s): %s - %x  (%d B) - %s\n", STEP, fn, dataSHA, len(data), func(status bool) string {
					if status {
						return "OK"
					}
					return "CORRUPTED"
				}(status))
				if !status {
					panic(errors.New("data corrupted"))
				}
			}

			// unlink only no truncate here - Syscall(SYS_UNLINKAT,...)
			if err := os.Remove(fn); err != nil {
				log.Printf("STEP(%s): %s", STEP, err)
			}

			// wait
			if WAIT_SECONDS.Seconds() > 0 {
				time.Sleep(WAIT_SECONDS)
			}

		}

		if CLEAN_ONLY {
			log.Println()
			log.Printf("DONE")
			os.Exit(0)
		}
	}

	// 2. write some files with the same data (random or zeroed)
	{
		STEP := "2"
		log.Println()
		log.Printf("STEP(%s): Trying to write (%d bytes => %d blocks)/file on (%s)", STEP, TEST_FILE_SIZE, ds.BlockFiles(TEST_FILE_SIZE), TEST_DIR)
		log.Println()

		data := make([]byte, TEST_FILE_SIZE)
		if !ZERO_DATA {
			if _, err := rand.Read(data); err != nil {
				log.Fatalf("STEP(%s): %s", STEP, err)
			}
		}
		dataSHA := sha1.Sum(data)

		// fetch/update disk stats - since we may have deleted files on STEP(1)
		if err := ds.Fetch(); err != nil {
			log.Fatalf("STEP(%s): %s", STEP, err)
		} else {
			ds.Print()
			log.Println()
		}

		maxFiles := ds.MaxFiles(TEST_FILE_SIZE)
		log.Printf("STEP(%s): Approx (%d) file(s) expected to succeed, (%d) additional file(s) may be attempted", STEP, maxFiles, EXTRA_FILES)
		for i := 0; i < maxFiles+EXTRA_FILES; i++ {
			fn := filepath.Join(TEST_DIR, fmt.Sprintf("%s%04d_%x", TEST_FILE_PREFIX, i+1, dataSHA))

			f, err := os.OpenFile(fn, os.O_TRUNC|os.O_CREATE|os.O_WRONLY|syscall.O_DIRECT, 0666) // O_DIRECT may not have any effect !!!
			if err != nil {
				log.Fatalf("STEP(%s): %s", STEP, err)
			}

			n, err := f.Write(data)
			if errc := f.Close(); errc != nil {
				log.Printf("STEP(%s): %s", STEP, errc)
			}
			if err != nil {
				log.Printf("STEP(%s): %s", STEP, err)
				if err := os.Remove(fn); err != nil {
					log.Printf("STEP(%s): %s", STEP, err)
				}
			} else {
				log.Printf("STEP(%s): %s - %x (%d B) - %s\n", STEP, fn, sha1.Sum(data), n, func(status bool) string {
					if status {
						return "OK"
					}
					return "OK, SHOULD HAVE FAILED"
				}(i < maxFiles))
			}

			// wait
			if WAIT_SECONDS.Seconds() > 0 {
				time.Sleep(WAIT_SECONDS)
			}

			if err != nil {
				break
			}
		}
	}

	// 3. read files content and calculate/check sha1sum
	{
		STEP := "3"
		log.Println()
		log.Printf("STEP(%s): Read files and calculate checksum on (%s)", STEP, TEST_DIR)
		log.Println()

		// fetch/update disk stats - since we may have added files on STEP(2)
		if err := ds.Fetch(); err != nil {
			log.Fatalf("STEP(%s): %s", STEP, err)
		} else {
			ds.Print()
			log.Println()
		}

		files, err := filepath.Glob(filepath.Join(TEST_DIR, TEST_FILE_PREFIX+"*"))
		if err != nil {
			log.Fatalf("STEP(%s): %s", STEP, err)
		}

		for _, fn := range files {
			if data, err := os.ReadFile(fn); err != nil {
				log.Printf("STEP(%s): %s", STEP, err)
			} else {
				sha1Sum := sha1.Sum(data)
				sha1SumHex := hex.EncodeToString(sha1Sum[:])
				status := fn[len(fn)-len(sha1SumHex):] == sha1SumHex
				log.Printf("STEP(%s): %s - %x  (%d B) - %s\n", STEP, fn, sha1Sum, len(data), func(status bool) string {
					if status {
						return "OK"
					}
					return "CORRUPTED"
				}(status))
				if !status {
					panic(errors.New("data corrupted"))
				}
			}

			// wait
			if WAIT_SECONDS.Seconds() > 0 {
				time.Sleep(WAIT_SECONDS)
			}
		}
	}

	{
		log.Println()
		log.Println("DONE - terminating")
	}
}

/*

	disk stats helpers

*/

// StatFS ...
type StatFS struct {
	path string
	stat syscall.Statfs_t
}

// NewStatFS ...
func NewStatFS(path string) *StatFS {
	var stat syscall.Statfs_t
	return &StatFS{path: path, stat: stat}
}

// Fetch the updated stats
func (s *StatFS) Fetch() error {
	return syscall.Statfs(s.path, &s.stat)
}

// MaxFiles that can be written based on filesize and free blocks
func (s *StatFS) MaxFiles(size int) int {
	return int(s.stat.Bfree / (uint64(size) / uint64(s.stat.Bsize)))
}

// BlockFiles calculates the amount of blocks needes for a file based on filesize and blocksize
func (s *StatFS) BlockFiles(size int) int {
	return size / int(s.stat.Bsize)
}

// Print ...
func (s *StatFS) Print() {
	log.Printf("\tBlock  Size : %dB => %d blocks/MiB", s.stat.Bsize, MiB/s.stat.Bsize)
	log.Printf("\tBlocks Total: %d Blocks", s.stat.Blocks)
	log.Printf("\tBlocks Free : %d Blocks", s.stat.Bfree)
	log.Printf("\tBlocks Avail: %d Blocks", s.stat.Bavail)
	log.Printf("\tFiles       : %d", s.stat.Files)
	log.Printf("\tFfree       : %d", s.stat.Ffree)
	log.Printf("\tFsid        : %v", s.stat.Fsid.X__val)
	log.Printf("\tNamelen     : %d", s.stat.Namelen)
	log.Printf("\tFrsize      : %d", s.stat.Frsize)
	log.Printf("\tFlags       : %d", s.stat.Flags)
	log.Printf("\tSpare       : %v", s.stat.Spare)
}

package runner

import (
	"sort"

	"github.com/nanovms/ops/lepton"
)

func defaultConfig() lepton.Config {
	var c lepton.Config

	c.Boot = "../output/boot/boot.img"
	c.Kernel = "../output/stage3/stage3.img"
	c.Mkfs = "../output/mkfs/bin/mkfs"
	c.NameServer = "8.8.8.8"

	c.Env = make(map[string]string)
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

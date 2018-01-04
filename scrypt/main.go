package main

import (
	"os"
	"stash.corp.netflix.com/ps/vssm/scryptlib"
)

func main() {
	println(scryptlib.CalcScrypt(os.Args[0]))
}

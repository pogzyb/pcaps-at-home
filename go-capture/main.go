package main

import (
	capture "./pcapturer"
	"os"
)

func main() {
	currentDir, _ := os.Getwd()
	capture.Run("enp3s0", currentDir)
}

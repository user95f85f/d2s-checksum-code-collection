package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/sqweek/dialog"
)

func main() {
	file, err := dialog.File().Title("Choose Save to fix").Filter("Diablo 2 Save File", "d2s").Load()

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	binary.LittleEndian.PutUint32(data[12:], uint32(0))

	//Generate Checksum
	var sum int32 = 0
	for _, byt := range data {
		var bytcopy int32 = int32(byt)
		if sum < 0 {
			bytcopy += 1
		}
		sum = bytcopy + (sum * 2)
	}

	binary.LittleEndian.PutUint32(data[12:], uint32(sum))

	f, err := os.Create(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	n2, err := f.Write(data)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}

	fmt.Println(n2, "bytes written successfully to "+file)
	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}

	log.Println("exiting...")
}

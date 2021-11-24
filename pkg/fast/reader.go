package fast

import (
	"bufio"
	"bytes"
	"os"
	"sync"
	"syscall"
)

func ReadLines(filename string, channels []chan []byte) error {
	f, err := os.Open(filename)
	info, _ := f.Stat()
	if err != nil {
		return err
	}
	defer f.Close()
	buf, err := syscall.Mmap(int(f.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return err
	}
	chunkSize := len(buf) / len(channels)

	readerWg := sync.WaitGroup{}
	readerWg.Add(len(channels))
	seekPos := 0
	for i := 0; i < len(channels); i++ {
		startByte := seekPos
		seekPos += chunkSize
		if seekPos > len(buf)-1 {
			seekPos = len(buf) - 1
		}
		for seekPos <= len(buf)-1 && buf[seekPos] != '\n' {
			seekPos++
		}
		if seekPos < len(buf)-1 {
			seekPos++
		}
		chunk := buf[startByte:seekPos]
		//fmt.Printf("Chunk %d: %d bytes [%d:%d]\n", i, len(chunk), startByte, seekPos)
		go func(chunk []byte, linesCh chan []byte) {
			defer readerWg.Done()
			scan := bufio.NewScanner(bytes.NewReader(chunk))
			for scan.Scan() {
				line := []byte(scan.Text())
				linesCh <- line
			}
			if err := scan.Err(); err != nil {
				panic(err)
			}
			close(linesCh)
		}(chunk, channels[i])
	}
	readerWg.Wait()
	return nil
}

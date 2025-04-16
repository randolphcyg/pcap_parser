package pcap_parser

import (
	"fmt"
	"testing"
)

const inputFilepath = "./pcaps/SAT-03-11-2018_0.pcap"

func TestEpanVersion(t *testing.T) {
	t.Log(EpanVersion())
}

func TestGetAllFrames(t *testing.T) {
	frames, total, err := GetAllFrames(inputFilepath, 5, 10, WithDebug(false), IgnoreError(false))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(len(frames), total)
}

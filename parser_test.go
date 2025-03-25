package pcap_parser

import (
	"fmt"
	"strings"
	"testing"
)

const inputFilepath = "./pcaps/SAT-03-11-2018_0.pcap"

func TestEpanVersion(t *testing.T) {
	t.Log(EpanVersion())
}

func TestGetHexDataByIdx(t *testing.T) {
	hexData, err := GetHexDataByIdx(inputFilepath, 65)
	if err != nil || hexData == nil {
		t.Fatal(err)
	}

	for i, item := range hexData.Offset {
		t.Log(i, item)
	}
	for i, item := range hexData.Hex {
		t.Log(i, item)
	}
	for i, item := range hexData.Ascii {
		t.Log(i, item)
	}
}

func TestGetFrameByIdx(t *testing.T) {
	frame, err := GetFrameByIdx(inputFilepath, 65, WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame index:", frame.BaseLayers.Frame.Number, "===========================")
	t.Log("【layer _ws.col.protocol】:", frame.BaseLayers.WsCol.Protocol)

	if frame.BaseLayers.Ip != nil {
		t.Log("## ip.src:", frame.BaseLayers.Ip.Src)
		t.Log("## ip.dst:", frame.BaseLayers.Ip.Dst)
	}

	t.Log("@@@", frame.Layers[strings.ToLower(frame.BaseLayers.WsCol.Protocol)])
}

func TestGetFramesByIdxs(t *testing.T) {
	nums := []int{11, 5, 0, 1, -1, 13, 288}
	frames, err := GetFramesByIdxs(inputFilepath, nums, WithDebug(false))
	if err != nil {
		t.Fatal(err)
	}

	// [1 5 11 13]
	for _, frame := range frames {
		t.Log("# Frame index:", frame.BaseLayers.WsCol.Num, "===========================")
		t.Log("## Index:", frame.Index)
	}
}

func TestGetAllFrames(t *testing.T) {
	frames, err := GetAllFrames(inputFilepath, "192.168.50", 1, 20, WithDebug(false), IgnoreError(false))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(len(frames))

	//for _, frame := range frames {
	//	t.Log("# Frame index:", frame.BaseLayers.WsCol.Num, "===========================")
	//
	//	if frame.BaseLayers.Ip != nil {
	//		t.Log("## ip.src:", frame.BaseLayers.Ip.Src)
	//		t.Log("## ip.dst:", frame.BaseLayers.Ip.Dst)
	//	}
	//	if frame.BaseLayers.Http != nil {
	//		t.Log("## http.request.uri:", frame.BaseLayers.Http[0].RequestUri)
	//	}
	//	if frame.BaseLayers.Dns != nil {
	//		t.Log("## dns:", frame.BaseLayers.Dns)
	//	}
	//}
}

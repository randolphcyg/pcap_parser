package pcap_parser

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark -lpcap
#cgo CFLAGS: -I${SRCDIR}/include
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -I${SRCDIR}/include/libpcap

#include "lib.h"
#include "offline.h"
*/
import "C"
import (
	"encoding/json"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var (
	ErrFileNotFound    = errors.New("cannot open file, no such file")
	ErrReadFile        = errors.New("occur error when read file ")
	ErrFromCLogic      = errors.New("run c logic occur error")
	ErrParseDissectRes = errors.New("fail to parse DissectRes")
	ErrFrameIsBlank    = errors.New("frame data is blank")
)

var EpanMutex = &sync.Mutex{}

// Init policies、WTAP mod、EPAN mod.
func init() {
	success := C.init_env()
	if !success {
		panic("fail to init env")
	}
}

// IsFileExist check if the file path exists
func IsFileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

// CChar2GoStr C string -> Go string
func CChar2GoStr(src *C.char) string {
	return C.GoStringN(src, C.int(C.strlen(src)))
}

// EpanVersion get EPAN module's version
func EpanVersion() string {
	return C.GoString((*C.char)(C.epan_get_version()))
}

// initCapFile Init capture file only once for each pcap file
func initCapFile(path string, opts ...Option) (conf *Conf, err error) {
	if !IsFileExist(path) {
		err = errors.Wrap(ErrFileNotFound, path)
		return
	}

	conf = NewConfig(opts...)
	errNo := C.init_cf(C.CString(path))
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		return
	}

	return
}

// HexData hex data
type HexData struct {
	Offset []string `json:"offset"`
	Hex    []string `json:"hex"`
	Ascii  []string `json:"ascii"`
}

// ParseHexData
//
// @Description: Unmarshal hex data dissect result into a structured format.
// @param src: JSON string representing the hex data.
// @return hexData: Parsed hex data.
func ParseHexData(src string) (hexData *HexData, err error) {
	err = json.Unmarshal([]byte(src), &hexData)
	if err != nil {
		return nil, err
	}

	return hexData, nil
}

// GetHexDataByIdx
//
// @Description: Retrieve and parse hex data for a specific frame by its index.
// @param path: Path to the pcap file.
// @param frameIdx: The index of the frame to retrieve hex data for (1-based index).
// @param opts: Optional configuration for dissection.
// @return hexData: Parsed hex data of the specified frame.
func GetHexDataByIdx(path string, frameIdx int, opts ...Option) (hexData *HexData, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	_, err = initCapFile(path, opts...)
	if err != nil {
		return
	}

	// get specific frame hex data in json format by c
	srcHex := C.get_specific_frame_hex_data(C.int(frameIdx))
	if srcHex != nil {
		if C.strlen(srcHex) == 0 { // loop ends
			return
		}
	}

	// unmarshal dissect result
	hexData, err = ParseHexData(CChar2GoStr(srcHex))
	if err != nil {
		slog.Warn("ParseHexData:", "ParseFrameData", err)
		return
	}

	return
}

// ParseFrameData
//
// @Description: Unmarshal and prrocess frame data concurrently, including parsing multiple network layers.
// @param src: JSON string representing the frame data.
// @return frame: Parsed frame data.
func ParseFrameData(src string) (frame *FrameData, err error) {
	if src == "" {
		return nil, errors.New("empty input data")
	}

	err = json.Unmarshal([]byte(src), &frame)
	if err != nil {
		return nil, ErrParseDissectRes
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var layerErrors []error

	// parseAndSetLayer parses a network layer and sets the result in the frame data.
	parseAndSetLayer := func(layerFunc func() (any, error), setLayerFunc func(any)) {
		defer wg.Done()
		layer, err := layerFunc()
		if err != nil && !errors.Is(err, ErrLayerNotFound) { // ignore if layer not found
			layerErrors = append(layerErrors, err)
		}
		if layer != nil {
			mu.Lock()
			setLayerFunc(layer) // update BaseLayers
			mu.Unlock()
		}
	}

	wg.Add(7)

	go parseAndSetLayer(frame.Layers.WsCol, func(layer any) {
		frame.BaseLayers.WsCol = layer.(*WsCol)
	})

	go parseAndSetLayer(frame.Layers.Frame, func(layer any) {
		frame.BaseLayers.Frame = layer.(*Frame)
	})

	go parseAndSetLayer(frame.Layers.Ip, func(layer any) {
		frame.BaseLayers.Ip = layer.(*Ip)
	})

	go parseAndSetLayer(frame.Layers.Udp, func(layer any) {
		frame.BaseLayers.Udp = layer.(*Udp)
	})

	go parseAndSetLayer(frame.Layers.Tcp, func(layer any) {
		frame.BaseLayers.Tcp = layer.(*Tcp)
	})

	go parseAndSetLayer(frame.Layers.Http, func(layer any) {
		frame.BaseLayers.Http = layer.([]*Http)
	})

	go parseAndSetLayer(frame.Layers.Dns, func(layer any) {
		frame.BaseLayers.Dns = layer.(*Dns)
	})

	wg.Wait()

	// Summarize all errors of a frame
	if len(layerErrors) > 0 {
		return frame, errors.Errorf("frame:%d:%v", frame.BaseLayers.Frame.Number, layerErrors)
	}

	return frame, nil
}

// GetFrameByIdx
//
// @Description: Dissect a specific frame of the pcap file by its index and return the JSON result.
// @param path: Path to the pcap file.
// @param frameIdx: The index of the frame to be dissected (1-based index).
// @param opts: Optional configuration for dissection.
// @return frameData: JSON dissect result of the specified frame.
func GetFrameByIdx(path string, frameIdx int, opts ...Option) (frameData *FrameData, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	counter := 0
	for {
		counter++
		if counter < frameIdx && frameIdx != counter {
			continue
		}

		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter), C.int(printCJson))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				return frameData, ErrFrameIsBlank
			}
		}

		// unmarshal dissect result
		frameData, err = ParseFrameData(CChar2GoStr(srcFrame))
		if err != nil {
			slog.Warn("GetFrameByIdx:", "ParseFrameData", err)
			return
		}

		return
	}
}

func removeNegativeAndZero(nums []int) []int {
	var result []int
	for _, num := range nums {
		if num > 0 {
			result = append(result, num)
		}
	}
	return result
}

// GetFramesByIdxs
//
//	@Description: Dissect specific frames of the pcap file and return JSON results.
//	@param path: Pcap file path
//	@param frameIdxs: The frame numbers to be extracted
//	@return frames: JSON dissect results of the specified frames
func GetFramesByIdxs(path string, frameIdxs []int, opts ...Option) (frames []*FrameData, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	frameIdxs = removeNegativeAndZero(frameIdxs)
	// Must sort from smallest to largest
	slices.Sort(frameIdxs)

	for _, idx := range frameIdxs {
		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(idx), C.int(printCJson))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				continue
			}
		}

		// unmarshal dissect result
		frame, err := ParseFrameData(CChar2GoStr(srcFrame))
		if err != nil {
			slog.Warn("GetFramesByIdxs:", "ParseFrameData", err)
		}

		frames = append(frames, frame)
	}

	return
}

// GetAllFrames
//
//	@Description: Dissect all frames of the pcap file and return JSON results.
//	@param path: Pcap file path
//	@param key: 用来模糊匹配
//	@param page: 页数
//	@param size: 返回的数量上限
//	@return frames: JSON dissect results of all frames
func GetAllFrames(path string, key string, page, size int, opts ...Option) (frames []string, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()
	conf, err := initCapFile(path, opts...)

	if err != nil {
		return nil, err
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	start := time.Now()
	frameChannel := make(chan string, 100)

	// call C function
	go func() {
		defer close(frameChannel)
		totalCnt := 1
		validCnt := 0
		offset := (page - 1) * size

		for {
			srcFrame := C.proto_tree_in_json(C.int(totalCnt), C.int(printCJson))
			if srcFrame == nil || C.strlen(srcFrame) == 0 { // end
				break
			}

			totalCnt++
			parseFrame := CChar2GoStr(srcFrame)

			// 过滤不符合key的记录
			if key != "" && !strings.Contains(parseFrame, key) {
				continue
			}

			// 分页筛选
			if validCnt < offset {
				validCnt++
				continue
			}

			if validCnt >= offset+size {
				break
			}

			frameChannel <- parseFrame
			validCnt++
		}
	}()

	for frame := range frameChannel {
		frames = append(frames, frame)
	}

	if conf.Debug {
		slog.Info("Dissect end:", "ELAPSED", time.Since(start), "PCAP_FILE", path)
	}

	return frames, nil
}

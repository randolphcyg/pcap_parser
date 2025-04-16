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
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket/pcapgo"
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

	return frame, nil
}

type FrameData struct {
	Index  string `json:"_index"`
	Layers any    `json:"layers"` // source
}

// CountFramesInPCAP 函数用于统计 PCAP 文件中的帧数
func CountFramesInPCAP(filePath string) (int, error) {
	// 打开指定的 PCAP 文件
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	// 确保在函数结束时关闭文件
	defer file.Close()

	// 创建一个新的 PCAP 读取器
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return 0, err
	}

	frameCount := 0
	// 循环读取数据包
	for {
		_, _, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		frameCount++
	}

	return frameCount, nil
}

// GetAllFrames
//
//	@Description: Dissect all frames of the pcap file and return JSON results.
//	@param path: Pcap file path
//	@param page: 页数
//	@param size: 返回的数量上限
//	@return frames: JSON dissect results of all frames
func GetAllFrames(path string, page, size int, opts ...Option) (frames []FrameData, total int, err error) {
	total, _ = CountFramesInPCAP(path)
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return nil, 0, err
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	start := time.Now()
	frameChannel := make(chan *FrameData, 100)

	offset := (page - 1) * size
	// call C function
	go func() {
		defer close(frameChannel)
		pageCnt := 0            // 用于分页计数，重命名为更准确的名称
		currentOffset := offset // 保持 offset 作为固定的起始偏移量

		for pageCnt < size {
			srcFrame := C.proto_tree_in_json(C.int(currentOffset), C.int(printCJson))
			if srcFrame == nil || C.strlen(srcFrame) == 0 {
				slog.Info("proto_tree_in_json 返回空结果", "offset", currentOffset)
				break
			}

			currentOffset++
			parseFrame := CChar2GoStr(srcFrame)

			parseFrameData, err := ParseFrameData(parseFrame)
			if err != nil {
				slog.Info("解析数据包出错", "内容", parseFrame, "错误", err)
				continue
			}

			frameChannel <- parseFrameData
			pageCnt++
			//slog.Info("计数器", "当前计数", currentOffset, "有效计数", pageCnt)
		}
	}()

	for frame := range frameChannel {
		frames = append(frames, *frame)
	}

	if conf.Debug {
		slog.Info("Dissect end:", "ELAPSED", time.Since(start), "PCAP_FILE", path)
	}

	return frames, total, nil
}

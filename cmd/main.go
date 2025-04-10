package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/randolphcyg/pcap_parser"
)

// AnalyzeReq 分析接口请求体
type AnalyzeReq struct {
	TaskID   string `json:"taskID"`
	UUID     string `json:"uuid"`
	PcapPath string `json:"pcapPath"`
	Filter   string `json:"filter"`
	Page     int    `json:"page"`
	Size     int    `json:"size"`
}

// AnalyzeResp 分析接口响应体
type AnalyzeResp struct {
	TaskID     string   `json:"taskID"`
	UUID       string   `json:"uuid"`
	PcapPath   string   `json:"pcapPath"`
	StartTime  string   `json:"startTime"`  // 任务开始时间
	FinishTime string   `json:"finishTime"` // 任务结束时间
	Frames     []string `json:"frames"`     // 结果
}

func validateAnalyzeReq(req AnalyzeReq) error {
	if req.PcapPath == "" {
		return errors.New("PCAP file path is required")
	}
	if !isFileExist(req.PcapPath) {
		return errors.New("PCAP file does not exist")
	}
	return nil
}

// 执行 Wireshark 分析
func runWiresharkAnalysis(req AnalyzeReq) (frames []string, err error) {
	frames, err = pcap_parser.GetAllFrames(req.PcapPath, req.Filter, req.Page, req.Size, pcap_parser.WithDebug(false), pcap_parser.IgnoreError(false))
	if err != nil {
		return nil, err
	}

	return frames, nil
}

func handleWiresharkAnalysis(c *gin.Context) {
	var req AnalyzeReq
	if err := c.BindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param:"+err.Error(), err)
		return
	}
	if err := validateAnalyzeReq(req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid request:"+err.Error(), err)
		return
	}

	begin := time.Now()

	frames, err := runWiresharkAnalysis(req)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "调用错误", err)
		return
	}

	end := time.Now()

	var resp AnalyzeResp
	resp = AnalyzeResp{
		TaskID:     req.TaskID,
		UUID:       req.UUID,
		PcapPath:   req.PcapPath,
		StartTime:  begin.Format(time.RFC3339),
		FinishTime: end.Format(time.RFC3339),
		Frames:     frames,
	}
	slog.Info("wireshark analysis succeeded",
		"pcapPath", req.PcapPath,
		"uuid", req.UUID,
		"taskID", req.TaskID,
		"StartTime", time.Now().Format(time.RFC3339),
		"FinishTime", time.Now().Format(time.RFC3339),
	)
	Success(c, resp)
}

func main() {
	r := gin.Default()

	api := r.Group("/api/v1")
	{
		api.POST("/analyze", handleWiresharkAnalysis)      // 分析接口
		api.GET("/version/wireshark", getWiresharkVersion) // wireshark版本接口
	}

	// 启动服务
	if err := r.Run(":8090"); err != nil {
		slog.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
}

type wiresharkVersionResp struct {
	Version string `json:"version"`
}

func getWiresharkVersion(c *gin.Context) {
	var resp wiresharkVersionResp
	resp.Version = pcap_parser.EpanVersion()
	Success(c, resp)
}

func HandleError(ctx *gin.Context, code int, message string, err error) {
	if err != nil {
		slog.Error(message, slog.Any("error", err))
	}
	ctx.JSON(200, gin.H{
		"code": code,
		"msg":  message,
	})
}

func Success(ctx *gin.Context, data any) {
	ctx.JSON(200, gin.H{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}

func isFileExist(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

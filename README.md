pcap_parser 基于 libwireshark 的离线pcap流量包解析，提供http接口

docker部署
```shell
docker pull ubuntu:22.04 --platform linux/amd64
docker pull golang:1.24.2 --platform linux/amd64
docker tag golang:1.24.2 golang:1.24-u22

# 构建
sudo docker build -t pcap_parser:1.0 . --platform linux/amd64
# 容器导出
sudo docker save pcap_parser:1.0  | gzip > pcap_parser_1_0.tar.gz
# 解压镜像
docker load -i pcap_parser_1_0.tar.gz

# 运行
docker run -d \
    --name pcap_parser \
    -p 8090:8090 \
    -v /opt/pcap_parser/pcaps:/opt/pcap_parser/pcaps \
    pcap_parser:1.0


# 测试
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "pcapPath": "/opt/pcap_parser/pcaps/sshguess.pcap",
    "uuid": "d3db5f67-c441-56a4-9591-c30c3abab24f",
    "taskID": "2333",
    "page": 1,
    "size": 10
  }' \
  http://localhost:8090/api/v1/analyze
  
curl http://localhost:8090/api/v1/version/wireshark
```
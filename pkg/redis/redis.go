package simpleredis

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

type RedisCmd struct {
	Command  string
	Name     string
	Data     []byte
	Duration int64
	Error    error
}

type SimpleRedis struct {
	redisHost string
}

func genRedisArray(params ...[]byte) []byte {
	MSG := ""
	for cntr := 0; cntr < len(params); cntr++ {
		MSG = strings.Join([]string{MSG, string(params[cntr])}, " ")
	}
	MSG = strings.Trim(MSG, " ")
	MSG = strings.Join([]string{MSG, "\r\n"}, "")
	return []byte(MSG)
}

func askRedis(hostnamePort string, cmd RedisCmd, channel chan RedisCmd) {
	conn, err := net.Dial("tcp", hostnamePort)
	if err != nil {
		return
	}
	defer conn.Close()

	writer := textproto.NewWriter(bufio.NewWriter(conn))
	reader := textproto.NewReader(bufio.NewReader(conn))

	switch cmd.Command {
	case "SET":
		data := genRedisArray([]byte("SET"), []byte(cmd.Name), []byte(cmd.Data), []byte("EX"), []byte(fmt.Sprintf("%v", cmd.Duration)))
		writer.PrintfLine(string(data))
		logger.Info("set")
	case "DEL":
		data := genRedisArray([]byte("DEL"), []byte(cmd.Name))
		writer.PrintfLine(string(data))
		logger.Info("del")
	case "GET":
		data := genRedisArray([]byte("GET"), []byte(cmd.Name))
		writer.PrintfLine(string(data))
		logger.Info("get")
		for {
			select {
			case <-time.After(time.Second * 1):
				channel <- RedisCmd{Error: fmt.Errorf("timeout")}
				return
			default:
				read, _ := reader.ReadLineBytes()
				if string(read) != "$1" {
					channel <- RedisCmd{Error: fmt.Errorf("miss")}
					return
				}
				read, _ = reader.ReadLineBytes()
				channel <- RedisCmd{Data: read}
				return
			}
		}
	}
}

func (sr *SimpleRedis) Init(redisHost string) {
	sr.redisHost = redisHost
}

func (sr *SimpleRedis) Get(name string) ([]byte, error) {
	redisCmd := RedisCmd{
		Command: "GET",
		Name:    name,
	}
	channel := make(chan RedisCmd)
	go askRedis(sr.redisHost, redisCmd, channel)
	resp := <-channel
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Data, nil
}

func (sr *SimpleRedis) Set(name string, data []byte, duration int64) error {
	redisCmd := RedisCmd{
		Command:  "SET",
		Name:     name,
		Data:     data,
		Duration: duration,
	}
	go askRedis(sr.redisHost, redisCmd, nil)
	return nil
}

func (sr *SimpleRedis) Del(name string) error {
	redisCmd := RedisCmd{
		Command: "DEL",
		Name:    name,
	}
	go askRedis(sr.redisHost, redisCmd, nil)
	return nil
}

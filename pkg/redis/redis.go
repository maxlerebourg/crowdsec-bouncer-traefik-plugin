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

const (
	RedisUnreachable = "redis:unreachable"
	RedisMiss = "redis:miss"
	RedisTimeout = "redis:timeout"
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
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", hostnamePort)
	if err != nil {
		channel <- RedisCmd{Error: fmt.Errorf(RedisUnreachable)}
		return
	}
	defer conn.Close()

	writer := textproto.NewWriter(bufio.NewWriter(conn))
	reader := textproto.NewReader(bufio.NewReader(conn))

	switch cmd.Command {
	case "SET":
		data := genRedisArray([]byte("SET"), []byte(cmd.Name), []byte(cmd.Data), []byte("EX"), []byte(fmt.Sprintf("%v", cmd.Duration)))
		writer.PrintfLine(string(data))
		logger.Debug("redis:set")
	case "DEL":
		data := genRedisArray([]byte("DEL"), []byte(cmd.Name))
		writer.PrintfLine(string(data))
		logger.Debug("redis:del")
	case "GET":
		data := genRedisArray([]byte("GET"), []byte(cmd.Name))
		writer.PrintfLine(string(data))
		logger.Debug("redis:get")
		for {
			select {
			case <-time.After(time.Second * 1):
				channel <- RedisCmd{Error: fmt.Errorf(RedisTimeout)}
				return
			default:
				read, _ := reader.ReadLineBytes()
				if string(read) != "$1" {
					channel <- RedisCmd{Error: fmt.Errorf(RedisMiss)}
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

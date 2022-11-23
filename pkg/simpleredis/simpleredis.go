// Package simpleredis implements utility routines for interacting.
// It supports currently the following operations: GET, SET, DELETE,
// and support timetoleave for keys.
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

// Error strings for redis.
const (
	RedisUnreachable = "redis:unreachable"
	RedisMiss        = "redis:miss"
	RedisTimeout     = "redis:timeout"
)

// A RedisCmd is used to communicate with redis at low level using commands.
type RedisCmd struct {
	Command  string
	Name     string
	Data     []byte
	Duration int64
	Error    error
}

// A SimpleRedis is used to communicate with redis.
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

func send(wr *textproto.Writer, method string, data []byte) {
	if err := wr.PrintfLine(string(data)); err != nil {
		logger.Error(fmt.Sprintf("redis:%s  %s", method, err.Error()))
	} else {
		logger.Debug(fmt.Sprintf("redis:%s", method))
	}
}

func askRedis(hostnamePort string, cmd RedisCmd, channel chan RedisCmd) {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", hostnamePort)
	if err != nil {
		channel <- RedisCmd{Error: fmt.Errorf(RedisUnreachable)}
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error(fmt.Sprintf("redis:connClose %s", err.Error()))
		}
	}()

	writer := textproto.NewWriter(bufio.NewWriter(conn))
	reader := textproto.NewReader(bufio.NewReader(conn))

	switch cmd.Command {
	case "SET":
		data := genRedisArray([]byte("SET"), []byte(cmd.Name), cmd.Data, []byte("EX"), []byte(fmt.Sprintf("%d", cmd.Duration)))
		send(writer, "set", data)
	case "DEL":
		data := genRedisArray([]byte("DEL"), []byte(cmd.Name))
		send(writer, "del", data)
	case "GET":
		data := genRedisArray([]byte("GET"), []byte(cmd.Name))
		send(writer, "get", data)
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

// Init sets the redisHost used to connect to redis.
func (sr *SimpleRedis) Init(redisHost string) {
	sr.redisHost = redisHost
}

// Get fetches the value for key name in redis.
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

// Set updates the value for key name in redis with value data for duration.
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

// Del removes the key name in redis.
func (sr *SimpleRedis) Del(name string) error {
	redisCmd := RedisCmd{
		Command: "DEL",
		Name:    name,
	}
	go askRedis(sr.redisHost, redisCmd, nil)
	return nil
}

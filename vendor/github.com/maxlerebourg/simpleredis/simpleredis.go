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
)

// Error strings for redis.
const (
	RedisUnreachable = "redis:unreachable"
	RedisMiss        = "redis:miss"
	RedisTimeout     = "redis:timeout"
	RedisNoAuth      = "redis:noauth"
)

// A redisCmd is used to communicate with redis at low level using commands.
type redisCmd struct {
	Command  string
	Name     string
	Data     []byte
	Duration int64
	Error    error
}

// A SimpleRedis is used to communicate with redis.
type SimpleRedis struct {
	host     string
	pass     string
	database string
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
		fmt.Printf("redis:%s  %s", method, err.Error())
	}
}

func (sr *SimpleRedis) waitRedis(reader *textproto.Reader, channel chan redisCmd) {
	for {
		select {
		case <-time.After(time.Second * 1):
			channel <- redisCmd{Error: fmt.Errorf(RedisTimeout)}
			return
		default:
			read, _ := reader.ReadLineBytes()
			if string(read) != "+OK" {
				channel <- redisCmd{Error: fmt.Errorf(RedisNoAuth)}
				return
			}
		}
		// breaks out of for
		break
	}
}

func (sr *SimpleRedis) askRedis(cmd redisCmd, channel chan redisCmd) {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", sr.host)
	if err != nil {
		channel <- redisCmd{Error: fmt.Errorf(RedisUnreachable)}
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("redis:connClose %s", err.Error())
		}
	}()

	writer := textproto.NewWriter(bufio.NewWriter(conn))
	reader := textproto.NewReader(bufio.NewReader(conn))

	if sr.pass != "" {
		data := genRedisArray([]byte("AUTH"), []byte(sr.pass))
		send(writer, "auth", data)
		sr.waitRedis(reader, channel)
	}

	if sr.database != "" {
		data := genRedisArray([]byte("SELECT"), []byte(sr.database))
		send(writer, "select", data)
		sr.waitRedis(reader, channel)
	}

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
				channel <- redisCmd{Error: fmt.Errorf(RedisTimeout)}
				return
			default:
				read, _ := reader.ReadLineBytes()
				str := string(read)
				if strings.Contains(str, "-NOAUTH") {
					channel <- redisCmd{Error: fmt.Errorf(RedisNoAuth)}
					return
				} else if str != "$1" {
					channel <- redisCmd{Error: fmt.Errorf(RedisMiss)}
					return
				}
				read, _ = reader.ReadLineBytes()
				channel <- redisCmd{Data: read}
				return
			}
		}
	}
}

// Init sets the redisHost used to connect to redis.
func (sr *SimpleRedis) Init(host, pass, database string) {
	sr.host = host
	sr.pass = pass
	sr.database = database
}

// Get fetches the value for key name in redis.
func (sr *SimpleRedis) Get(name string) ([]byte, error) {
	cmd := redisCmd{
		Command: "GET",
		Name:    name,
	}
	channel := make(chan redisCmd)
	go sr.askRedis(cmd, channel)
	resp := <-channel
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Data, nil
}

// Set updates the value for key name in redis with value data for duration.
func (sr *SimpleRedis) Set(name string, data []byte, duration int64) error {
	cmd := redisCmd{
		Command:  "SET",
		Name:     name,
		Data:     data,
		Duration: duration,
	}
	go sr.askRedis(cmd, nil)
	return nil
}

// Del removes the key name in redis.
func (sr *SimpleRedis) Del(name string) error {
	cmd := redisCmd{
		Command: "DEL",
		Name:    name,
	}
	go sr.askRedis(cmd, nil)
	return nil
}

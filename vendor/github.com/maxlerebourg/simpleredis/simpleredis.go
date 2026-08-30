// Package simpleredis implements utility routines for interacting.
// It supports currently the following operations: GET, MGET, SET, DELETE,
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
	RedisIssue       = "redis:issue?"
)

// A redisCmd is used to communicate with redis at low level using commands.
type redisCmd struct {
	Command  string
	Name     string
	Names    []string
	Data     []byte
	Multi    [][]byte
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

func (sr *SimpleRedis) askRedis(cmd redisCmd, channel chan redisCmd) redisCmd {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp", sr.host)
	if err != nil {
		return redisCmd{Error: fmt.Errorf(RedisUnreachable)}
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
				return redisCmd{Error: fmt.Errorf(RedisTimeout)}
			default:
				read, _ := reader.ReadLineBytes()
				str := string(read)
				if strings.Contains(str, "-NOAUTH") {
					return redisCmd{Error: fmt.Errorf(RedisNoAuth)}
				} else if str == "$-1" {
					return redisCmd{Error: fmt.Errorf(RedisMiss)}
				}
				read, _ = reader.ReadLineBytes()
				return redisCmd{Data: read}
			}
		}
	case "MGET":
		args := [][]byte{[]byte("MGET")}
		for _, name := range cmd.Names {
			args = append(args, []byte(name))
		}
		send(writer, "mget", genRedisArray(args...))
		for {
			select {
			case <-time.After(time.Second * 1):
				return redisCmd{Error: fmt.Errorf(RedisTimeout)}
			default:
				values, err := readRedisBulkArray(reader)
				if err != nil {
					return redisCmd{Error: err}
				}
				return redisCmd{Multi: values}
			}
		}
	}
	return redisCmd{Error: fmt.Errorf(RedisIssue)}
}

// Init sets the redisHost used to connect to redis.
func (sr *SimpleRedis) Init(host, pass, database string) {
	sr.host = host
	sr.pass = pass
	sr.database = database
}

func readRedisBulkArray(reader *textproto.Reader) ([][]byte, error) {
	header, err := reader.ReadLineBytes()
	if err != nil {
		return nil, fmt.Errorf(RedisUnreachable)
	}
	str := string(header)
	if strings.Contains(str, "-NOAUTH") {
		return nil, fmt.Errorf(RedisNoAuth)
	}
	if strings.HasPrefix(str, "-") || !strings.HasPrefix(str, "*") {
		return nil, fmt.Errorf(RedisIssue)
	}
	var count int
	if _, scanErr := fmt.Sscanf(str, "*%d", &count); scanErr != nil || count < 0 {
		return nil, fmt.Errorf(RedisIssue)
	}
	out := make([][]byte, count)
	for i := 0; i < count; i++ {
		meta, metaErr := reader.ReadLineBytes()
		if metaErr != nil {
			return nil, fmt.Errorf(RedisUnreachable)
		}
		metaStr := string(meta)
		if metaStr == "$-1" {
			continue
		}
		if !strings.HasPrefix(metaStr, "$") {
			return nil, fmt.Errorf(RedisIssue)
		}
		payload, payloadErr := reader.ReadLineBytes()
		if payloadErr != nil {
			return nil, fmt.Errorf(RedisUnreachable)
		}
		out[i] = payload
	}
	return out, nil
}

// Get fetches the value for key name in redis.
func (sr *SimpleRedis) Get(name string) ([]byte, error) {
	cmd := redisCmd{
		Command: "GET",
		Name:    name,
	}
	channel := make(chan redisCmd)
	resp := sr.askRedis(cmd, channel)
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Data, nil
}

// MGet fetches the values for key names in redis. A missing key is a nil slot.
func (sr *SimpleRedis) MGet(names []string) ([][]byte, error) {
	if len(names) == 0 {
		return nil, nil
	}
	cmd := redisCmd{
		Command: "MGET",
		Names:   names,
	}
	channel := make(chan redisCmd)
	resp := sr.askRedis(cmd, channel)
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Multi, nil
}

// Set updates the value for key name in redis with value data for duration.
func (sr *SimpleRedis) Set(name string, data []byte, duration int64) error {
	cmd := redisCmd{
		Command:  "SET",
		Name:     name,
		Data:     data,
		Duration: duration,
	}
	sr.askRedis(cmd, nil)
	return nil
}

// Del removes the key name in redis.
func (sr *SimpleRedis) Del(name string) error {
	cmd := redisCmd{
		Command: "DEL",
		Name:    name,
	}
	sr.askRedis(cmd, nil)
	return nil
}

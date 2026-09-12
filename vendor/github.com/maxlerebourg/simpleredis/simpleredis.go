// Package simpleredis implements utility routines for interacting.
// It supports currently the following operations: GET, MGET, SET, DELETE,
// and support timetoleave for keys.
package simpleredis

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
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

const (
	maxIdleConns = 8
	idleTimeout  = 30 * time.Second
	dialTimeout  = 2 * time.Second
	ioTimeout    = 1 * time.Second
)

var (
	errUnreachable = errors.New(RedisUnreachable)
	errMiss        = errors.New(RedisMiss)
	errTimeout     = errors.New(RedisTimeout)
	errNoAuth      = errors.New(RedisNoAuth)
	errIssue       = errors.New(RedisIssue)
)

type pooledConn struct {
	netConn  net.Conn
	reader   *bufio.Reader
	writer   *bufio.Writer
	lastUsed time.Time
}

func (c *pooledConn) close() {
	_ = c.netConn.Close()
}

// A SimpleRedis is used to communicate with redis.
type SimpleRedis struct {
	host     string
	pass     string
	database string

	mu   sync.Mutex
	idle []*pooledConn
}

// Init sets the redisHost used to connect to redis.
func (sr *SimpleRedis) Init(host, pass, database string) {
	sr.host = host
	sr.pass = pass
	sr.database = database
}

// Get fetches the value for key name in redis.
func (sr *SimpleRedis) Get(name string) ([]byte, error) {
	values, err := sr.exec([]byte("GET"), []byte(name))
	if err != nil {
		return nil, err
	}
	if len(values) != 1 {
		return nil, errIssue
	}
	return values[0], nil
}

// MGet fetches the values for keys names in redis, nil where a key is missing.
func (sr *SimpleRedis) MGet(names []string) ([][]byte, error) {
	if len(names) == 0 {
		return nil, nil
	}
	args := make([][]byte, 0, len(names)+1)
	args = append(args, []byte("MGET"))
	for _, name := range names {
		args = append(args, []byte(name))
	}
	values, err := sr.exec(args...)
	if err != nil {
		return nil, err
	}
	if len(values) != len(names) {
		return nil, errIssue
	}
	return values, nil
}

// Set updates the value for key name in redis with value data for duration.
func (sr *SimpleRedis) Set(name string, data []byte, duration int64) error {
	_, err := sr.exec([]byte("SET"), []byte(name), data, []byte("EX"), []byte(strconv.FormatInt(duration, 10)))
	return err
}

// Del removes the key name in redis.
func (sr *SimpleRedis) Del(name string) error {
	_, err := sr.exec([]byte("DEL"), []byte(name))
	return err
}

func (sr *SimpleRedis) exec(args ...[]byte) ([][]byte, error) {
	conn, reused, err := sr.borrow()
	if err != nil {
		return nil, err
	}
	values, reusable, err := sr.do(conn, args)
	sr.release(conn, reusable)
	if err == nil || reusable || !reused {
		return values, err
	}
	conn, err = sr.dial()
	if err != nil {
		return nil, err
	}
	values, reusable, err = sr.do(conn, args)
	sr.release(conn, reusable)
	return values, err
}

func (sr *SimpleRedis) borrow() (*pooledConn, bool, error) {
	var reused *pooledConn
	var stale []*pooledConn
	now := time.Now()

	sr.mu.Lock()
	for len(sr.idle) > 0 {
		conn := sr.idle[len(sr.idle)-1]
		sr.idle = sr.idle[:len(sr.idle)-1]
		if now.Sub(conn.lastUsed) < idleTimeout {
			reused = conn
			break
		}
		stale = append(stale, conn)
	}
	sr.mu.Unlock()

	for _, conn := range stale {
		conn.close()
	}
	if reused != nil {
		return reused, true, nil
	}
	conn, err := sr.dial()
	return conn, false, err
}

func (sr *SimpleRedis) release(conn *pooledConn, reusable bool) {
	if !reusable {
		conn.close()
		return
	}
	conn.lastUsed = time.Now()

	sr.mu.Lock()
	if len(sr.idle) >= maxIdleConns {
		sr.mu.Unlock()
		conn.close()
		return
	}
	sr.idle = append(sr.idle, conn)
	sr.mu.Unlock()
}

func (sr *SimpleRedis) dial() (*pooledConn, error) {
	dialer := net.Dialer{Timeout: dialTimeout}
	netConn, err := dialer.Dial("tcp", sr.host)
	if err != nil {
		return nil, errUnreachable
	}
	conn := &pooledConn{
		netConn: netConn,
		reader:  bufio.NewReader(netConn),
		writer:  bufio.NewWriter(netConn),
	}

	if sr.pass != "" {
		if _, _, err = sr.do(conn, [][]byte{[]byte("AUTH"), []byte(sr.pass)}); err != nil {
			conn.close()
			return nil, err
		}
	}
	if sr.database != "" {
		if _, _, err = sr.do(conn, [][]byte{[]byte("SELECT"), []byte(sr.database)}); err != nil {
			conn.close()
			return nil, err
		}
	}
	return conn, nil
}

func (sr *SimpleRedis) do(conn *pooledConn, args [][]byte) ([][]byte, bool, error) {
	if err := conn.netConn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, false, errUnreachable
	}
	if err := writeCommand(conn.writer, args); err != nil {
		return nil, false, ioError(err)
	}
	values, clean, err := readReply(conn.reader)
	if err != nil && !clean {
		return nil, false, ioError(err)
	}
	return values, true, err
}

func writeCommand(writer *bufio.Writer, args [][]byte) error {
	if _, err := writer.WriteString("*" + strconv.Itoa(len(args)) + "\r\n"); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := writer.WriteString("$" + strconv.Itoa(len(arg)) + "\r\n"); err != nil {
			return err
		}
		if _, err := writer.Write(arg); err != nil {
			return err
		}
		if _, err := writer.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func readReply(reader *bufio.Reader) ([][]byte, bool, error) {
	line, err := readLine(reader)
	if err != nil {
		return nil, false, err
	}
	if len(line) == 0 {
		return nil, false, errIssue
	}

	switch line[0] {
	case '+', ':':
		return [][]byte{line[1:]}, true, nil
	case '-':
		return nil, true, replyError(line[1:])
	case '$':
		data, bulkErr := readBulk(reader, line)
		if bulkErr == errMiss {
			return nil, true, errMiss
		}
		if bulkErr != nil {
			return nil, false, bulkErr
		}
		return [][]byte{data}, true, nil
	case '*':
		count, convErr := strconv.Atoi(string(line[1:]))
		if convErr != nil || count < 0 {
			return nil, false, errIssue
		}
		values := make([][]byte, count)
		for i := 0; i < count; i++ {
			head, headErr := readLine(reader)
			if headErr != nil {
				return nil, false, headErr
			}
			data, bulkErr := readBulk(reader, head)
			if bulkErr == errMiss {
				continue
			}
			if bulkErr != nil {
				return nil, false, bulkErr
			}
			values[i] = data
		}
		return values, true, nil
	default:
		return nil, false, errIssue
	}
}

func readBulk(reader *bufio.Reader, head []byte) ([]byte, error) {
	if len(head) == 0 || head[0] != '$' {
		return nil, errIssue
	}
	length, err := strconv.Atoi(string(head[1:]))
	if err != nil {
		return nil, errIssue
	}
	if length < 0 {
		return nil, errMiss
	}
	data := make([]byte, length+2)
	if _, err = io.ReadFull(reader, data); err != nil {
		return nil, err
	}
	return data[:length], nil
}

func readLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return nil, errIssue
	}
	return line[:len(line)-2], nil
}

func replyError(message []byte) error {
	text := string(message)
	for _, prefix := range []string{"NOAUTH", "WRONGPASS", "NOPERM", "ERR Client sent AUTH"} {
		if strings.HasPrefix(text, prefix) {
			return errNoAuth
		}
	}
	return errors.New(text)
}

func ioError(err error) error {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return errTimeout
	}
	return errUnreachable
}

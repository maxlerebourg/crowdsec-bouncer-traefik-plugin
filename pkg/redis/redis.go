package redis

// My intepretation of the RESP protocol.
// Referenced from https://redis.io/docs/reference/protocol-spec/
// 8-7-2022

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/textproto"
	"net"
	"bufio"
	"strings"
	"sync"
)

type RespT byte

const (
	SimpleString RespT = '+'
	Error        RespT = '-'
	Integer      RespT = ':'
	BulkString   RespT = '$'
	Array        RespT = '*'
)

type Message interface {
	String() string
}

type MsgSimpleStr string
type MsgError string
type MsgBulkStr string
type MsgInteger int64
type MsgArray []Message

func (m MsgInteger) String() string {
	return fmt.Sprintf("%d", m)
}

func (m MsgBulkStr) String() string {
	return string(m)
}

func (m MsgError) String() string {
	return string(m)
}

func (m MsgSimpleStr) String() string {
	return string(m)
}

// func (m MsgArray) String() string {
// 	return fmt.Sprintf("[%s]", strings.Join(Map(m, Message.String), ","))
// }

func (m RedisMessage) String() string {
	return m.Choice.String()
}

type RedisMessage struct {
	RedisType RespT
	Raw       string
	Choice    Message
}

func NewParseError(got RespT, expected ...RespT) error {
	return fmt.Errorf("got %v but expected %v", got, expected)
}

func (msg RedisMessage) Symbol() rune {
	return rune(msg.RedisType)
}

func (msg RedisMessage) AsString() (string, error) {
	if conv, ok := msg.Choice.(MsgSimpleStr); ok {
		return string(conv), nil
	} else if conv, ok := msg.Choice.(MsgBulkStr); ok {
		return string(conv), nil
	} else {
		return "", NewParseError(msg.RedisType, SimpleString, BulkString)
	}
}

func (msg RedisMessage) AsInteger() (int64, error) {
	if conv, ok := msg.Choice.(MsgInteger); ok {
		return int64(conv), nil
	} else {
		return 0, NewParseError(msg.RedisType, Integer)
	}
}

func (msg RedisMessage) AsError() (error, error) {
	if conv, ok := msg.Choice.(MsgError); ok {
		return errors.New(string(conv)), nil
	} else {
		return nil, NewParseError(msg.RedisType, Error)
	}
}

// func (msg RedisMessage) AsArray() ([]Message, error) {
// 	if conv, ok := (msg.Choice).(MsgArray); ok {
// 		return conv, nil
// 	} else {
// 		return nil, NewParseError(msg.RedisType, Array)
// 	}
// }

type RedisReader struct {
	Rd  *textproto.Reader
	Out chan RedisMessage
}

// Reset the parsing state of the reader
func (rr *RedisReader) Reset() {

}

func NewRespReader(tp *textproto.Reader, out chan RedisMessage) RedisReader {
	return RedisReader{
		Rd:  tp,
		Out: out,
	}
}

// Fetch grabs the next incoming RESP type from the IO input
func Fetch(rr *RedisReader) *RedisMessage {
	byteCode, err := rr.TryReadByte()
	if err != nil {
		return nil
	}
	switch RespT(byteCode) {
	case BulkString:
		return RespBulkStr(rr)
	case SimpleString:
		return RespSimpleStr(rr)
	case Integer:
		return RespInt(rr)
	case Error:
		return RespError(rr)
	// case Array:
	// 	return RespArray(rr)
	default:
		panic(fmt.Sprint("Unknown bytecode: ", byteCode))
	}
}

// Scan is the main API to send redis messages out to a channel.
func (rr *RedisReader) Scan() {
	rr.Out <- *Fetch(rr)
}

// RespSimpleStr attempts to parse a string from the resulting line.
//
// TODO: I don't think we need the high level facilities from net/textproto anymore
// 	     since the parsing is quite trivial.
func RespSimpleStr(rr *RedisReader) *RedisMessage {
	s, err := rr.Rd.ReadLine()
	if err != nil {
		log.Printf("Fatal RespSimpleStr: %+v", err)
		return nil
	}

	return &RedisMessage{
		RedisType: RespT(SimpleString),
		Raw:       s,
		Choice:    MsgSimpleStr(s),
	}
}

func RespError(rr *RedisReader) *RedisMessage {
	s, err := rr.Rd.ReadLine()
	if err != nil {
		log.Printf("Fatal RespError: %+v", err)
		return nil
	}

	return &RedisMessage{
		RedisType: RespT(Error),
		Raw:       s,
		Choice:    MsgError(s),
	}
}

// RespSimpleStr attempts to parse a string from the resulting line.
//
// It first expects a length value parsed as an integer,
// then directly copies the subsequent payload into a string
// buffer
func RespBulkStr(rr *RedisReader) *RedisMessage {
	len, err := loopReadInt(rr)
	if err != nil {
		return nil
	}

	// Read the string data into buffer
	bulkStr := make([]byte, len)
	io.ReadFull(rr.Rd.R, bulkStr)

	// Discard two bytes since we don't need the '\r\n'
	_, err = rr.Rd.R.Discard(2)
	if err != nil {
		log.Printf("Fatal: %+v", err)
	}

	return &RedisMessage{
		RedisType: BulkString,
		Raw:       string(bulkStr),
		Choice:    MsgBulkStr(string(bulkStr)),
	}
}

// RespInt reads an integer from the IO stream
func RespInt(rr *RedisReader) *RedisMessage {
	val, err := loopReadInt(rr)
	if err != nil {
		return nil
	}
	return &RedisMessage{
		RedisType: Integer,
		Raw:       fmt.Sprintf("%d", val),
		Choice:    MsgInteger(val),
	}
}

// RespArray reads an array of RESP objects from the IO stream
// func RespArray(rr *RedisReader) *RedisMessage {
// 	len, err := loopReadInt(rr)
// 	if err != nil {
// 		return nil
// 	}
// 	fetched := make([]RedisMessage, 0, len)
// 	for i := 0; i < len; i++ {
// 		fetched[i] = *Fetch(rr)
// 	}
// 	return &RedisMessage{
// 		RedisType: Array,
// 		Raw:       fmt.Sprint(Map(fetched, func(rm RedisMessage) string { return rm.Raw })),
// 		Choice:    MsgArray(Map(fetched, func(rm RedisMessage) Message { return rm.Choice })),
// 	}
// }

// loopReadInt reads from IO and returns an integer, discarding \r\n.
func loopReadInt(rr *RedisReader) (int, error) {
	val := 0
	for b, _ := rr.TryReadByte(); b != '\r'; b, _ = rr.TryReadByte() {
		val = (val * 10) + int(b-byte('0'))
	}
	_, err := rr.Rd.R.Discard(1)
	if err != nil {
		return 0, fmt.Errorf("Fatal loopReadInt: %+v", err)
	}
	return val, nil
}

// TryReadByte attempts to read a single byte from IO and panics on any error
func (rr *RedisReader) TryReadByte() (byte, error) {
	b, err := rr.Rd.R.ReadByte()
	if err != nil {
		return byte('0'), fmt.Errorf("Fatal TryReadByte: %+v", err)
	}
	return b, nil
}

// Map. Your standard good old fashioned generic map function :)
//
// A la []T -> []K
func Map[T any, K any](slice []T, fn func(T) K) []K {
	out := make([]K, 0, len(slice))
	for i := range out {
		out[i] = fn(slice[i])
	}
	return out
}








func loopScan(reader *textproto.Reader, msg_ch chan RedisMessage) {
	rr := NewRespReader(reader, msg_ch)
	for {
		rr.Scan()
	}
}

// repl starts an read input loop on the standard input.
//
// Commands are sent out after a new line is parsed.
//
// TODO: Improve ergonomics of the repl.
func repl(input *textproto.Reader, wr *textproto.Writer) {
	for {
		print("> ")
		input_str, err := input.ReadLine()
		if len(input_str) > 0 && err == nil {
			// The redis server expects arrays of bulk strings for sending commands.
			commands := strings.Split(input_str, " ")
			// Specify the array length and create the bulk strings
			pipe := []string{fmt.Sprintf("*%d", len(commands))}
			pipe = append(pipe, createBulkStrings(commands)...)
			for _, out := range pipe {
				wr.PrintfLine(out)
			}
		}
	}
}

// createBulkStrings converts normal strings into bulk strings to send to redis.
func createBulkStrings(commands []string) []string {
	cmds := make([]string, len(commands)*2)
	for i, v := range commands {
		cmds[i*2] = fmt.Sprintf("$%d", len(commands[i]))
		cmds[(i*2)+1] = v
	}
	return cmds
}


// cmd/client starts a simple Read-Send-Print-Loop (RSPL?)
// with a redis server.
//
// TODO: Implement command flags
func Init(host string, password string) (*textproto.Writer, *textproto.Reader) {
	log.Printf("yo")
	// Create the connection to the redis server
	// TODO: cli, rm hardcode
	conn, err := net.Dial("tcp", host)
	if err != nil {
		log.Printf("[net] unable to connect: %v", err)
		return nil, nil
	}
	defer conn.Close()

	// Create the readers and writers we will pass to our subroutines
	msg_channel := make(chan RedisMessage)
	write_sock := textproto.NewWriter(bufio.NewWriter(conn))
	read_sock := textproto.NewReader(bufio.NewReader(conn))

	go runAsWaitGroup(
		// Subscribe to redis connection
		func() {
			loopScan(read_sock, msg_channel)
		},
		// Write to output
		func() {
			for {
				msg := <-msg_channel
				log.Printf("%v", msg)
			}
		},
	).Wait()
	log.Printf("yolo")
  return write_sock, read_sock 
}

// runAsWaitGroup runs closures within a sync.WaitGroup
//
// Calling .Wait() on the resultant WaitGroup is a blocking operation until all closures finish running.
func runAsWaitGroup(closures ...func()) *sync.WaitGroup {
	wg := sync.WaitGroup{}
	for _, fn := range closures {
		wg.Add(1)
		go func(fn func()) {
			fn()
			wg.Done()
		}(fn)
	}
	return &wg
}
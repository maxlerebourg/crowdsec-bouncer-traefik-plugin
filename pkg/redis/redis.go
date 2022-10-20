package simpleredis

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tehnerd/goUtils/netutils"

	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

type RedisCmd struct {
	Command string
	Name    string
	Data    []byte
	Error   error
}

type SimpleRedis struct {
	redisChanRead  chan RedisCmd
	redisChanWrite chan RedisCmd
	redisHost      string
	redisCmd       RedisCmd
}

func GenRedisArray(params ...[]byte) []byte {
	CRLF := "\r\n"
	MSG := ""
	for cntr := 0; cntr < len(params); cntr++ {
		MSG = strings.Join([]string{MSG, string(params[cntr])}, " ")
	}
	MSG = strings.Trim(MSG, " ")
	MSG = strings.Join([]string{MSG, CRLF}, "")
	return []byte(MSG)
}

func RedisSet(name string, data []byte) []byte {
	return GenRedisArray([]byte("SET"), []byte(name), data)
}

func RedisGet(name string) []byte {
	return GenRedisArray([]byte("GET"), []byte(name))
}

func ParseRedisResponse(response []byte, dataBuf []byte, Len *int) ([]byte, []byte, error) {
	dataBuf = append(dataBuf, response...)
	lenCRLF := 2
	if *Len != 0 {
		if len(dataBuf) < *Len {
			return nil, dataBuf, nil
		} else {
			return dataBuf[:*Len], dataBuf[*Len:], nil
		}
	}
	for {
		switch string(dataBuf[0]) {
		case "+", "-", ":":
			//simple strings, error,int. usually ther are in format (+|-|:)DATA\r\n"
			if len(dataBuf) < 3 {
				return nil, dataBuf, nil
			}
			cntr := 1
			for ; cntr < len(dataBuf); cntr++ {
				if dataBuf[cntr] == '\r' {
					break
				}
			}
			if cntr == len(dataBuf) {
				return nil, dataBuf, nil
			}
			response = dataBuf[1:cntr]
			return response, dataBuf[cntr+2:], nil
		case "$":
			//bulk string. format $LEN\r\nDATA\r\n. up to 512MB
			cntr := 1
			for ; cntr < len(dataBuf); cntr++ {
				if string(dataBuf[cntr]) == "\r" {
					break
				}
			}
			if cntr == len(dataBuf) || cntr+lenCRLF > len(dataBuf) {
				return nil, dataBuf, nil
			}
			dataLen, err := strconv.Atoi(string(dataBuf[1:cntr]))
			if err != nil {
				return nil, dataBuf[cntr:], nil
			}

			if dataLen == -1 {
				return nil, dataBuf[cntr:], fmt.Errorf("NOT FOUND")
			}
			if cntr+lenCRLF > len(dataBuf)-lenCRLF {
				*Len = dataLen
				return nil, dataBuf[cntr+lenCRLF:], nil
			}
			if len(dataBuf[cntr+lenCRLF:len(dataBuf)-lenCRLF]) < dataLen {
				*Len = dataLen
				return nil, dataBuf[cntr+lenCRLF:], nil
			} else {
				return dataBuf[cntr+lenCRLF : cntr+dataLen+lenCRLF], dataBuf[cntr+dataLen+lenCRLF:], nil
			}
		case "*":
			panic("array")
		default:
			if len(dataBuf) > 1 {
				dataBuf = dataBuf[1:]
			} else {
				return nil, dataBuf, nil
			}
		}
	}
	return nil, dataBuf, nil
}

func RedisContext(hostnamePort string, redisCmdWrite, redisCmdRead chan RedisCmd) {
	tcpRemoteAddress, err := net.ResolveTCPAddr("tcp", hostnamePort)
	if err != nil {
		panic("cant resolve remote redis address")
	}
	var ladr *net.TCPAddr
	msgBuf := make([]byte, 65000)
	initMsg := []byte("*1\r\n$4\r\nPING\r\n")
	writeChan := make(chan []byte)
	readChan := make(chan []byte)
	flushChan := make(chan int)
	go netutils.AutoRecoonectedTCP(ladr, tcpRemoteAddress, msgBuf, initMsg, writeChan, readChan, flushChan)
	<-readChan
	dataBuf := make([]byte, 0)
	dataLen := 0
	for true {
		select {
		case cmd := <-redisCmdWrite:
			switch cmd.Command {
			case "SET":
				data := RedisSet(cmd.Name, cmd.Data)
				writeChan <- data
			case "GET":
				data := RedisGet(cmd.Name)
				writeChan <- data
			}
		case response := <-readChan:
			data, dataBuf, err := ParseRedisResponse(response, dataBuf, &dataLen)
			if dataLen != 0 {
				for data == nil {
					response = <-readChan
					data, dataBuf, err = ParseRedisResponse(response, dataBuf, &dataLen)
				}
			}
			if err != nil {
				select {
				case redisCmdRead <- RedisCmd{
					Error: err,
				}:
				case <-time.After(time.Second * 5):
				}
			}
			if data != nil && string(data) != "PONG" {
				select {
				case redisCmdRead <- RedisCmd{
					Data: data,
				}:
				case <-time.After(time.Second * 5):
				}
				dataLen = 0
			}
		case <-flushChan:
			dataBuf = dataBuf[:]
			dataLen = 0
			select {
			case redisCmdRead <- RedisCmd{}:
			case <-time.After(time.Second * 5):
			}
		}
	}
}

func (sr *SimpleRedis) Init(redisHost string) {
	sr.redisHost = redisHost
	sr.redisChanWrite = make(chan RedisCmd)
	sr.redisChanRead = make(chan RedisCmd)
	go RedisContext(sr.redisHost, sr.redisChanWrite, sr.redisChanRead)
}

func (sr *SimpleRedis) Do(cmd, name string, data []byte) ([]byte, error) {
	sr.redisCmd.Command = cmd
	sr.redisCmd.Name = name
	sr.redisCmd.Data = data
	sr.redisChanWrite <- sr.redisCmd
	resp := <- sr.redisChanRead
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Data, nil
}
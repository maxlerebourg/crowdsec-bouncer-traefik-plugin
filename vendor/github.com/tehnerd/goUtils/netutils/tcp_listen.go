package netutils

import (
	"errors"
	"net"
)

/*
	we need to provide a function, which will read/write to/from socket and read/write to/from sockets feedback chans
*/
func ListenForConnection(port string, fn func(chan []byte, chan []byte, chan int, chan int)) error {
	addr := ":" + port
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return errors.New("cant resolve local tcp address")
	}
	loop := 1
	servSock, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return errors.New("cant bind to local tcp address")
	}

	for loop == 1 {
		sock, err := servSock.AcceptTCP()
		if err != nil {
			continue
		}
		go ServeTcpConn(sock, fn)
	}
	return nil
}

func ServeTcpConn(sock *net.TCPConn, fn func(chan []byte, chan []byte, chan int, chan int)) {
	readChan := make(chan []byte)
	writeChan := make(chan []byte)
	feedbackFrom := make(chan int, 1)
	feedbackTo := make(chan int, 1)
	buf := make([]byte, 65535)
	go ReadFromTCP(sock, buf, readChan, feedbackFrom)
	go WriteToTCPrw(sock, writeChan, feedbackFrom, feedbackTo)
	fn(readChan, writeChan, feedbackFrom, feedbackTo)
}

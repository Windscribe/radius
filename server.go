package radius

import (
	"net"
	"sync"
	"time"

	"github.com/function61/gokit/logex"
)

const AUTH_PORT = 1812
const ACCOUNTING_PORT = 1813

type Server struct {
	addr      string
	secret    string
	service   Service
	ch        chan struct{}
	waitGroup *sync.WaitGroup
	cl        *ClientList
}

// ServerChallenges stores the challenges sent to peers.
// The key is the EAP Identifier field
var ServerChallenges map[uint8][]byte

// PeerMSK stores the password and ntResponse of a successful challenge response for generating the MSK upon AccessAccept.
// The key is the EAP Identifier field
var PeerMSK map[uint8]map[string][]byte

type Service interface {
	RadiusHandle(request *Packet) *Packet
}

var Logger *logex.Leveled

// NewServer return a new Server given a addr, secret, and service
func NewServer(addr string, secret string, service Service, logger *logex.Leveled) *Server {

	Logger = logger

	// init EAP state vars
	ServerChallenges = map[uint8][]byte{}
	PeerMSK = map[uint8]map[string][]byte{}

	s := &Server{addr: addr,
		secret:    secret,
		service:   service,
		ch:        make(chan struct{}),
		waitGroup: &sync.WaitGroup{},
	}
	return s
}

// WithClientList set a list of clients that have it's own secret
func (s *Server) WithClientList(cl *ClientList) {
	s.cl = cl
}

// ListenAndServe listen on the UDP network address
func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		select {
		case <-s.ch:
			return nil
		default:
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			return err
		}

		s.waitGroup.Add(1)
		go func(p []byte, addr net.Addr) {
			defer s.waitGroup.Done()
			var secret = s.secret

			if s.cl != nil {
				host, _, err := net.SplitHostPort(addr.String())
				if err != nil {
					Logger.Error.Println("net.SplitHostPort: ", err)
					return
				}
				if cl := s.cl.Get(host); cl != nil {
					secret = cl.GetSecret()
				}
			}

			pac, err := DecodePacket(secret, p)
			if err != nil {
				Logger.Error.Println("DecodePacket: ", err)
				return
			}
			pac.ClientAddr = addr.String()

			npac := s.service.RadiusHandle(pac)
			err = npac.Send(conn, addr)
			if err != nil {
				Logger.Error.Println("npac.Send: ", err)
			}
		}(b[:n], addr)
	}
}

// Stop will stop the server
func (s *Server) Stop() {
	close(s.ch)
	s.waitGroup.Wait()
}

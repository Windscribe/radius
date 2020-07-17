package radius

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
)

type MsChapV2ChallengePacket struct {
	Challenge []byte
	Name      []byte
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (c *MsChapV2ChallengePacket) GenerateChallenge(pID uint8, nasID string) {
	//TODO handle error
	challenge, _ := randomHex(16)
	// Save the challenge to verify the response
	ServerChallenges[pID] = challenge
	c.Challenge = []byte(challenge)
	c.Name = []byte(nasID)
}

func (c *MsChapV2ChallengePacket) Encode() []byte {
	return append(c.Challenge, c.Name...)
}

type MsChapV2Packet struct {
	Eap    *EapPacket //解密的时候的eap信息,不使用里面的data
	OpCode MsChapV2OpCode
	Data   []byte
}

func (p *MsChapV2Packet) Encode() (b []byte) {
	b = make([]byte, len(p.Data)+4)
	b[0] = byte(p.OpCode)
	b[1] = byte(p.Eap.Identifier)
	length := uint16(len(b))
	binary.BigEndian.PutUint16(b[2:4], length)
	copy(b[4:], p.Data)
	return b
}

func MsChapV2PacketFromEap(eap *EapPacket) (p *MsChapV2Packet, err error) {
	p = &MsChapV2Packet{
		Eap: eap,
	}
	if len(eap.Data) < 4 {
		return nil, fmt.Errorf("[MsChapV2PacketFromEap] protocol error 1, packet too small")
	}
	p.OpCode = MsChapV2OpCode(eap.Data[0])
	p.Data = append([]byte(nil), eap.Data[4:]...)
	return p, nil
}

//不包括eap的信息
func (p *MsChapV2Packet) String() string {
	return fmt.Sprintf("OpCode:%s Data:[%#v]", p.OpCode, p.Data)
}

type MsChapV2OpCode uint8

const (
	MsChapV2OpCodeChallenge      MsChapV2OpCode = 1
	MsChapV2OpCodeResponse       MsChapV2OpCode = 2
	MsChapV2OpCodeSuccess        MsChapV2OpCode = 3
	MsChapV2OpCodeFailure        MsChapV2OpCode = 4
	MsChapV2OpCodeChangePassword MsChapV2OpCode = 7
)

func (c MsChapV2OpCode) String() string {
	switch c {
	case MsChapV2OpCodeChallenge:
		return "Challenge"
	case MsChapV2OpCodeResponse:
		return "Response"
	case MsChapV2OpCodeSuccess:
		return "Success"
	case MsChapV2OpCodeFailure:
		return "Failure"
	case MsChapV2OpCodeChangePassword:
		return "ChangePassword"
	default:
		return "unknow MsChapV2OpCode " + strconv.Itoa(int(c))
	}
}

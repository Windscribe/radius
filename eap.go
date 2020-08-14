package radius

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// ietf docs:
// Code
//    1 - Request
//    2 - Response

type EapCode uint8

const (
	EapCodeRequest  EapCode = 1
	EapCodeResponse EapCode = 2
)

func (c EapCode) String() string {
	switch c {
	case EapCodeRequest:
		return "Request"
	case EapCodeResponse:
		return "Response"
	default:
		return "unknow EapCode " + strconv.Itoa(int(c))
	}
}

// OpCode
//    The OpCode field is one octet and identifies the type of EAP MS-CHAP-
//    v2 packet.  OpCodes are assigned as follows:
//    1       Challenge
//    2       Response
//    3       Success
//    4       Failure
//    7       Change-Password

type EapOpCode uint8

const (
	EapOpCodeChallenge      EapOpCode = 1
	EapOpCodeResponse       EapOpCode = 2
	EapOpCodeSuccess        EapOpCode = 3
	EapOpCodeFailure        EapOpCode = 4
	EapOpCodeChangePassword EapOpCode = 7
)

func (c EapOpCode) String() string {
	switch c {
	case EapOpCodeChallenge:
		return "Challenge"
	case EapOpCodeResponse:
		return "Response"
	case EapOpCodeSuccess:
		return "Success"
	case EapOpCodeFailure:
		return "Failure"
	case EapOpCodeChangePassword:
		return "Change-Password"
	default:
		return "unknow EapCode " + strconv.Itoa(int(c))
	}
}

type EapType uint8

const (
	EapTypeIdentity         EapType = 1
	EapTypeNotification     EapType = 2
	EapTypeNak              EapType = 3 //Response only
	EapTypeMd5Challenge     EapType = 4
	EapTypeOneTimePassword  EapType = 5 //otp
	EapTypeGenericTokenCard EapType = 6 //gtc
	EapTypeMSCHAPV2         EapType = 26
	EapTypeExpandedTypes    EapType = 254
	EapTypeExperimentalUse  EapType = 255
)

func (c EapType) String() string {
	switch c {
	case EapTypeIdentity:
		return "Identity"
	case EapTypeNotification:
		return "Notification"
	case EapTypeNak:
		return "Nak"
	case EapTypeMd5Challenge:
		return "Md5Challenge"
	case EapTypeOneTimePassword:
		return "OneTimePassword"
	case EapTypeGenericTokenCard:
		return "GenericTokenCard"
	case EapTypeMSCHAPV2:
		return "MSCHAPV2"
	case EapTypeExpandedTypes:
		return "ExpandedTypes"
	case EapTypeExperimentalUse:
		return "ExperimentalUse"
	default:
		return "unknow EapType " + strconv.Itoa(int(c))
	}
}

type EapPacket struct {
	Code       EapCode
	Identifier uint8
	Type       EapType
	Data       []byte
	OpCode     MsChapV2OpCode
}

func (a *EapPacket) String() string {
	return fmt.Sprintf("Eap Code:%s id:%d Type:%s Data:[%s]", a.Code.String(), a.Identifier, a.Type.String(), string(a.Data))
}

func (a *EapPacket) DecodeMsChapV2() (*MsChapV2Packet, error) {
	return MsChapV2PacketFromEap(a)
}

func (a *EapPacket) Copy() *EapPacket {
	eap := *a
	eap.Data = append([]byte(nil), a.Data...)
	return &eap
}

func (a *EapPacket) Encode() (b []byte) {
	b = make([]byte, len(a.Data)+5)
	b[0] = byte(a.Code)
	b[1] = byte(a.Identifier)
	length := uint16(len(b))
	binary.BigEndian.PutUint16(b[2:4], length)
	b[4] = byte(a.Type)
	if a.OpCode == MsChapV2OpCodeSuccess {
		//The MS-Length field is two octets and MUST be set to the value of the Length field minus 5.
		a.Data[3] = b[3] - 5
	}
	copy(b[5:], a.Data)
	return b
}

func EapDecode(b []byte) (eap *EapPacket, err error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("[EapDecode] protocol error input too small")
	}
	length := binary.BigEndian.Uint16(b[2:4])
	if len(b) < int(length) {
		return nil, fmt.Errorf("[EapDecode] protocol error input too length does not match header")
	}
	eap = &EapPacket{
		Code:       EapCode(b[0]),
		Identifier: uint8(b[1]),
		Type:       EapType(b[4]),
		Data:       b[5:length],
	}
	return eap, nil
}

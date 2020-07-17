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
	OpCode     EapOpCode
	Data       []byte
}

func (a *EapPacket) String() string {
	return fmt.Sprintf("Eap Code:%s id:%d Type:%s Data:[%s]", a.Code.String(), a.Identifier, a.Type.String(), string(a.Data))
}

func (a *EapPacket) valueString() string {
	switch a.Type {
	case EapTypeIdentity:
		return fmt.Sprintf("%s", string(a.Data)) //应该是字符串,但是也有可能被搞错
	case EapTypeMSCHAPV2:
		mcv, err := MsChapV2PacketFromEap(a)
		if err != nil {
			return err.Error()
		}
		return mcv.String()
	}
	return fmt.Sprintf("%#v", a.Data)
}

func (a *EapPacket) Copy() *EapPacket {
	eap := *a
	eap.Data = append([]byte(nil), a.Data...)
	return &eap
}

func (a *EapPacket) Encode() (b []byte) {
	// 	The Length field is two octets and indicates the length of the EAP
	//  packet including the Code (1), Identifier (1), Length (2), Type (1), OpCode (1), MS-
	//  CHAPv2-ID (1), MS-Length (2) and Data (x) fields
	b = make([]byte, len(a.Data)+9)
	b[0] = byte(a.Code)
	b[1] = byte(a.Identifier)
	length := uint16(len(b))
	binary.BigEndian.PutUint16(b[2:4], length)
	b[4] = byte(a.Type)
	b[5] = byte(a.OpCode)
	b[6] = byte(a.Identifier)                    // MS-CHAPv2-ID
	binary.BigEndian.PutUint16(b[7:9], length-5) // MS-Length
	// The MS-Length field is two octets and MUST be set to the value of the
	// Length field minus 5.
	copy(b[9:], a.Data)
	return b
}

func (a *EapPacket) ToEAPMessage() *AVP {
	return &AVP{
		Type:  EAPMessage,
		Value: a.Encode(),
	}
}

func EapDecode(b []byte) (eap *EapPacket, err error) {
	if len(b) < 9 {
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
		OpCode:     EapOpCode(b[5]),
		Data:       b[9:length],
	}
	return eap, nil
}

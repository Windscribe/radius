package radius

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/md4"
)

// MsChapV2ChallengePacket is sent after the Identity Request
type MsChapV2ChallengePacket struct {
	Challenge []byte
	Name      []byte
}

// MsChapV2ChallengePacket is sent after the Identity Request
type MsChapV2SuccessPacket struct {
	Message []byte
}

// MsCHapV2ResponsePacket is received as a response to the Challenge packet
type MsCHapV2ResponsePacket struct {
	PeerChallenge []byte // 16 bytes
	NTResponse    []byte // 24 bytes
}

// DecodeMsChapV2Response parses the EAP Message data for the peer-challenge and ntresponse
func DecodeMsChapV2Response(data []byte) MsCHapV2ResponsePacket {
	return MsCHapV2ResponsePacket{
		PeerChallenge: data[0:16],
		NTResponse:    data[24:48],
	}
}

// CheckResponseValidity returns true is the resonse is valid, false if its not
func CheckResponseValidity(response, AuthenticatorChallenge, PeerChallenge []byte, username, password string) bool {
	// The NT-Response field is an encoded function of the password, the
	// Name field of the Response packet, the contents of the Peer-Challenge
	// field and the received Challenge as output by the routine
	// GenerateNTResponse() defined in  [RFC2759], Section 8.1.
	fmt.Printf("[VALIDATE] response: %#v\n", response)
	check := GenerateNTResponse(AuthenticatorChallenge, PeerChallenge, username, password)
	fmt.Printf("[VALIDATE] calculated: %#v\n", check)
	if bytes.Compare(response, check) == 0 {
		return true
	}
	return false
}

// ChallengeHash (
// 	IN 16-octet               PeerChallenge,
// 	IN 16-octet               AuthenticatorChallenge,
// 	IN  0-to-256-char         UserName,
// 	OUT 8-octet               Challenge
// 	{
// 	   /*
// 		* SHAInit(), SHAUpdate() and SHAFinal() functions are an
// 		* implementation of Secure Hash Algorithm (SHA-1) [11]. These are
// 		* available in public domain or can be licensed from
// 		* RSA Data Security, Inc.
// 		*/
// 	   SHAInit(Context)
// 	   SHAUpdate(Context, PeerChallenge, 16)
// 	   SHAUpdate(Context, AuthenticatorChallenge, 16)
// 	   /*
// 		* Only the user name (as presented by the peer and
// 		* excluding any prepended domain name)
// 		* is used as input to SHAUpdate().
// 		*/
// 	   SHAUpdate(Context, UserName, strlen(Username))
// 	   SHAFinal(Context, Digest)
// 	   memcpy(Challenge, Digest, 8)
// 	}
func ChallengeHash(PeerChallenge, AuthenticatorChallenge []byte, username string) []byte {
	h := sha1.New()
	h.Write(PeerChallenge)
	h.Write(AuthenticatorChallenge)
	io.WriteString(h, username)
	hash := h.Sum(nil)
	return hash[0:8]
}

// NtPasswordHash (
// 	IN  0-to-256-unicode-char Password,
// 	OUT 16-octet              PasswordHash )
// 	{
// 	   /*
// 		* Use the MD4 algorithm [5] to irreversibly hash Password
// 		* into PasswordHash.  Only the password is hashed without
// 		* including any terminating 0.
// 		*/
// 	}
func NtPasswordHash(password string) []byte {
	h := md4.New()
	io.WriteString(h, password)
	return h.Sum(nil)
}

// ChallengeResponse (
// 	IN  8-octet  Challenge,
// 	IN  16-octet PasswordHash,
// 	OUT 24-octet Response )
// 	{
// 	   Set ZPasswordHash to PasswordHash zero-padded to 21 octets
// 	   DesEncrypt( Challenge,
// 				   1st 7-octets of ZPasswordHash,
// 				   giving 1st 8-octets of Response )
// 	   DesEncrypt( Challenge,
// 				   2nd 7-octets of ZPasswordHash,
// 				   giving 2nd 8-octets of Response )
// 	   DesEncrypt( Challenge,
// 				   3rd 7-octets of ZPasswordHash,
// 				   giving 3rd 8-octets of Response )
// 	}
func ChallengeResponse(challenge, passwordHash []byte) []byte {
	ZPasswordHash := zeroPadding(passwordHash, 21)
	part1, _ := DesEncrypt(challenge, ZPasswordHash[0:7])
	part2, _ := DesEncrypt(challenge, ZPasswordHash[7:14])
	part3, _ := DesEncrypt(challenge, ZPasswordHash[14:21])
	response := make([]byte, 24)
	response = append(response, part1...)
	response = append(response, part2...)
	response = append(response, part3...)
	return response
}

// GenerateNTResponse (
// 	IN  16-octet              AuthenticatorChallenge,
// 	IN  16-octet              PeerChallenge,
// 	IN  0-to-256-char         UserName,
// 	IN  0-to-256-unicode-char Password,
// 	OUT 24-octet              Response )
// 	{
// 	   8-octet  Challenge
// 	   16-octet PasswordHash
// 	   ChallengeHash( PeerChallenge, AuthenticatorChallenge, UserName,
// 					  giving Challenge)
// 	   NtPasswordHash( Password, giving PasswordHash )
// 	   ChallengeResponse( Challenge, PasswordHash, giving Response )
// 	}
func GenerateNTResponse(AuthenticatorChallenge, PeerChallenge []byte, username, password string) []byte {
	challenge := ChallengeHash(PeerChallenge, AuthenticatorChallenge, username)
	passwordHash := NtPasswordHash(password)
	return ChallengeResponse(challenge, passwordHash)
}

// GenerateAuthenticatorResponse (
// 	IN  0-to-256-unicode-char Password,
// 	IN  24-octet              NT-Response,
// 	IN  16-octet              PeerChallenge,
// 	IN  16-octet              AuthenticatorChallenge,
// 	IN  0-to-256-char         UserName,
// 	OUT 42-octet              AuthenticatorResponse )
// 	{
// 	   16-octet              PasswordHash
// 	   16-octet              PasswordHashHash
// 	   8-octet               Challenge
// 	   /*
// 		* "Magic" constants used in response generation
// 		*/
// 	   Magic1[39] =
// 		  {0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
// 		   0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
// 		   0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
// 		   0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};
// 	   Magic2[41] =
// 		   {0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
// 			0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
// 			0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
// 			0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
// 			0x6E};
// 		/*
// 		 * Hash the password with MD4
// 		 */
// 		NtPasswordHash( Password, giving PasswordHash )
// 		/*
// 		 * Now hash the hash
// 		 */
//
// 		HashNtPasswordHash( PasswordHash, giving PasswordHashHash)
//
// 		SHAInit(Context)
// 		SHAUpdate(Context, PasswordHashHash, 16)
// 		SHAUpdate(Context, NTResponse, 24)
// 		SHAUpdate(Context, Magic1, 39)
// 		SHAFinal(Context, Digest)
//
// 		ChallengeHash( PeerChallenge, AuthenticatorChallenge, UserName,
// 					   giving Challenge)
//
// 		SHAInit(Context)
// 		SHAUpdate(Context, Digest, 20)
// 		SHAUpdate(Context, Challenge, 8)
// 		SHAUpdate(Context, Magic2, 41)
// 		SHAFinal(Context, Digest)
//
// 		/*
// 		 * Encode the value of 'Digest' as "S=" followed by
// 		 * 40 ASCII hexadecimal digits and return it in
// 		 * AuthenticatorResponse.
// 		 * For example,
// 		 *   "S=0123456789ABCDEF0123456789ABCDEF01234567"
// 		 */
// 	 }
func GenerateAuthenticatorResponse(PasswordHash, NTResponse, PeerChallenge, AuthenticatorChallenge []byte, username string) string {

	Magic1 := []byte{0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
		0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
		0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
		0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74}

	Magic2 := []byte{0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
		0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
		0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
		0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
		0x6E}

	PasswordHashHash := NtPasswordHash(string(PasswordHash))

	h := sha1.New()
	h.Write(PasswordHashHash)
	h.Write(NTResponse)
	h.Write(Magic1)
	digest := h.Sum(nil)

	challenge := ChallengeHash(PeerChallenge, AuthenticatorChallenge, username)

	h2 := sha1.New()
	h2.Write(digest)
	h2.Write(challenge)
	h2.Write(Magic2)
	final := h2.Sum(nil)
	return fmt.Sprintf("S=%X", final)
}

// DesEncrypt (
// 	IN  8-octet Clear,
// 	IN  7-octet Key,
// 	OUT 8-octet Cypher )
// 	{
// 	   /*
// 		* Use the DES encryption algorithm [4] in ECB mode [10]
// 		* to encrypt Clear into Cypher such that Cypher can
// 		* only be decrypted back to Clear by providing Key.
// 		* Note that the DES algorithm takes as input a 64-bit
// 		* stream where the 8th, 16th, 24th, etc.  bits are
// 		* parity bits ignored by the encrypting algorithm.
// 		* Unless you write your own DES to accept 56-bit input
// 		* without parity, you will need to insert the parity bits
// 		* yourself.
// 		*/
// 	}
// Implementation from : https://gist.github.com/cuixin/10612934
func DesEncrypt(src, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	src = zeroPadding(src, bs)
	// src = PKCS5Padding(src, bs)
	if len(src)%bs != 0 {
		return nil, errors.New("Need a multiple of the blocksize")
	}
	out := make([]byte, len(src))
	dst := out
	for len(src) > 0 {
		block.Encrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

func zeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func randomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return bytes, err
	}
	return bytes, nil
}

func (c *MsChapV2ChallengePacket) GenerateChallenge(pID uint8, nasID string) {
	//TODO handle error
	challenge, _ := randomBytes(16)
	// Save the challenge to verify the response
	ServerChallenges[pID] = challenge
	c.Challenge = []byte(challenge)
	c.Name = []byte(nasID)
}

func (c *MsChapV2ChallengePacket) Encode() []byte {
	// Microsoft authenticators do not currently provide information in the Name field.  This may change in the future.
	// return append(c.Challenge, c.Name...)
	return c.Challenge
}

func (c *MsChapV2SuccessPacket) Encode() []byte {
	return c.Message
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

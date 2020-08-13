package radius

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strconv"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// MsChapV2ChallengePacket is sent after the Identity Request
type MsChapV2ChallengePacket struct {
	Challenge []byte
	Name      []byte
}

// MsCHapV2ResponsePacket is received as a response to the Challenge packet
type MsCHapV2ResponsePacket struct {
	PeerChallenge []byte // 16 bytes
	NTResponse    []byte // 24 bytes
}

// DecodeMsChapV2Response parses the EAP Message data for the peer-challenge and ntresponse
func DecodeMsChapV2Response(data []byte) MsCHapV2ResponsePacket {
	return MsCHapV2ResponsePacket{
		PeerChallenge: data[5:21],
		NTResponse:    data[29:53],
	}
}

// NTPassword Converts pass to UCS-2 (UTF-16)
func NTPassword(pass string) []byte {
	buf := utf16.Encode([]rune(pass))
	enc := make([]byte, len(pass)*2)
	for i := 0; i < len(pass); i++ {
		pos := 2 * i
		binary.LittleEndian.PutUint16(enc[pos:pos+2], buf[i])
	}
	return enc
}

// CheckResponseValidity returns true is the resonse is valid, false if its not
func CheckResponseValidity(response, AuthenticatorChallenge, PeerChallenge []byte, username string, password []byte) bool {
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
func ChallengeHash(PeerChallenge, AuthenticatorChallenge, username []byte) []byte {
	h := sha1.New()
	h.Write(PeerChallenge)
	h.Write(AuthenticatorChallenge)
	h.Write(username)
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
func NtPasswordHash(password []byte) []byte {
	h := md4.New()
	h.Write(password)
	return h.Sum(nil)
}

// DES uses 56-bit keys, expanded to 64 bits by the insertion of parity
// bits.  After the parity of the key has been fixed, every eighth bit
// is a parity bit and the number of bits that are set (1) in each octet
// is odd; i.e., odd parity.  Note that many DES engines do not check
// parity, however, simply stripping the parity bits.
func strToKey(str []byte) []byte {
	key := make([]byte, 8)
	key[0] = str[0] >> 1
	key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2)
	key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3)
	key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4)
	key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5)
	key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6)
	key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7)
	key[7] = str[6] & 0x7F

	for i := 0; i < 8; i++ {
		key[i] = (key[i] << 1)
	}
	return key
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
	fmt.Printf("ChallengeResponse: ZPasswordHash = %+v\n", ZPasswordHash)

	response := make([]byte, 24)

	{
		block, e := des.NewCipher(strToKey(ZPasswordHash[:7]))
		if e != nil {
			fmt.Printf("ChallengeResponse: err = %+v\n", e)
			return nil
		}
		mode := newECBEncrypter(block)
		mode.CryptBlocks(response, challenge)
	}

	{
		block, e := des.NewCipher(strToKey(ZPasswordHash[7:14]))
		if e != nil {
			fmt.Printf("ChallengeResponse: err = %+v\n", e)
			return nil
		}
		mode := newECBEncrypter(block)
		mode.CryptBlocks(response[8:], challenge)
	}

	{
		block, e := des.NewCipher(strToKey(ZPasswordHash[14:21]))
		if e != nil {
			fmt.Printf("ChallengeResponse: err = %+v\n", e)
			return nil
		}
		mode := newECBEncrypter(block)
		mode.CryptBlocks(response[16:], challenge)
	}

	fmt.Printf("ChallengeResponse: response = %+v\n", response)
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
func GenerateNTResponse(AuthenticatorChallenge, PeerChallenge []byte, username string, passwordHash []byte) []byte {
	challenge := ChallengeHash(PeerChallenge, AuthenticatorChallenge, []byte(username))
	fmt.Printf("GenerateNTResponse: challenge = %+v\n", challenge)
	fmt.Printf("GenerateNTResponse: passwordHash = %+v\n", passwordHash)
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

	Magic1 := []byte{
		0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
		0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
		0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
		0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74,
	}

	Magic2 := []byte{
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
		0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
		0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
		0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
		0x6E,
	}

	PasswordHashHash := NtPasswordHash(PasswordHash)

	h := sha1.New()
	h.Write(PasswordHashHash)
	h.Write(NTResponse)
	h.Write(Magic1)
	digest := h.Sum(nil)

	fmt.Printf("Success DEBUG: %+v\n", len(digest))

	challenge := ChallengeHash(PeerChallenge, AuthenticatorChallenge, []byte(username))

	h2 := sha1.New()
	h2.Write(digest)
	h2.Write(challenge)
	h2.Write(Magic2)
	final := h2.Sum(nil)
	return fmt.Sprintf("S=%X", final)
}

func zeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func RandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return bytes, err
	}
	return bytes, nil
}

func NextIdentifier() uint8 {
	//TODO: add a lock on ServerChallenges
	nextID := uint8(len(ServerChallenges)) + 1
	if nextID > 255 {
		nextID = 1
	}
	return nextID
}

func (c *MsChapV2ChallengePacket) GenerateChallenge(nasID string) uint8 {
	//TODO handle error
	identifier := NextIdentifier()
	challenge, _ := RandomBytes(16)
	// Save the challenge to verify the response
	ServerChallenges[identifier] = challenge
	c.Challenge = []byte(challenge)
	c.Name = []byte(nasID)
	return identifier
}

func (c *MsChapV2ChallengePacket) Encode() []byte {
	return append(c.Challenge, c.Name...)
}

type MsChapV2Packet struct {
	Eap    *EapPacket
	OpCode MsChapV2OpCode
	Data   []byte
}

func (p *MsChapV2Packet) Encode() (b []byte) {
	b = make([]byte, len(p.Data)+5)
	b[0] = byte(p.OpCode)
	b[1] = byte(p.Eap.Identifier)
	length := uint16(len(b))
	binary.BigEndian.PutUint16(b[2:4], length)
	b[4] = uint8(len(p.Data))
	if p.OpCode == MsChapV2OpCodeChallenge {
		b[4] = uint8(16)
	}
	copy(b[5:], p.Data)
	return b
}

type MsChapV2SuccessPacket struct {
	Eap    *EapPacket
	OpCode MsChapV2OpCode
	Data   []byte
}

func (p *MsChapV2SuccessPacket) Encode() (b []byte) {
	b = make([]byte, len(p.Data)+4)
	b[0] = byte(p.OpCode)
	// Here we revert the Identifier field to the previous value, since the EAP identifier was incremented
	// Without this, Windows clients do not work (throw 691 error)
	// The RFC does not seem to explain why this would be needed: https://tools.ietf.org/id/draft-kamath-pppext-eap-mschapv2-01.txt
	// 	The MS-CHAPv2-ID field is one octet and aids in matching MSCHAP-v2
	//  responses with requests.  Typically, the MS-CHAPv2-ID field is the
	//  same as the Identifier field.
	b[1] = byte(p.Eap.Identifier - 1)
	length := uint16(len(p.Data))
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

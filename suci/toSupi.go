package suci

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/bits"
	"strings"

	"github.com/Nikhil690/util_3gpp/logger"
	"golang.org/x/crypto/curve25519"

	"github.com/cloudflare/circl/kem"
)

// profile A.
const ProfileAMacKeyLen = 32 // octets
const ProfileAEncKeyLen = 16 // octets
const ProfileAIcbLen = 16    // octets
const ProfileAMacLen = 8     // octets
const ProfileAHashLen = 32   // octets

// profile B.
const ProfileBMacKeyLen = 32 // octets
const ProfileBEncKeyLen = 16 // octets
const ProfileBIcbLen = 16    // octets
const ProfileBMacLen = 8     // octets
const ProfileBHashLen = 32   // octets

// profile C
const ProfileCMacKeyLen = 32 // octets
const ProfileCEncKeyLen = 16 // octets
const ProfileCIcbLen = 16    // octets
const ProfileCMacLen = 8     // octets
const ProfileCHashLen = 32   // octets

func hexStringToBytes(hexStr string) ([]byte, error) {
	// Decode the hex string into a byte slice
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %v", err)
	}
	return bytes, nil
}

func decapsulate(privateKey string, cipherText []byte, scheme kem.Scheme) ([]byte, error) {

	//client already has the private key so not needed. https://github.com/open-quantum-safe/liboqs-go/blob/main/oqs/oqs.go#L214

	// sharedSecret, err := oqs_client.DecapSecret(cipherText) // returns a byte slice, thank god!
	// if err != nil {
	// 	log.Fatal(err)
	// 	return []byte{0}, err
	// }

	// return sharedSecret, nil

	bytes_priv_key, err := hexStringToBytes(privateKey)
	if err != nil {
		return nil, fmt.Errorf("Error during decapsulation, %s", err)
	}

	privateKey_, _ := scheme.UnmarshalBinaryPrivateKey(bytes_priv_key)

	return scheme.Decapsulate(privateKey_, cipherText)

}

func CompressKey(uncompressed []byte, y *big.Int) []byte {
	compressed := uncompressed[0:33]
	if y.Bit(0) == 1 { // 0x03
		compressed[0] = 0x03
	} else { // 0x02
		compressed[0] = 0x02
	}
	// fmt.Printf("compressed: %x\n", compressed)
	return compressed
}

// modified from https://stackoverflow.com/questions/46283760/
// how-to-uncompress-a-single-x9-62-compressed-point-on-an-ecdh-p256-curve-in-go.
func uncompressKey(compressedBytes []byte, priv []byte) (*big.Int, *big.Int) {
	// Split the sign byte from the rest
	signByte := uint(compressedBytes[0])
	xBytes := compressedBytes[1:]

	x := new(big.Int).SetBytes(xBytes)
	three := big.NewInt(3)

	// The params for P256
	c := elliptic.P256().Params()

	// The equation is y^2 = x^3 - 3x + b
	// x^3, mod P
	xCubed := new(big.Int).Exp(x, three, c.P)

	// 3x, mod P
	threeX := new(big.Int).Mul(x, three)
	threeX.Mod(threeX, c.P)

	// x^3 - 3x + b mod P
	ySquared := new(big.Int).Sub(xCubed, threeX)
	ySquared.Add(ySquared, c.B)
	ySquared.Mod(ySquared, c.P)

	// find the square root mod P
	y := new(big.Int).ModSqrt(ySquared, c.P)
	if y == nil {
		// If this happens then you're dealing with an invalid point.
		logger.Util3GPPLog.Errorln("Uncompressed key with invalid point")
		return nil, nil
	}

	// Finally, check if you have the correct root. If not you want -y mod P
	if y.Bit(0) != signByte&1 {
		y.Neg(y)
		y.Mod(y, c.P)
	}
	// fmt.Printf("xUncom: %x\nyUncon: %x\n", x, y)
	return x, y
}

func HmacSha256(input, macKey []byte, macLen int) []byte {
	h := hmac.New(sha256.New, macKey)
	if _, err := h.Write(input); err != nil {
		log.Printf("HMAC SHA256 error %+v", err)
	}
	macVal := h.Sum(nil)
	macTag := macVal[:macLen]
	// fmt.Printf("macVal: %x\nmacTag: %x\n", macVal, macTag)
	return macTag
}

func Aes128ctr(input, encKey, icb []byte) []byte {
	output := make([]byte, len(input))
	block, err := aes.NewCipher(encKey)
	if err != nil {
		log.Printf("AES128 CTR error %+v", err)
	}
	stream := cipher.NewCTR(block, icb)
	stream.XORKeyStream(output, input)
	// fmt.Printf("aes input: %x %x %x\naes output: %x\n", input, encKey, icb, output)
	return output
}

func AnsiX963KDF(sharedKey, publicKey []byte, profileEncKeyLen, profileMacKeyLen, profileHashLen int) []byte {
	var counter uint32 = 0x00000001
	var kdfKey []byte
	kdfRounds := int(math.Ceil(float64(profileEncKeyLen+profileMacKeyLen) / float64(profileHashLen)))
	for i := 1; i <= kdfRounds; i++ {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		// fmt.Printf("counterBytes: %x\n", counterBytes)
		tmpK := sha256.Sum256(append(append(sharedKey, counterBytes...), publicKey...))
		sliceK := tmpK[:]
		kdfKey = append(kdfKey, sliceK...)
		// fmt.Printf("kdfKey in round %d: %x\n", i, kdfKey)
		counter++
	}
	return kdfKey
}

func swapNibbles(input []byte) []byte {
	output := make([]byte, len(input))
	for i, b := range input {
		output[i] = bits.RotateLeft8(b, 4)
	}
	return output
}

func calcSchemeResult(decryptPlainText []byte, supiType string) string {
	var schemeResult string
	if supiType == typeIMSI {
		schemeResult = hex.EncodeToString(swapNibbles(decryptPlainText))
		if schemeResult[len(schemeResult)-1] == 'f' {
			schemeResult = schemeResult[:len(schemeResult)-1]
		}
	} else {
		schemeResult = hex.EncodeToString(decryptPlainText)
	}
	return schemeResult
}

func profileA(input, supiType, privateKey string) (string, error) {

	logger.Util3GPPLog.Infoln("SuciToSupi Profile A")
	s, hexDecodeErr := hex.DecodeString(input)
	if hexDecodeErr != nil {
		logger.Util3GPPLog.Errorln("hex DecodeString error")
		return "", hexDecodeErr
	}

	// for X25519(profile A), q (The number of elements in the field Fq) = 2^255 - 19
	// len(pubkey) is therefore ceil((log2q)/8+1) = 32octets

	ProfileAPubKeyLen := 32
	if len(s) < ProfileAPubKeyLen+ProfileAMacLen {
		logger.Util3GPPLog.Errorln("len of input data is too short!")
		return "", fmt.Errorf("suci input too short\n")
	}

	decryptMac := s[len(s)-ProfileAMacLen:]
	decryptPublicKey := s[:ProfileAPubKeyLen]
	decryptCipherText := s[ProfileAPubKeyLen : len(s)-ProfileAMacLen] //here cipher text: concealed MSIN

	// fmt.Printf("dePub: %x\ndeCiph: %x\ndeMac: %x\n", decryptPublicKey, decryptCipherText, decryptMac)

	// test data from TS33.501 Annex C.4
	// aHNPriv, _ := hex.DecodeString("c53c2208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d")

	var aHNPriv []byte
	if aHNPrivTmp, err := hex.DecodeString(privateKey); err != nil {
		log.Printf("Decode error: %+v", err)
	} else {
		aHNPriv = aHNPrivTmp
	}
	var decryptSharedKey []byte //symmetric key for encryption.
	if decryptSharedKeyTmp, err := curve25519.X25519(aHNPriv, []byte(decryptPublicKey)); err != nil {
		log.Printf("X25519 error: %+v", err)
	} else {
		decryptSharedKey = decryptSharedKeyTmp
	}
	// fmt.Printf("deShared: %x\n", decryptSharedKey)

	kdfKey := AnsiX963KDF(decryptSharedKey, decryptPublicKey, ProfileAEncKeyLen, ProfileAMacKeyLen, ProfileAHashLen)
	decryptEncKey := kdfKey[:ProfileAEncKeyLen]
	decryptIcb := kdfKey[ProfileAEncKeyLen : ProfileAEncKeyLen+ProfileAIcbLen]
	decryptMacKey := kdfKey[len(kdfKey)-ProfileAMacKeyLen:]
	// fmt.Printf("\ndeEncKey(size%d): %x\ndeMacKey: %x\ndeIcb: %x\n", len(decryptEncKey), decryptEncKey, decryptMacKey,
	// decryptIcb)

	decryptMacTag := HmacSha256(decryptCipherText, decryptMacKey, ProfileAMacLen)
	if bytes.Equal(decryptMacTag, decryptMac) {
		logger.Util3GPPLog.Infoln("decryption MAC match")
	} else {
		logger.Util3GPPLog.Errorln("decryption MAC failed")
		return "", fmt.Errorf("decryption MAC failed\n")
	}

	decryptPlainText := Aes128ctr(decryptCipherText, decryptEncKey, decryptIcb)

	return calcSchemeResult(decryptPlainText, supiType), nil
}

func profileB(input, supiType, privateKey string) (string, error) {

	logger.Util3GPPLog.Infoln("SuciToSupi Profile B")

	s, hexDecodeErr := hex.DecodeString(input)
	if hexDecodeErr != nil {
		logger.Util3GPPLog.Errorln("hex DecodeString error")
		return "", hexDecodeErr
	}

	var ProfileBPubKeyLen int // p256, module q = 2^256 - 2^224 + 2^192 + 2^96 - 1
	var uncompressed bool
	if s[0] == 0x02 || s[0] == 0x03 {
		ProfileBPubKeyLen = 33 // ceil(log(2, q)/8) + 1 = 33
		uncompressed = false
	} else if s[0] == 0x04 {
		ProfileBPubKeyLen = 65 // 2*ceil(log(2, q)/8) + 1 = 65
		uncompressed = true
	} else {
		logger.Util3GPPLog.Errorln("input error")
		return "", fmt.Errorf("suci input error\n")
	}

	// fmt.Printf("len:%d %d\n", len(s), ProfileBPubKeyLen + ProfileBMacLen)
	if len(s) < ProfileBPubKeyLen+ProfileBMacLen {
		logger.Util3GPPLog.Errorln("len of input data is too short!")
		return "", fmt.Errorf("suci input too short\n")
	}
	decryptPublicKey := s[:ProfileBPubKeyLen]
	decryptMac := s[len(s)-ProfileBMacLen:]
	decryptCipherText := s[ProfileBPubKeyLen : len(s)-ProfileBMacLen]
	// fmt.Printf("dePub: %x\ndeCiph: %x\ndeMac: %x\n", decryptPublicKey, decryptCipherText, decryptMac)

	// test data from TS33.501 Annex C.4
	// bHNPriv, _ := hex.DecodeString("F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA")
	var bHNPriv []byte
	if bHNPrivTmp, err := hex.DecodeString(privateKey); err != nil {
		log.Printf("Decode error: %+v", err)
	} else {
		bHNPriv = bHNPrivTmp
	}

	var xUncompressed, yUncompressed *big.Int
	if uncompressed {
		xUncompressed = new(big.Int).SetBytes(decryptPublicKey[1:(ProfileBPubKeyLen/2 + 1)])
		yUncompressed = new(big.Int).SetBytes(decryptPublicKey[(ProfileBPubKeyLen/2 + 1):])
	} else {
		xUncompressed, yUncompressed = uncompressKey(decryptPublicKey, bHNPriv)
		if xUncompressed == nil || yUncompressed == nil {
			logger.Util3GPPLog.Errorln("Uncompressed key has invalid point")
			return "", fmt.Errorf("Key uncompression error\n")
		}
	}

	// x-coordinate is the shared key
	decryptSharedKey, _ := elliptic.P256().ScalarMult(xUncompressed, yUncompressed, bHNPriv)
	// fmt.Printf("deShared: %x\n", decryptSharedKey.Bytes())

	decryptPublicKeyForKDF := decryptPublicKey
	if uncompressed {
		decryptPublicKeyForKDF = CompressKey(decryptPublicKey, yUncompressed)
	}

	kdfKey := AnsiX963KDF(decryptSharedKey.Bytes(), decryptPublicKeyForKDF, ProfileBEncKeyLen, ProfileBMacKeyLen,
		ProfileBHashLen)
	// fmt.Printf("kdfKey: %x\n", kdfKey)
	decryptEncKey := kdfKey[:ProfileBEncKeyLen]
	decryptIcb := kdfKey[ProfileBEncKeyLen : ProfileBEncKeyLen+ProfileBIcbLen]
	decryptMacKey := kdfKey[len(kdfKey)-ProfileBMacKeyLen:]
	// fmt.Printf("\ndeEncKey(size%d): %x\ndeMacKey: %x\ndeIcb: %x\n", len(decryptEncKey), decryptEncKey, decryptMacKey,
	// decryptIcb)

	decryptMacTag := HmacSha256(decryptCipherText, decryptMacKey, ProfileBMacLen)
	if bytes.Equal(decryptMacTag, decryptMac) {
		logger.Util3GPPLog.Infoln("decryption MAC match")
	} else {
		logger.Util3GPPLog.Errorln("decryption MAC failed")
		return "", fmt.Errorf("decryption MAC failed\n")
	}

	decryptPlainText := Aes128ctr(decryptCipherText, decryptEncKey, decryptIcb)

	return calcSchemeResult(decryptPlainText, supiType), nil
}

func profileC(input string, supiType string, privateKey string, publicKey string, kem_scheme kem.Scheme) (string, error) {

	logger.Util3GPPLog.Infof("\nSuciToSupi Profile C\n")

	/* concealed part of suci, here we only have MAC tag & a CipherTEXT */

	s, hexDecodeErr := hex.DecodeString(input)
	if hexDecodeErr != nil {
		logger.Util3GPPLog.Errorln("hex DecodeString error")
		return "", hexDecodeErr
	}

	// ProfileCPubKeyLen := 800 // 800 bytes : Kyber 512
	ProfileCCipherLen := 768 //we use HMAC-SHA256 on our cipher text.

	if len(s) < (ProfileCCipherLen + ProfileCMacLen) {
		logger.Util3GPPLog.Errorln("len of input data is too short!")
		return "", fmt.Errorf("suci input too short\n")
	}

	decryptCipherText := s[:ProfileCCipherLen]
	concealedMsin := s[ProfileCCipherLen : len(s)-ProfileCMacLen] //3 things have been sent: cipher + msin (encrypted) + mac tag
	decryptMac := s[len(s)-ProfileCMacLen:]                       //get the mac tag sent by the UE.

	//getting the Prof C  Home Network Priv Key
	var cHNPriv []byte
	if cHNPrivTmp, err := hex.DecodeString(privateKey); err != nil {
		log.Printf("Decode error: %+v", err)
	} else {
		cHNPriv = cHNPrivTmp
	}

	var cHNPub []byte
	if cHNPubTemp, err := hex.DecodeString(publicKey); err != nil {
		log.Printf("Decode error: %+v", err)
	} else {
		cHNPub = cHNPubTemp
	}

	fmt.Printf("%v", cHNPriv) //not used anywhere, because we only use our OQS client object.

	var decryptSharedKey []byte // we obtain this on decapsulation.

	if decryptSharedKeyTmp, err := decapsulate(privateKey, []byte(decryptCipherText), kem_scheme); err != nil {
		log.Printf("Decaps error: %+v", err)
		return "",fmt.Errorf("\n Decaps failed \n")

	} else {
		logger.Util3GPPLog.Infof("\nDecapsulation Successful\n")
		decryptSharedKey = decryptSharedKeyTmp
	}

	/*
		    Here, we are basically generating an AES128 (CTR mode) encryption key from the concatenation of our shared key & our public key, which also generates the Mac, the Mac Key obtained is verified with the mac key sent in the SUCI.

			  We can use CRYSTALS-Dilithium instead of HMAC too, there our Shared Secret only will serve as the Enc & Dec key.

			  KDF -> MAC Key generated -> HMAC -> Mac tag, we obtain this mac tag from our suci & then we compute it from our shared secret & then check whether they both are same or not.

	*/

	kdfKey := AnsiX963KDF(decryptSharedKey, cHNPub, ProfileCEncKeyLen, ProfileCMacKeyLen, ProfileCHashLen)
	decryptEncKey := kdfKey[:ProfileCEncKeyLen]
	decryptIcb := kdfKey[ProfileCEncKeyLen : ProfileCEncKeyLen+ProfileCIcbLen]
	decryptMacKey := kdfKey[len(kdfKey)-ProfileCMacKeyLen:]

	decryptMacTag := HmacSha256(decryptCipherText, decryptMacKey, ProfileCMacLen)

	if bytes.Equal(decryptMacTag, decryptMac) {

		logger.Util3GPPLog.Infoln("decryption MAC match ✅")
	} else {

		logger.Util3GPPLog.Errorln("decryption MAC failed")
		return "", fmt.Errorf("decryption MAC failed\n") // forgery may be involved

	}

	decryptPlainText := Aes128ctr(concealedMsin, decryptEncKey, decryptIcb) //here, we decrypt using the shared secret using the key we just derived, this is our MSIN value..... We pass this onto our calcSchemeResult to properly display the results.

	logger.Util3GPPLog.Infof("\nDecryption succcessful!\n")

	return calcSchemeResult(decryptPlainText, supiType), nil

}

// suci-0(SUPI type)-mcc-mnc-routingIndentifier-protectionScheme-homeNetworkPublicKeyIdentifier-schemeOutput.
const supiTypePlace = 1 //their indices.
const mccPlace = 2
const mncPlace = 3
const schemePlace = 5

const typeIMSI = "0"
const imsiPrefix = "imsi-"
const profileAScheme = "1"
const profileBScheme = "2"
const profileCScheme = "3"

func ToSupi(suci string, privateKey string) (string, error) {
	suciPart := strings.Split(suci, "-")
	// logger.Util3GPPLog.Infof("suciPart %s\n", suciPart)

	suciPrefix := suciPart[0]
	if suciPrefix == "imsi" || suciPrefix == "nai" {
		// logger.Util3GPPLog.Infof("Got supi\n")
		return suci, nil

	} else if suciPrefix == "suci" {
		if len(suciPart) < 6 {
			logger.Util3GPPLog.Errorf("Suci with wrong format\n")
			return suci, fmt.Errorf("Suci with wrong format\n")
		}

	} else {
		logger.Util3GPPLog.Errorf("Unknown suciPrefix\n")
		return suci, fmt.Errorf("Unknown suciPrefix\n")
	}

	// logger.Util3GPPLog.Infof("scheme %s\n", suciPart[schemePlace])
	scheme := suciPart[schemePlace]
	mccMnc := suciPart[mccPlace] + suciPart[mncPlace]

	supiPrefix := imsiPrefix
	if suciPrefix == "suci" && suciPart[supiTypePlace] == typeIMSI {
		supiPrefix = imsiPrefix
		// logger.Util3GPPLog.Infof("SUPI type is IMSI\n")
	}

	var res string

	if scheme == profileAScheme {
		profileAResult, err := profileA(suciPart[len(suciPart)-1], suciPart[supiTypePlace], privateKey)
		if err != nil {
			return "", err
		} else {
			res = supiPrefix + mccMnc + profileAResult
		}
	} else if scheme == profileBScheme {
		profileBResult, err := profileB(suciPart[len(suciPart)-1], suciPart[supiTypePlace], privateKey)
		if err != nil {
			return "", err
		} else {
			res = supiPrefix + mccMnc + profileBResult
		}
	} else { // NULL scheme
		res = supiPrefix + mccMnc + suciPart[len(suciPart)-1]
	}

	// everything successful, print the logs

	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")
	logger.Util3GPPLog.Infof("| %-63s |\n", "Coran Labs Private & Public Key configured")
	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "SUCI successfully received", "")
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "Scheme", scheme)
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "MccMnc", mccMnc)

	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "MAC used", "HMAC-SHA256")
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "KDF used", "ANSI X9.63")

	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "Shared Key generated", "✓")
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "Decryption Mac matched", "✓")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "SUPI prefix", supiPrefix)
	logger.Util3GPPLog.Infof("| %-30s | %-30s|\n", "SUPI generated successfully", "✅")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n\n", "SUPI value", res)
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "", "COMPLETED!")

	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")

	return res, nil

}

func ToSupi_2(suci string, privateKey string, publicKey string, kem_scheme kem.Scheme) (string, error) {
	suciPart := strings.Split(suci, "-")
	// logger.Util3GPPLog.Infof("suciPart %s\n", suciPart)

	suciPrefix := suciPart[0]
	if suciPrefix == "imsi" || suciPrefix == "nai" {
		// logger.Util3GPPLog.Infof("Got supi\n")
		return suci, nil

	} else if suciPrefix == "suci" {
		if len(suciPart) < 6 {
			logger.Util3GPPLog.Errorf("Suci with wrong format\n")
			return suci, fmt.Errorf("Suci with wrong format\n")
		}

	} else {
		logger.Util3GPPLog.Errorf("Unknown suciPrefix\n")
		return suci, fmt.Errorf("Unknown suciPrefix\n")
	}

	// logger.Util3GPPLog.Infof("scheme %s\n", suciPart[schemePlace])
	scheme := suciPart[schemePlace]
	mccMnc := suciPart[mccPlace] + suciPart[mncPlace]

	supiPrefix := imsiPrefix
	if suciPrefix == "suci" && suciPart[supiTypePlace] == typeIMSI {
		supiPrefix = imsiPrefix
		// logger.Util3GPPLog.Infof("SUPI type is IMSI\n")
	}

	var res string

	if scheme == profileCScheme {
		profileCResult, err := profileC(suciPart[len(suciPart)-1], suciPart[supiTypePlace], privateKey, publicKey, kem_scheme)
		if err != nil {
			return "", err
		} else {
			res = supiPrefix + mccMnc + profileCResult
		}
	} else { // NULL scheme
		res = supiPrefix + mccMnc + suciPart[len(suciPart)-1]
	}

	// everything successful, print the logs

	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")
	logger.Util3GPPLog.Infof("| %-63s |\n", "Coran Labs Private & Public Key configured")
	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "SUCI successfully received", "")
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "Scheme", scheme)
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "MccMnc", mccMnc)

	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "MAC used", "HMAC-SHA256")
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "KDF used", "ANSI X9.63")

	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "Shared Key generated", "✓")
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "Decryption Mac matched", "✓")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "SUPI prefix", supiPrefix)
	logger.Util3GPPLog.Infof("| %-30s | %-30s|\n", "SUPI generated successfully", "✅")

	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n\n", "SUPI value", res)
	logger.Util3GPPLog.Infof("| %-30s | %-30s |\n", "", "COMPLETED!")

	logger.Util3GPPLog.Infof("+" + strings.Repeat("-", 70) + "+\n")

	return res, nil

}

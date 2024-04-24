package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log"
	"math/bits"
	"strings"

	"math"

	"github.com/open-quantum-safe/liboqs-go/oqs"

	"encoding/binary"
	"encoding/hex"

	"github.com/Nikhil690/util_3gpp/logger"
)

// profile C.
const ProfileCMacKeyLen = 32 // octets
const ProfileCEncKeyLen = 16 // octets
const ProfileCIcbLen = 16    // octets
const ProfileCMacLen = 8     // octets
const ProfileCHashLen = 32   // octets

const typeIMSI = "0"
const imsiPrefix = "imsi-"
const profileCScheme = "3"

// suci-0(SUPI type)-mcc-mnc-routingIndentifier-protectionScheme-schemeOutput:
// schemeOutput : cipher + msin + mac tag
// indices of these params in the suci string
const supiTypePlace = 1
const mccPlace = 2
const mncPlace = 3
const schemePlace = 5

// oqs_client : the object which decaps the secret & generates the HN pub/priv key, here the client is UDM.

func decapsulate(oqs_client *oqs.KeyEncapsulation, cipherText []byte) ([]byte, error) {

	//client already has the private key so not needed. https://github.com/open-quantum-safe/liboqs-go/blob/main/oqs/oqs.go#L214

	sharedSecret, err := oqs_client.DecapSecret(cipherText) // returns a byte slice, thank god!
	if err != nil {
		log.Fatal(err)
		return []byte{0}, err
	}

	return sharedSecret, nil

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

func swapNibbles(input []byte) []byte {
	output := make([]byte, len(input))
	for i, b := range input {
		output[i] = bits.RotateLeft8(b, 4)
	}
	return output
}

func AnsiX963KDF(sharedKey []byte, profileEncKeyLen, profileMacKeyLen, profileHashLen int) []byte {

	var counter uint32 = 0x00000001
	var kdfKey []byte
	kdfRounds := int(math.Ceil(float64(profileEncKeyLen+profileMacKeyLen) / float64(profileHashLen)))
	for i := 1; i <= kdfRounds; i++ {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		// fmt.Printf("counterBytes: %x\n", counterBytes)
		tmpK := sha256.Sum256(append(append(sharedKey, counterBytes...))) //32 bytes.
		sliceK := tmpK[:]
		kdfKey = append(kdfKey, sliceK...)
		// fmt.Printf("kdfKey in round %d: %x\n", i, kdfKey)
		counter++
	}
	return kdfKey
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

func profileC(input string, supiType string, privateKey string, oqs_client *oqs.KeyEncapsulation) (string, error) {

	logger.Util3GPPLog.Infoln("SuciToSupi Profile C")

	/* concealed part of suci, here we only have MAC tag & a CipherTEXT */

	s, hexDecodeErr := hex.DecodeString(input)
	if hexDecodeErr != nil {
		logger.Util3GPPLog.Errorln("hex DecodeString error")
		return "", hexDecodeErr
	}

	// ProfileCPubKeyLen := 800 // 800 bytes : Kyber 512
	ProfileCCipherLen := 768 //we use HMAC-SHA256 on our cipher text.

	if len(s) < (ProfileCCipherLen + ProfileCMacKeyLen) {
		logger.Util3GPPLog.Errorln("len of input data is too short!")
		return "", fmt.Errorf("suci input too short\n")
	}

	decryptCipherText := s[:ProfileCCipherLen]
	concealedMsin := s[ProfileCCipherLen : len(s)-ProfileCMacLen] //3 things have been sent: cipher + msin (encrypted) + mac tag
	decryptMac := s[len(s)-ProfileCCipherLen:]                    //get the mac tag sent by the UE.

	//getting the Prof C  Home Network Priv Key
	var cHNPriv []byte
	if cHNPrivTmp, err := hex.DecodeString(privateKey); err != nil {
		log.Printf("Decode error: %+v", err)
	} else {
		cHNPriv = cHNPrivTmp
	}

	fmt.Printf("%v", cHNPriv) //not used anywhere, because we only use our OQS client object.

	var decryptSharedKey []byte // we obtain this on decapsulation.

	if decryptSharedKeyTmp, err := decapsulate(oqs_client, []byte(decryptCipherText)); err != nil {
		log.Printf("Decaps error: %+v", err)
	} else {
		decryptSharedKey = decryptSharedKeyTmp
	}

	/*
		    Here, we are basically generating an AES128 (CTR mode) encryption key from the concatenation of our shared key & our public key, which also generates the Mac, the Mac Key obtained is verified with the mac key sent in the SUCI.

			  We can use CRYSTALS-Dilithium instead of HMAC too, there our Shared Secret only will serve as the Enc & Dec key.

			  KDF -> MAC Key generated -> HMAC -> Mac tag, we obtain this mac tag from our suci & then we compute it from our shared secret & then check whether they both are same or not.

	*/

	kdfKey := AnsiX963KDF(decryptSharedKey, ProfileCEncKeyLen, ProfileCMacKeyLen, ProfileCHashLen)
	decryptEncKey := kdfKey[:ProfileCEncKeyLen]
	decryptIcb := kdfKey[ProfileCEncKeyLen : ProfileCEncKeyLen+ProfileCIcbLen]
	decryptMacKey := kdfKey[len(kdfKey)-ProfileCMacKeyLen:]

	decryptMacTag := HmacSha256(decryptCipherText, decryptMacKey, ProfileCMacLen)

	if bytes.Equal(decryptMacTag, decryptMac) {

		logger.Util3GPPLog.Infoln("decryption MAC match")
	} else {

		logger.Util3GPPLog.Errorln("decryption MAC failed")
		return "", fmt.Errorf("decryption MAC failed\n") // forgery may be involved

	}

	decryptPlainText := Aes128ctr(concealedMsin, decryptEncKey, decryptIcb) //here, we decrypt using the shared secret using the key we just derived, this is our MSIN value..... We pass this onto our calcSchemeResult to properly display the results.

	return calcSchemeResult(decryptPlainText, supiType), nil

}

func ToSupi(suci string, privateKey string, oqs_client *oqs.KeyEncapsulation) (string, error) {
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
		profileCResult, err := profileC(suciPart[len(suciPart)-1], suciPart[supiTypePlace], privateKey, oqs_client)
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

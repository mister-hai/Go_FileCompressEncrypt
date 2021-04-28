// This file contains the code for the crypto routines
package GoDNSexfiltration

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	// Every project needs to have the "go get {REPOSITORY}"
	// command run for the dependencies

	"github.com/kevinburke/nacl"
	"github.com/kevinburke/nacl/secretbox"

	// this is how you overload names for import
	// Now this is used instead of the internal logger
	// when you type "log"
	log "github.com/sirupsen/logrus"
)

// bytes per read operation
var FILEREADSPEED int = 36
var MADEFOR string = "Church of the Subhacker"
var BANNERSTRING string = "====== mega impressive banner ======="

func StartLogger(logfile string) (return_code int) {
	Logs, derp := os.OpenFile(logfile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	LoggerInstance := log.New()
	Formatter := new(log.TextFormatter)
	Formatter.ForceColors = true
	Formatter.FullTimestamp = true
	Formatter.TimestampFormat = "02-01-2006 15:04:05"
	LoggerInstance.SetFormatter(Formatter)
	if derp != nil {
		// Cannot open log file. Logging to stderr
		fmt.Sprintf("[-] ERROR: Failure To Open Logfile!", "warn")
		return 0
	} else {
		log.SetOutput(Logs)
	}
	return 1
}

// shows entries from the logfile, starting at the bottom
// limit by line number, loglevel, or time
func ShowLogs(LinesToPrint int, loglevel string, time string) {
	log.SetFormatter(&log.JSONFormatter{})
	//switch loglevel{
	//	case "error":
	//		log.ErrorLevel

}

// function to use zlib to compress a byte array
func ZCompress(input []byte) (herp []byte, derp error) {
	var b bytes.Buffer
	// feed the writer a buffer
	w := zlib.NewWriter(&b)
	// and the Write method will copy data to that buffer
	// in this case, the input we provide gets copied into the buffer "b"
	w.Write(input)
	// and then we close the connection
	w.Close()
	// and copy the buffer to the output
	copy(herp, b.Bytes())
	return herp, derp
}

// decompresses []byte with zlib
// feed it a file blob
func ZDecompress(DataIn []byte) (DataOut []byte, derp error) {
	byte_reader := bytes.NewReader(DataIn)
	ZReader, derp := zlib.NewReader(byte_reader)
	if derp != nil {
		fmt.Sprintf("generic error, fix me plz lol <3!", derp)
	}
	copy(DataOut, DataIn)
	ZReader.Close()
	return DataOut, derp
}

// opens files for reading and writing
func OpenFile(filename string) (filebytes []byte) {
	// open the file
	herp, derp := os.Open(filename)
	if derp != nil {
		fmt.Sprintf("[-] Could not open File, exiting program", derp)
	}
	// function to wait on closing the file
	defer func() {
		if derp = herp.Close(); derp != nil {
			fmt.Sprintf("[-]IO: file already closed, stopped existituating, or de-binarized", "warn")
		}
	}()
	// make io.reader and the buffer it will read into
	reader := bufio.NewReader(herp)
	buffer := make([]byte, FILEREADSPEED)
	for {
		// read INTO buffer
		// return bytes read as filebytes
		_, derp := reader.Read(buffer)
		if derp != nil {
			fmt.Sprintf("[-] Could not read from file", derp)
			break
		}
		fmt.Sprintf("[+] Bytes read: %s", filebytes)

	}
	return buffer
}
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// This file uses []bytes but there are other ways to write files
//
func WriteFile([]byte) (herp int, derp error) {
	// WriteFile writes []byte to a file named by filename.
	// this is the one used in this tutorial
	d1 := []byte("hello\ngo\n")
	err := ioutil.WriteFile("/tmp/dat1", d1, 0644)
	check(err)

	//
	// This creates a file for writing
	CreatedFile, err := os.Create("/tmp/dat2")
	check(err)
	defer CreatedFile.Close()

	d2 := []byte{115, 111, 109, 101, 10}
	n2, err := CreatedFile.Write(d2)
	check(err)
	fmt.Printf("wrote %d bytes\n", n2)

	n3, err := CreatedFile.WriteString("writes\n")
	check(err)
	fmt.Printf("wrote %d bytes\n", n3)
	CreatedFile.Sync()

	BufferWriter := bufio.NewWriter(CreatedFile)
	n4, err := BufferWriter.WriteString("buffered\n")
	check(err)
	fmt.Printf("wrote %d bytes\n", n4)
	BufferWriter.Flush()
}

// This function creates a nonce with the bit size set at 24
// options are:
//		"gcm"
//		"salty"
func NonceGenerator(size int) (nonce []byte, derp error) {
	nonce = make([]byte, 24)
	// make random 24 bit prime number
	herp, derp := rand.Read(nonce)
	if derp != nil {
		fmt.Sprintf("[-] Failed to generate %i-bit Random Number , len(bytes):%i", size, herp, derp)
	}
	return nonce, derp
}

// makes chunky data for packet stuffing
// chunk size known, number of packets unknown
func DataChunkerChunkSize(DataIn []byte, chunkSize int) [][]byte { //, derp error) {
	var DataInLength = len(DataIn)
	// make the buffer
	DataOutBuffer := make([][]byte, DataInLength)
	// loop over the original data object taking a bite outta crim... uh data
	for asdf := 1; asdf < DataInLength; asdf += chunkSize {
		// mark the end bounds
		end := asdf + chunkSize
		// necessary check to avoid slicing beyond slice capacity
		if end > DataInLength {
			end = DataInLength
		}
		DataOutBuffer = append(DataOutBuffer, DataIn[asdf:chunkSize])

	}

	return DataOutBuffer
}

func GCMEncrypter(key []byte, plaintext []byte, nonce []byte) (EncryptedBytes []byte, derp error) {
	// The key argument should be the AES key, either 16 or 32 bytes to select AES-128 or AES-256.
	block, derp := aes.NewCipher(key)
	if derp != nil {
		fmt.Sprintf("generic error, fix me plz lol <3!", derp)
	}
	//if _, derp := io.ReadFull(rand.Reader, nonce); derp != nil {
	//	fmt.Sprintf("generic error, fix me plz lol <3!", derp)
	//}
	aesgcm, derp := cipher.NewGCM(block) // cipher.NewGCM(block)
	if derp != nil {
		fmt.Sprintf("generic error, fix me plz lol <3!", derp)
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	copy(ciphertext, EncryptedBytes)
	return EncryptedBytes, derp
}

//AES-256-GCM
// 32bytes only
// defaults to : AES256Key-32Characters1234567890
func GCMDecrypter(key []byte, nonce []byte, CipherText []byte) (plaintext []byte, derp error) {
	if key == nil {
		key = []byte("AES256Key-32Characters1234567890")
	}
	//ciphertext, _ := hex.DecodeString("f90fbef747e7212ad7410d0eee2d965de7e890471695cddd2a5bc0ef5da1d04ad8147b62141ad6e4914aee8c512f64fba9037603d41de0d50b718bd665f019cdcd")
	//nonce, _ := hex.DecodeString("bb8ef84243d2ee95a41c6c57")
	block, derp := aes.NewCipher(key)
	if derp != nil {
		fmt.Sprintf("generic error, fix me plz lol <3!", derp)
	}
	aesgcm, derp := cipher.NewGCM(block)
	if derp != nil {
		fmt.Sprintf("generic error, fix me plz lol <3!", derp)
	}

	plaintext, derp = aesgcm.Open(nil, nonce, CipherText, nil)
	if derp != nil {
		fmt.Sprintf("generic error, fix me plz lol <3!", derp)
	}

	return plaintext, derp
}

//uses NaCl library
func saltycrypt(keystring string, DataIn []byte) []byte {
	key, derp := nacl.Load(keystring)
	if derp != nil {
		panic(derp)
	}
	encrypted := secretbox.EasySeal(DataIn, key)
	return encrypted
}

// decrypts with NaCl
func saltDEcrypt(keystring string, data []byte) []byte {
	key, derp := nacl.Load(keystring)
	if derp != nil {
		panic(derp)
	}
	decrypted, derp := secretbox.EasyOpen(data, key)
	if derp != nil {
		fmt.Sprintf("[-] FATAL ERROR: Could not decrypt data!", derp)
	}
	return decrypted
}

func Decrypt(TypeSelection int, key []byte) {

}

/*/


/*/
// struct to contain the message as octets hidden an ipv6 record set
var Hex2IPV6Stego struct {
	ciphertext []byte
}

//https://stackoverflow.com/questions/35809252/check-if-flag-was-provided-in-go
// make the idea exist
type FlagVals struct {
	set       bool   // true if flag used on command line
	FlagValue string // empty if used but no value fed to parameter
}

// give the idea an action
func (FlagPassed *FlagVals) Set(FlagValue string) error {
	FlagPassed.FlagValue = FlagValue
	FlagPassed.set = true
	return nil
}

//
func (FlagPassed *FlagVals) String() string {
	return FlagPassed.FlagValue
}

//declare the new type as variable
var filename FlagVals
var EncryptionKey FlagVals
var EncryptionType FlagVals

// if both are set, pop a cow on the screen and yell at em

//var serveraddr FlagVals

// set before flag options in main
func init() {
	flag.Var(&filename, "filename", "the local file to exfiltrate.")
	flag.Var(&EncryptionKey, "key", "Encryption Key to use")
	flag.Var(&EncryptionType, " enctype", "Encryption Type , Can be: aes256gcm / salty ")

}
func main() {
	//var debug = flag.Bool("d", false, "enable debugging.")
	var help = flag.Bool("help", false, "show help.")
	var SelectOp = flag.Bool("decrypt", true, "Use this flag if decrypting")
	flag.Parse()

	if *help || len(os.Args) == 1 {
		flag.PrintDefaults()
		return
	}
	// Encode the key
	key, _ := hex.DecodeString(EncryptionKey.FlagValue)
	//
	// create nonce
	//
	nonce, derp := NonceGenerator(32)
	//
	// check for errors
	//
	if derp != nil {
		fmt.Sprintf("[-] Nonce Generation FAILED!", derp)
	}
	//
	// open the file
	//
	fileobject := OpenFile(filename.FlagValue)
	//
	// If we are decrypting, we decrypt/decompress
	//
	switch *SelectOp {

	case true:
		herp, derp := ZDecompress(fileobject)
		if derp != nil {
			fmt.Sprintf("[-] Could not compress file", derp)
		}
		GCMDecrypter(key, nonce, herp)
	case false:
		//DebugPrint(1, "--filename set to %q\n", filename.FlagValue)
		// encode the key to hex
		//ENCRYPTIONKEY := hex.EncodeToString()
		//
		// compress the file
		//
		herp, derp := ZCompress(fileobject)
		//
		// Check for errors
		//
		if derp != nil {
			fmt.Sprintf("[-] Could not compress file", derp)
		}
		//
		// Switch/Case Usage: Select Encryption Type
		//
		switch EncryptionType.FlagValue {
		// in case we want to use internal aes
		case "aes":
			//
			// Write encrypted text to file
			//

			EncryptedText, derp := GCMEncrypter(key, nonce, herp)

		}
	}
}

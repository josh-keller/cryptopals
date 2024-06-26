package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math"
	"os"
)

var englishFreq = map[byte]float64{
	32:  0.167564443682168,
	101: 0.08610229517681191,
	116: 0.0632964962389326,
	97:  0.0612553996079051,
	110: 0.05503703643138501,
	105: 0.05480626188138746,
	111: 0.0541904405334676,
	115: 0.0518864979648296,
	114: 0.051525029341199825,
	108: 0.03218192615049607,
	100: 0.03188948073064199,
	104: 0.02619237267611581,
	99:  0.02500268898936656,
	10:  0.019578060965172565,
	117: 0.019247776378510318,
	109: 0.018140172626462205,
	112: 0.017362092874808832,
	102: 0.015750347191785568,
	103: 0.012804659959943725,
	46:  0.011055184780313847,
	121: 0.010893686962847832,
	98:  0.01034644514338097,
	119: 0.009565830104169261,
	44:  0.008634492219614468,
	118: 0.007819143740853554,
	48:  0.005918945715880591,
	107: 0.004945712204424292,
	49:  0.004937789430804492,
	83:  0.0030896915651553373,
	84:  0.0030701064687671904,
	67:  0.002987392712176473,
	50:  0.002756237869045172,
	56:  0.002552781042488694,
	53:  0.0025269211093936652,
	65:  0.0024774830020061096,
	57:  0.002442242504945237,
	120: 0.0023064144740073764,
	51:  0.0021865587546870337,
	73:  0.0020910417959267183,
	45:  0.002076717421222119,
	54:  0.0019199098857390264,
	52:  0.0018385271551164353,
	55:  0.0018243295447897528,
	77:  0.0018134911904778657,
	66:  0.0017387002075069484,
	34:  0.0015754276887500987,
	39:  0.0015078622753204398,
	80:  0.00138908405321239,
	69:  0.0012938206232079082,
	78:  0.0012758834637326799,
	70:  0.001220297284016159,
	82:  0.0011037374385216535,
	68:  0.0010927723198318497,
	85:  0.0010426370083657518,
	113: 0.00100853739070613,
	76:  0.0010044809306127922,
	71:  0.0009310209736100016,
	74:  0.0008814561018445294,
	72:  0.0008752446473266058,
	79:  0.0008210528757671701,
	87:  0.0008048270353938186,
	106: 0.000617596049210692,
	122: 0.0005762708620098124,
	47:  0.000519607185080999,
	60:  0.00044107665296153596,
	62:  0.0004404428310719519,
	75:  0.0003808001912620934,
	41:  0.0003314254660634964,
	40:  0.0003307916441739124,
	86:  0.0002556203680692448,
	89:  0.00025194420110965734,
	58:  0.00012036277683200988,
	81:  0.00010001709417636208,
	90:  8.619977698342993e-05,
	88:  6.572732994986532e-05,
	59:  7.41571610813331e-06,
	63:  4.626899793963519e-06,
	127: 3.1057272589618137e-06,
	94:  2.2183766135441526e-06,
	38:  2.0282300466689395e-06,
	43:  1.5211725350017046e-06,
	91:  6.97204078542448e-07,
	93:  6.338218895840436e-07,
	36:  5.070575116672349e-07,
	33:  5.070575116672349e-07,
	42:  4.436753227088305e-07,
	61:  2.5352875583361743e-07,
	126: 1.9014656687521307e-07,
	95:  1.2676437791680872e-07,
	9:   1.2676437791680872e-07,
	123: 6.338218895840436e-08,
	64:  6.338218895840436e-08,
	5:   6.338218895840436e-08,
	27:  6.338218895840436e-08,
	30:  6.338218895840436e-08,
}

const (
	TAB = byte(9)
	LF  = byte(10)
	CR  = byte(13)
)

func ReadBase64File(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	decoder := base64.NewDecoder(base64.RawStdEncoding.WithPadding('='), file)
	return io.ReadAll(decoder)
}

func ReadHexLines(filename string) ([][]byte, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	rawLines := bytes.Split(contents, []byte{'\n'})
	decodedLines := make([][]byte, len(rawLines))
	for i, rl := range rawLines {
		dest := make([]byte, len(rl)/2)
		_, err := hex.Decode(dest, rl)
		if err != nil {
			return nil, err
		}
		decodedLines[i] = dest
	}
	return decodedLines, nil
}

// Calculate how closely the character frequency matches expected
// English characters. Lower number is better. Used the chi-square test
// based on some research I did and after unsuccessfully trying other methods.
func calculateWeight(bs []byte) float64 {
	// Filter out any with non-printable characters
	ltrSpcCount := 0
	for _, b := range bs {
		if b == ' ' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
			ltrSpcCount++
		}
		if b >= ' ' && b <= '~' { // Normal printable ascii characters
			continue
		} else if b == TAB || b == LF || b == CR { // Printable whitespace
			continue
		} else { // If this string has non-printable chars, it probably isn't what we want
			return math.Inf(1)
		}
	}

	return 1.0 / float64(ltrSpcCount) / float64(len(bs))
	// Calculate the ratio of letters and spaces to anything else
	//
	// chi2 := 0.0
	// len := len(bs)
	// for i := byte(0); i < 128; i++ {
	// 	observed := float64(freq[i])
	// 	expectedFreq, exists := englishFreq[i]
	// 	if !exists {
	// 		continue
	// 	}
	// 	expected := float64(len) * expectedFreq
	// 	difference := observed - expected
	// 	chi2 += difference * difference / expected
	// }
	//
	// return chi2
}

func bestByteAndScore(bs []byte) (byte, float64, []byte) {
	xored := make([]byte, len(bs))
	copy(xored, bs)
	bestWeight := math.Inf(1)
	currBest := make([]byte, len(bs))
	bestByte := 0

	for xorByte := 0; xorByte < 256; xorByte++ {
		for i := range bs {
			xored[i] = bs[i] ^ byte(xorByte)
		}
		weight := calculateWeight(xored)
		if weight < bestWeight {
			bestWeight = weight
			copy(currBest, xored)
			bestByte = xorByte
		}
	}

	return byte(bestByte), bestWeight, currBest
}

func RandomBytes(size int) []byte {
	if size < 0 {
		panic("Cannot generate less than 0 bytes")
	}

	b := make([]byte, size)
	_, err := rand.Reader.Read(b)
	if err != nil {
		panic(err)
	}

	return b
}

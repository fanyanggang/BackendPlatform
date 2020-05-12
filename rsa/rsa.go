package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"git.code.oa.com/trpc-go/trpc-go/log"
	"io/ioutil"
	"os"
)

const (
	CHAR_SET               = "UTF-8"
	BASE_64_FORMAT         = "UrlSafeNoPadding"
	RSA_ALGORITHM_KEY_TYPE = "PKCS8"
	RSA_ALGORITHM_SIGN     = crypto.SHA256
)

type XRsa struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func Create() {
	var bits int
	flag.IntVar(&bits, "b", 2048, "密钥长度，默认为1024位")
	if err := GenRsaKey(bits); err != nil {
		log.Fatal("密钥文件生成失败！")
	}
	log.Debug("密钥文件生成成功！")
}

func GenRsaKey(bits int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "私钥",
		Bytes: derStream,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "公钥",
		Bytes: derPkix,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

var decrypted string
var privateKey, publicKey, keystore []byte

var xrsa *XRsa

func init() {
	var err error
	flag.StringVar(&decrypted, "d", "", "加密过的数据")
	flag.Parse()
	publicKey, err = ioutil.ReadFile("public.pem")
	if err != nil {
		os.Exit(-1)
	}
	privateKey, err = ioutil.ReadFile("private.pem")
	if err != nil {
		os.Exit(-1)
	}
	//keystore, err = ioutil.ReadFile("5ea6896c55c35.keystore")
	keystore, err = ioutil.ReadFile("5ea6896c55c35.keystore")
	if err != nil {
		os.Exit(-1)
	}
	log.Debugf("keystory:%v", len(keystore))
	log.Debugf("privateKey:%v", len(privateKey))
	log.Debugf("publicKey:%v", len(publicKey))
	xrsa, err = NewXRsa(publicKey, privateKey)

	//keystore, err = ioutil.ReadFile("dddd.keystore")
	if err != nil {
		os.Exit(-1)
	}

	log.Debugf("xrsa:%v", xrsa)
	ecry, err := xrsa.PublicEncrypt(string(keystore))

	log.Debugf("PublicEncrypt:%v, err:%v", len([]byte(ecry)), err)

	decry, err := xrsa.PrivateDecrypt(ecry)
	log.Debugf("PrivateDecrypt:%v", len([]byte(decry)))

}

func NewXRsa(publicKey []byte, privateKey []byte) (*XRsa, error) {
	log.Debugf("NewXRsa:%v", len(publicKey))

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	log.Debugf("NewXRsa 1:%v", len(publicKey))

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {

		return nil, err
	}

	pub := pubInterface.(*rsa.PublicKey)

	block, _ = pem.Decode(privateKey)

	if block == nil {
		return nil, errors.New("private key error!")
	}
	log.Debugf("NewXRsa 2:%v", len(publicKey))

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Debugf("NewXRsa 10:%v", err)

		return nil, err
	}
	log.Debugf("NewXRsa 3:%v", len(publicKey))

	//pri, ok := priv.(*rsa.PrivateKey)
	if true {
		return &XRsa{
			publicKey:  pub,
			privateKey: priv,
		}, nil
	} else {
		return nil, errors.New("private key not supported")
	}
}

// 公钥加密
func (r *XRsa) PublicEncrypt(data string) (string, error) {
	partLen := r.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bytes, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(bytes)
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

// 私钥解密
func (r *XRsa) PrivateDecrypt(encrypted string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

// 数据加签
func (r *XRsa) Sign(data string) (string, error) {
	h := RSA_ALGORITHM_SIGN.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	sign, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, RSA_ALGORITHM_SIGN, hashed)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sign), err
}

// 数据验签
func (r *XRsa) Verify(data string, sign string) error {
	h := RSA_ALGORITHM_SIGN.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	decodedSign, err := base64.RawURLEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(r.publicKey, RSA_ALGORITHM_SIGN, hashed, decodedSign)
}

func MarshalPKCS8PrivateKey(key *rsa.PrivateKey) []byte {
	info := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{}
	info.Version = 0
	info.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	info.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	info.PrivateKey = x509.MarshalPKCS1PrivateKey(key)

	k, _ := asn1.Marshal(info)
	return k
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}

/*

var decrypted string
var privateKey, publicKey, keystore []byte

func init() {
	var err error
	flag.StringVar(&decrypted, "d", "", "加密过的数据")
	flag.Parse()
	publicKey, err = ioutil.ReadFile("public.pem")
	if err != nil {
		os.Exit(-1)
	}
	privateKey, err = ioutil.ReadFile("private.pem")
	if err != nil {
		os.Exit(-1)
	}
	//keystore, err = ioutil.ReadFile("5ea6896c55c35.keystore")
	keystore, err = ioutil.ReadFile("dddd.keystore")
	if err != nil {
		os.Exit(-1)
	}
	log.Debugf("keystory:%v", len(keystore))
	log.Debugf("privateKey:%v", len(privateKey))
	log.Debugf("publicKey:%v", len(publicKey))

}

func add() {
	var data string
	var err error
	//data, err = RsaEncrypt([]byte("keystore"))
	data, err = RsaEncrypt([]byte("keystore"))
	//data, err := RsaEncryptWithSha1Base64("fyxichen", string(publicKey))

	if err != nil {
		panic(err)
	}
	log.Debugf("rsadata:%v", len(data))
	origData, err := RsaDecrypt([]byte(data))
	//origData, err := RsaDecryptWithSha1Base64(data, string(privateKey))
	if err != nil {
		panic(err)
	}
	log.Debugf("origData:%v", string(origData))
}

// 加密
func RsaEncrypt(origData []byte) (string, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return "nil", errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	//pubInterface, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pub := pubInterface.(*rsa.PublicKey)
	partLen := pub.N.BitLen()/8 - 11
	chunks := split(origData, partLen)
	buffer := bytes.NewBufferString("")
	log.Debugf("RsaEncrypt partLen:%v", partLen)

	//encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
	//
	//return string(encryptedData), err

	for v, chunk := range chunks {
		encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, pub, chunk)
		if err != nil {
			return "", err
		}

		buffer.Write(encryptedData)

		log.Debugf("buffer :%v partLen:%v", v, len(buffer.Bytes()))
	}

	//return base64.StdEncoding.EncodeToString(buffer.Bytes()), err
	return buffer.String(), err
}

// 解密
func RsaDecrypt(encryptedData []byte) (string, error) {

	//encryptedDecodeBytes, err := base64.StdEncoding.DecodeString(string(encryptedData))
	//if err != nil {
	//	return "", err
	//}

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return "nil", errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	//pubInterface, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pub := pubInterface.(*rsa.PublicKey)
	partLen := pub.N.BitLen()/8 - 11

	log.Debugf("RsaDecrypt partLen:%v", partLen)
	chunks := split(encryptedData, partLen)
	buffer := bytes.NewBufferString("")

	block, _ = pem.Decode(privateKey)
	if block == nil {
		return "nil", errors.New("public key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "nil", err
	}

	log.Debugf("RsaDecrypt :%v", len(encryptedData))
	//
	//originalData, err := rsa.DecryptPKCS1v15(rand.Reader, priv, encryptedData)
	//
	//return string(originalData), err
	for _, chunk := range chunks {
		log.Debugf("chunk :%v", len(chunk))

		originalData, err := rsa.DecryptPKCS1v15(rand.Reader, priv, chunk)
		if err != nil {
			return "", err
		}

		buffer.Write(originalData)
		log.Debugf("buffer 解密:%v", len(buffer.Bytes()))

	}

	return buffer.String(), err

}

func Create() {
	var bits int
	flag.IntVar(&bits, "b", 2048, "密钥长度，默认为1024位")
	if err := GenRsaKey(bits); err != nil {
		log.Fatal("密钥文件生成失败！")
	}
	log.Debug("密钥文件生成成功！")
}

func GenRsaKey(bits int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "私钥",
		Bytes: derStream,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "公钥",
		Bytes: derPkix,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}


*/

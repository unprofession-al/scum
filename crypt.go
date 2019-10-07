package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
)

type Crypt struct {
	publicKey       *rsa.PublicKey
	privateKeyBlock *pem.Block
}

func NewCrypt(pubFile, privFile string) (Crypt, error) {
	c := Crypt{}

	pubData, err := ioutil.ReadFile(pubFile)
	if err != nil {
		return c, fmt.Errorf("Error while reading public key file %s: %s", pubFile, err.Error())
	}
	err = c.bytesToPublicKey(pubData)
	if err != nil {
		return c, err
	}

	privData, err := ioutil.ReadFile(privFile)
	if err != nil {
		return c, fmt.Errorf("Error while reading private key file %s: %s", privFile, err.Error())
	}
	err = c.bytesToPrivateKeyBlock(privData)
	if err != nil {
		return c, err
	}

	return c, nil
}

func (c Crypt) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, c.publicKey, data, []byte("scum file"))
}

func (c Crypt) Decrypt(data, pass []byte) ([]byte, error) {
	priv, err := c.getPrivateKey(pass)
	if err != nil {
		return []byte{}, err
	}
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, data, []byte("scum file"))
}

func (c *Crypt) bytesToPrivateKeyBlock(priv []byte) error {
	block, _ := pem.Decode(priv)
	if block == nil {
		return fmt.Errorf("Private key could not be decoded")
	}
	c.privateKeyBlock = block
	return nil
}

func (c Crypt) getPrivateKey(password []byte) (*rsa.PrivateKey, error) {
	enc := x509.IsEncryptedPEMBlock(c.privateKeyBlock)
	b := c.privateKeyBlock.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(c.privateKeyBlock, password)
		if err != nil {
			return nil, err
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *Crypt) bytesToPublicKey(pub []byte) error {
	tokens := strings.Split(string(pub), " ")

	if len(tokens) < 2 {
		return fmt.Errorf("Invalid key format; must contain at least two fields (keytype data [comment])")
	}

	key_type := tokens[0]
	data, err := base64.StdEncoding.DecodeString(tokens[1])
	if err != nil {
		return err
	}

	format, e, n, err := c.getRSAValues(data)

	if format != key_type {
		return fmt.Errorf("Key type said %s, but encoded format said %s.  These should match!", key_type, format)
	}

	c.publicKey = &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	return nil
}

func (c Crypt) readLength(data []byte) ([]byte, uint32, error) {
	l_buf := data[0:4]

	buf := bytes.NewBuffer(l_buf)

	var length uint32

	err := binary.Read(buf, binary.BigEndian, &length)
	if err != nil {
		return nil, 0, err
	}

	return data[4:], length, nil
}

func (c Crypt) readBigInt(data []byte, length uint32) ([]byte, *big.Int, error) {
	var bigint = new(big.Int)
	bigint.SetBytes(data[0:length])
	return data[length:], bigint, nil
}

func (c Crypt) getRSAValues(data []byte) (format string, e *big.Int, n *big.Int, err error) {
	data, length, err := c.readLength(data)
	if err != nil {
		return
	}

	format = string(data[0:length])
	data = data[length:]

	data, length, err = c.readLength(data)
	if err != nil {
		return
	}

	data, e, err = c.readBigInt(data, length)
	if err != nil {
		return
	}

	data, length, err = c.readLength(data)
	if err != nil {
		return
	}

	data, n, err = c.readBigInt(data, length)
	if err != nil {
		return
	}

	return
}

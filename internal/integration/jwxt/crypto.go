package jwxt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// AESChars 与金智统一身份认证前端 encrypt.js 中的字符表完全一致。
const AESChars = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

// EncryptPassword 按金智 encrypt.js 规则使用 AES-CBC + PKCS7 加密明文密码。
func EncryptPassword(password, salt string) (string, error) {
	trimmedSalt := strings.TrimSpace(salt)
	if trimmedSalt == "" {
		return password, nil
	}
	key := []byte(trimmedSalt)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("pwdEncryptSalt 字节长度无效: %d", len(key))
	}

	prefix, err := randomAESString(64)
	if err != nil {
		return "", err
	}
	iv, err := randomAESString(16)
	if err != nil {
		return "", err
	}

	return encryptAES(prefix+password, key, []byte(iv))
}

func encryptAES(plaintext string, key, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

func randomAESString(length int) (string, error) {
	max := big.NewInt(int64(len(AESChars)))
	buf := make([]byte, length)
	for i := range buf {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("生成加密随机数失败: %w", err)
		}
		buf[i] = AESChars[n.Int64()]
	}
	return string(buf), nil
}

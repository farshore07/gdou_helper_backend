package jwxt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptPassword(t *testing.T) {
	salt := "1234567890abcdef"
	plain := "Pass@123456!"

	enc1, err := EncryptPassword(plain, salt)
	if err != nil {
		t.Fatalf("EncryptPassword failed: %v", err)
	}
	enc2, err := EncryptPassword(plain, salt)
	if err != nil {
		t.Fatalf("EncryptPassword second call failed: %v", err)
	}
	if enc1 == enc2 {
		t.Fatalf("expected randomized ciphertexts to differ")
	}
	if strings.ContainsAny(enc1, "\r\n") {
		t.Fatalf("ciphertext must be single-line base64")
	}

	raw, err := base64.StdEncoding.DecodeString(enc1)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(raw)%aes.BlockSize != 0 || len(raw) < 64+len(plain) {
		t.Fatalf("unexpected ciphertext length: %d", len(raw))
	}

	// 验证首块无法靠固定 IV 还原，但从第 64 字节之后的明文解密与原始密码完全一致（使用前一个密文块作 IV）
	block, err := aes.NewCipher([]byte(salt))
	if err != nil {
		t.Fatalf("new cipher failed: %v", err)
	}
	// 第 4 块（索引 64 字节起）在 CBC 中以第 3 块（索引 48..64）为 IV
	tailCipher := raw[64:]
	tailPlain := make([]byte, len(tailCipher))
	cipher.NewCBCDecrypter(block, raw[48:64]).CryptBlocks(tailPlain, tailCipher)
	padLen := int(tailPlain[len(tailPlain)-1])
	if padLen <= 0 || padLen > aes.BlockSize {
		t.Fatalf("invalid pkcs7 padLen: %d", padLen)
	}
	got := string(tailPlain[:len(tailPlain)-padLen])
	if got != plain {
		t.Fatalf("decrypted password mismatch: got %q, want %q", got, plain)
	}
}

func TestEncryptPasswordEdgeCases(t *testing.T) {
	got, err := EncryptPassword("abc", "   ")
	if err != nil || got != "abc" {
		t.Fatalf("empty salt should return plaintext, got (%q, %v)", got, err)
	}
	if _, err := EncryptPassword("abc", "short"); err == nil {
		t.Fatalf("expected error for invalid salt length")
	}
}

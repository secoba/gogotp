package gogotp

import (
	"hash"
	"crypto/sha1"
	"crypto/hmac"
	"math"
	"fmt"
	"strings"
	"github.com/secoba/gogotp/util"
	"encoding/base32"
)

type Hasher struct {
	HashName string
	Digest   func() hash.Hash
}

type OTP struct {
	secret string  // base32编码后的Secret
	digits int     // OTP中整数，一些应用程是6位数或者更多
	hasher *Hasher // 在HMAC中使用的摘要（默认是sha1）
}

// 新建OTP对象
func NewOTP(secret string, digits int, hasher *Hasher) OTP {
	if hasher == nil {
		hasher = &Hasher{
			HashName: "sha1",
			Digest:   sha1.New,
		}
	}
	return OTP{
		secret: secret,
		digits: digits,
		hasher: hasher,
	}
}

// 生成OTP
/**
参数说明：
	input：	用作OTP输入的HMAC计数器值，通常是计数器或Unix时间戳
 */
func (o *OTP) generateOTP(input int) string {
	if input < 0 {
		panic("input must be positive integer")
	}
	hasher := hmac.New(o.hasher.Digest, o.byteSecret())
	hasher.Write(util.Itob(input))
	hmacHash := hasher.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	code = code % int(math.Pow10(o.digits))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", o.digits), code)
}

func (o *OTP) byteSecret() []byte {
	missingPadding := len(o.secret) % 8
	if missingPadding != 0 {
		o.secret = o.secret + strings.Repeat("=", 8-missingPadding)
	}
	//ciphertext := strings.Replace(o.secret, " ", "", -1)
	bytes, err := base32.StdEncoding.DecodeString(o.secret)
	if err != nil {
		panic("decode secret failed")
	}
	return bytes
}

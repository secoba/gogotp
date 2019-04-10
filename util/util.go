package util

import (
	"fmt"
	"net/url"
	"strings"
	"time"
	"math/rand"
)

const (
	OtpTypeTotp = "totp"
	OtpTypeHotp = "hotp"
)

// 生成OTP验证的URI(适用与TOTP和HOTP)
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
/**
参数说明:
    otpType：		otp类型，必须是totp/hotp
    secret：			用于生成URI的hotp/totp secret
    accountName：	账号名
    issuerName：		OTP发行人名称，这是OTP的组织标题
    algorithm：		算法名称
    initialCount：	计数器开始值，只用于hotp
    digits：			OTP Code生成的长度
    period：			OTP Code的过期时间(秒)
返回值：
	用于OTP验证的URI
 */
func BuildUri(otpType, secret, accountName, issuerName, algorithm string, initialCount, digits, period int) string {
	if otpType != OtpTypeHotp && otpType != OtpTypeTotp {
		panic("otp type error, got " + otpType)
	}

	urlParams := make([]string, 0)
	urlParams = append(urlParams, "secret="+secret)
	if otpType == OtpTypeHotp {
		urlParams = append(urlParams, fmt.Sprintf("counter=%d", initialCount))
	}
	label := url.QueryEscape(accountName)
	if issuerName != "" {
		issuerNameEscape := url.QueryEscape(issuerName)
		label = issuerNameEscape + ":" + label
		urlParams = append(urlParams, "issuer="+issuerNameEscape)
	}
	if algorithm != "" && algorithm != "sha1" {
		urlParams = append(urlParams, "algorithm="+strings.ToUpper(algorithm))
	}
	if digits != 0 && digits != 6 {
		urlParams = append(urlParams, fmt.Sprintf("digits=%d", digits))
	}
	if period != 0 && period != 30 {
		urlParams = append(urlParams, fmt.Sprintf("period=%d", period))
	}
	return fmt.Sprintf("otpauth://%s/%s?%s", otpType, label, strings.Join(urlParams, "&"))
}

// 获取当前时间戳
func CurrentTimestamp() int {
	return int(time.Now().Unix())
}

// 整型转字节数组
func Itob(integer int) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	}
	return byteArr
}

// 根据长度生成随机Secret
func RandomSecret(length int) string {
	rand.Seed(time.Now().UnixNano())
	//letterRunes := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*_+=")
	letterRunes := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

	bytes := make([]rune, length)

	for i := range bytes {
		bytes[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(bytes)
}

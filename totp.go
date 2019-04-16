package gogotp

import (
	"time"
	"github.com/secoba/gogotp/util"
)

// 基于时间的OTP计数器
type TOTP struct {
	OTP
	interval int
}

func NewTOTP(secret string, digits, interval int, hasher *Hasher) *TOTP {
	otp := NewOTP(secret, digits, hasher)
	return &TOTP{OTP: otp, interval: interval}
}

// 生成默认OTP对象
func NewDefaultTOTP(secret string) *TOTP {
	return NewTOTP(secret, 6, 30, nil)
}

// 根据给定的时间戳生成OTP值
func (t *TOTP) At(timestamp int) string {
	return t.generateOTP(t.timecode(timestamp))
}

// 生成当前时间的OTP值
func (t *TOTP) Now() string {
	return t.At(util.CurrentTimestamp())
}

// 生成当前时间的OTP值，并返回过期时间
func (t *TOTP) NowWithExpiration() (string, int64) {
	interval64 := int64(t.interval)
	timeCodeInt64 := time.Now().Unix() / interval64
	expirationTime := (timeCodeInt64 + 1) * interval64
	return t.generateOTP(int(timeCodeInt64)), expirationTime
}

// 验证OTP
/**
参数说明：
	otp:         待检查的OTP值
    timestamp:   验证OTP的时间戳
返回值：
	bool	是否验证成功，成功返回true
 */
func (t *TOTP) Verify(otp string, timestamp int) bool {
	return otp == t.At(timestamp)
}

// 获取需要验证OTP的URI，可以嵌入到二维码中
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
/**
参数说明：
	accountName：	账号名
    issuerName：		OTP发行人名称，这是OTP的组织标题
返回值：
	用于验证的URI
 */
func (t *TOTP) ProvisioningUri(accountName, issuerName string) string {
	return util.BuildUri(
		util.OtpTypeTotp,
		t.secret,
		accountName,
		issuerName,
		t.hasher.HashName,
		0,
		t.digits,
		t.interval)
}

func (t *TOTP) timecode(timestamp int) int {
	return int(timestamp / t.interval)
}

package gogotp

import "github.com/secoba/gogotp/util"

// 基于HMAC的OTP计数器
type HOTP struct {
	OTP
}

func NewHOTP(secret string, digits int, hasher *Hasher) *HOTP {
	otp := NewOTP(secret, digits, hasher)
	return &HOTP{OTP: otp}

}

// 生成默认OTP对象
func NewDefaultHOTP(secret string) *HOTP {
	return NewHOTP(secret, 6, nil)
}

// 根据给定的整数生成OTP值
func (h *HOTP) At(count int) string {
	return h.generateOTP(count)
}

// 验证OTP
/**
参数说明：
	otp：	待检查的OTP值
    count：	验证OTP的HMAC计数器
返回值：
	bool	是否验证成功，成功返回true
 */
func (h *HOTP) Verify(otp string, count int) bool {
	return otp == h.At(count)
}

// 获取需要验证OTP的URI，可以嵌入到二维码中
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
/**
参数说明：
	accountName：	账号名
    issuerName：		OTP发行人名称，这是OTP的组织标题
    initialCount：	初始HMAC计数器值
返回值：
	用于验证的URI
 */
func (h *HOTP) ProvisioningUri(accountName, issuerName string, initialCount int) string {
	return util.BuildUri(
		util.OtpTypeHotp,
		h.secret,
		accountName,
		issuerName,
		h.hasher.HashName,
		initialCount,
		h.digits,
		0)
}

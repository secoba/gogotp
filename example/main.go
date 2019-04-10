package main

import (
	"fmt"
	"gogotp"
	"gogotp/util"
	"crypto/sha512"
)

func main() {
	//totp := gogotp.NewDefaultTOTP("FEFEiowefewf")

	//key:=util.RandomSecret(16)
	totp2 := gogotp.NewTOTP("FD5AP7ZA4IUSIPWB", 8, 100, &gogotp.Hasher{HashName: "sha512", Digest: sha512.New})
	//totp2 := gogotp.NewTOTP("ffff", 8, 100, &gogotp.Hasher{HashName: "sha512", Digest: sha512.New})
	fmt.Println(totp2.ProvisioningUri("haha@haha.com", "thinking"))

	//fmt.Println(totp.ProvisioningUri("test@test.com", "test_comp"))
	//totp2.Verify("25230888", int(time.Now().UnixNano()))
	//fmt.Println(util.CurrentTimestamp())
	fmt.Println(totp2.Verify("71478833", util.CurrentTimestamp()))
	//fmt.Println(totp2.At(util.CurrentTimestamp()))
}

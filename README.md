> 一个用于生成和验证一次性密码的Golang包，它可用于在需要用户登录的任何地方实施双因素（2FA）或多因素（MFA）身份验证。
> 开放式MFA标准在RFC 4226（HOTP：基于HMAC的一次性密码算法）和RFC 6238（TOTP：基于时间的一次性密码算法）中定义，此包为这两个标准实现了服务器端支持。

### 基于时间 OTP

```Go
totp := gotp.NewDefaultTOTP("4S62BZNFXXSZLCRO")
totp.Now()          // current otp '123456'
totp.At(1524486261) // otp of timestamp 1524486261 '123456'

// 根据给定的时间戳验证 OTP
totp.Verify('492039', 1524486261)  // true
totp.Verify('492039', 1520000000)  // false

// 生成验证URI
totp.ProvisioningUri("demoAccountName", "issuerName")
// otpauth://totp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName
```

### 基于计数器 OTP

```Go
hotp := gotp.NewDefaultHOTP("4S62BZNFXXSZLCRO")
hotp.At(0)  // '944181'
hotp.At(1)  // '770975'

// 根据给定的计数验证OTP
hotp.Verify('944181', 0)  // true
hotp.Verify('944181', 1)  // false

// 生成验证URI
hotp.ProvisioningUri("demoAccountName", "issuerName", 1)
// otpauth://hotp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&counter=1&issuer=issuerName
```

### 生成随机 secret

```Go
secretLength := 16
gotp.RandomSecret(secretLength) // LMT4URYNZKEWZRAA
```

### 兼容Google身份验证器

可与iPhone和Android的Google身份验证器以及其他OTP应用（如Authy）配合使用。
其包括生成供QR码使用的验证URI能力，通过`otpObj.ProvisioningUri`方法内置到MFA客户端应用程序中的扫描程序:

```Go
// TOTP
gotp.NewDefaultTOTP("4S62BZNFXXSZLCRO").ProvisioningUri("demoAccountName", "issuerName")
// otpauth://totp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName

// HOTP
gotp.NewDefaultHOTP("4S62BZNFXXSZLCRO").ProvisioningUri("demoAccountName", "issuerName", 1)
// otpauth://hotp/issuerName:demoAccountName?secret=4S62BZNFXXSZLCRO&counter=1&issuer=issuerName
```

然后，可以将此URL呈现为QR码，将其扫描并添加到OTP凭证的用户列表中。

### 示例

使用手机的OTP应用扫描以下条形码（例如Google身份验证器）:

![Demo](https://user-images.githubusercontent.com/5506906/39129827-0f12b582-473e-11e8-9c19-5e4f071eed26.png)

运行以下命令并比较输出：

```Go
package main

import (
	"fmt"
	"github.com/xlzd/gotp"
)

func main() {
	fmt.Println("Current OTP is", gotp.NewDefaultTOTP("4S62BZNFXXSZLCRO").Now())
}
```


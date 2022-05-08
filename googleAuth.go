/*
	谷歌身份验证器执行步骤：
	1.生成url:GenerateOTP()
	2.校验验证码：CompareCode()
*/

package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// CompareCode 比较Code是否匹配,shift是向前漂移多少个30s,key是密钥
func CompareCode(shift int, code uint32, key string) bool {
	now := time.Now().Unix()
	if shift == 0 {
		shift = 1
	}
	for i := 0; i < shift; i++ {
		now -= int64(i) * 30
		if c, _, _ := GenerateCode(key, now); c == code {
			return true
		}
	}
	return false
}

// GenerateOTP 生成url
// 格式：otpauth://totp/xx@qq.com?secret=U4QWUHPI4JZNVXSC&issuer=Issuer
func GenerateOTP(issuer, tag string) (string, string) {
	if issuer == "" {
		issuer = "Issuer"
	}
	secreteKey := GenerateSecretKey()
	return secreteKey, fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", tag, secreteKey, issuer)
}

// GenerateSecretKey 生成随机密钥
func GenerateSecretKey() string {
	var bytes = make([]byte, 10)
	rand.Read(bytes)
	return base32.StdEncoding.EncodeToString(bytes)
}

// GenerateCode 生成动态code
func GenerateCode(secretKey string, epochSeconds int64) (uint32, int64, error) {
	inputNoSpacesUpper := strings.ToUpper(secretKey)
	key, err := base32.StdEncoding.DecodeString(inputNoSpacesUpper)
	if err != nil {
		return 0, 0, err
	}
	if epochSeconds == 0 {
		epochSeconds = time.Now().Unix()
	}
	//谷歌验证码刷新时间默认是30s一个间隔
	pwd := oneTimePassword(key, toBytes(epochSeconds/30))
	return pwd, epochSeconds, nil
}

func toBytes(value int64) []byte {
	var result = make([]byte, 8)
	binary.BigEndian.PutUint64(result, uint64(value))
	return result
}

func toUint32(bytes []byte) uint32 {
	return binary.BigEndian.Uint32(bytes)
}

//生成一次性密码
func oneTimePassword(key []byte, value []byte) uint32 {
	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F

	number := toUint32(hashParts)

	// size to 6 digits
	// one million is the first number with 7 digits so the remainder
	// of the division will always return < 7 digits
	pwd := number % 1000000

	return pwd
}

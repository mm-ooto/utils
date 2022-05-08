package utils

import (
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var loc *time.Location

func init() {
	loc, _ = time.LoadLocation("local")
}

// CheckPhone 验证手机号
// phone 待验证手机号
func CheckPhone(phone string) bool {
	regular := "^((13[0-9])|(14[5,7])|(15[0-3,5-9])|(17[0,3,5-8])|(18[0-9])|166|198|199|(147))\\d{8}$"
	reg := regexp.MustCompile(regular)
	return reg.MatchString(phone)
}

// CheckCall 验证固话
// tel 待验证固定电话
func CheckCall(tel string) bool {
	//分析参数
	if tel == "" {
		return false
	}
	pattern := "^[\\d]{3,4}\\-[\\d]{7,8}$"
	if bools, _ := regexp.MatchString(pattern, tel); bools {
		return true
	}
	return false
}

// CheckEmail 验证邮箱
// email 待验证邮箱
func CheckEmail(email string) bool {
	pattern := `^[0-9a-z][_.0-9a-z-]{0,31}@([0-9a-z][0-9a-z-]{0,30}[0-9a-z]\.){1,4}[a-z]{2,4}$`
	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}

// MarkPhone 马赛克中国大陆手机号
// phone 待打马赛克手机号，re 马赛克默认标识 默认="*"
func MarkPhone(phone string, re ...string) string {
	if len(phone) != 11 {
		return phone
	}
	var replaceMark string
	if len(re) == 0 {
		replaceMark = strings.Repeat("*", 5)
	} else {
		replaceMark = strings.Repeat(string(re[0]), 5)
	}
	replace := phone[3:8]
	return strings.Replace(phone, replace, replaceMark, 1)
}

// GobEncode2Byte 使用gob编码将数据转化为byte切片
// data gob数据
func GobEncode2Byte(data interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GobDecodeByte gob编码的byte切片数据转化为其他数据
// data 字节切片数组
func GobDecodeByte(data []byte, to interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(to)
}

// StringsToJSON string字符串转json输出
// str 待转字符串
func StringsToJSON(str string) string {
	var jsons bytes.Buffer
	for _, r := range str {
		rint := int(r)
		if len(string(r)) == 4 {
			jsons.WriteRune(r)
		} else if rint < 128 {
			jsons.WriteRune(r)
		} else {
			jsons.WriteString("\\u")
			if rint < 0x100 {
				jsons.WriteString("00")
			} else if rint < 0x1000 {
				jsons.WriteString("0")
			}
			jsons.WriteString(strconv.FormatInt(int64(rint), 16))
		}
	}
	return jsons.String()
}

// Implode 把数组转换为字符串
// separator 转换分隔符，array 待转换数据
func Implode(separator string, array interface{}) string {
	return strings.Replace(strings.Trim(fmt.Sprint(array), "[]"), " ", separator, -1)
}

//生成指定长度的随机字符串
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// RandSeq 生成随机字符串
// n 待生成随机字符串的长度
func RandSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// StrtoTime 字符串转化为时间戳
// timeStr 日期字符串
func StrtoTime(timeStr string, timelayouts ...string) int64 {
	timeLayout := "2006-01-02 15:04:05" //转化所需模板
	if len(timelayouts) > 0 {
		timeLayout = timelayouts[0]
	}
	loc, _ := time.LoadLocation("Local")                         //重要：获取时区
	theTime, _ := time.ParseInLocation(timeLayout, timeStr, loc) //使用模板在对应时区转化为time.time类型
	return theTime.Unix()
}

// TimeToStr 时间戳转化为字符串
// timestamp  时间戳
func TimeToStr(timestamp int64) string {
	tm := time.Unix(timestamp, 0)
	return tm.Format("2006/01/02 15:04:05")
}

// Mb4Strlen 获取字符串长度
// str 待获取长度字符串
func Mb4Strlen(str string) int {
	str = strings.TrimSpace(str)
	if len(str) == 0 {
		return 0
	}
	strRune := []rune(str)
	lens := len(strRune)
	return lens
}

// StuffStr 截取字符串
// str 待截取的字符串，index 截取开始位置，lens  截取长度
func StuffStr(str string, index int, lens int) string {
	str = strings.TrimSpace(str)
	if len(str) == 0 {
		return str
	}
	strRune := []rune(str)
	if len(strRune) < lens {
		lens = len(strRune)
	}
	return string(strRune[index:lens])
}

// ArrayKeys map转数组
func ArrayKeys(maps map[int]interface{}) []int {
	//分析参数
	if len(maps) == 0 {
		return make([]int, 0)
	}
	var arr = make([]int, 0)
	for i, _ := range maps {
		arr = append(arr, i)
	}
	return arr
}

// ArrayValue2Array map数组转数组
func ArrayValue2Array(field string, maps []map[string]interface{}) []int {
	//分析参数
	if len(maps) == 0 {
		return make([]int, 0)
	}
	var arr = make([]int, 0)
	for _, m := range maps {
		v, ok := m[field]
		if ok {
			if vs, p := v.(string); p {
				n, _ := strconv.Atoi(vs)
				arr = append(arr, n)
			}
			if vs, p := v.(int); p {
				arr = append(arr, vs)
			}
		}
	}
	return arr
}

// ArrayRebuild map数组转map
func ArrayRebuild(field string, maps []map[string]interface{}) map[string]interface{} {
	//分析参数
	if len(maps) == 0 {
		return make(map[string]interface{}, 0)
	}
	var reMap = make(map[string]interface{})
	for _, m := range maps {
		v, ok := m[field]
		if ok {
			if vs, p := v.(int); p {
				reMap[strconv.Itoa(vs)] = m
			}
			if vs, p := v.(string); p {
				reMap[vs] = m
			}
			if vs, p := v.(float64); p {
				reMap[strconv.FormatFloat(vs, 'f', -1, 64)] = m
			}
			if vs, p := v.(float32); p {
				reMap[strconv.FormatFloat(float64(vs), 'f', -1, 64)] = m
			}
		}
	}
	return reMap
}

// SortsMap 数组map排序
func SortsMap(field string, maps []map[string]interface{}) []map[string]interface{} {
	var mapData = make(map[string]interface{})
	var keys = make([]string, 0)
	for _, v := range maps {
		vs := v[field]
		if vp, ok := vs.(float64); ok {
			vs = strconv.FormatFloat(vp, 'f', -1, 64)
		}
		if vp, ok := vs.(int); ok {
			vs = strconv.FormatInt(int64(vp), 10)
		}
		if vp, ok := vs.(string); ok {
			vs = vp
		}
		mapData[vs.(string)] = v
		keys = append(keys, vs.(string))
	}
	sort.Strings(keys)
	remapData := make([]map[string]interface{}, 0)
	for _, v := range keys {
		remapData = append(remapData, mapData[v].(map[string]interface{}))
	}
	return remapData
}

// InArray 判断search是否在array中
func InArray(search interface{}, array interface{}) bool {
	if arr, ok := array.([]int); ok {
		for _, val := range arr {
			if val == search {
				return true
			}
		}
	}
	if arr, ok := array.([]string); ok {
		for _, val := range arr {
			if val == search {
				return true
			}
		}
	}
	return false
}

// ArrayUniqueInt 整型数组去重
func ArrayUniqueInt(arr []int) []int {
	if len(arr) == 0 {
		return arr
	}
	newArr := make([]int, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if arr[i] == 0 {
			continue
		}
		if repeat == false {
			newArr = append(newArr, arr[i])
		}
	}
	return newArr
}

// ArrayUniqueString 整型数组去重
func ArrayUniqueString(arr []string) []string {
	if len(arr) == 0 {
		return arr
	}
	newArr := make([]string, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if arr[i] == "" {
			continue
		}
		if repeat == false {
			newArr = append(newArr, arr[i])
		}
	}
	return newArr
}

// ClientIP 尽最大努力实现获取客户端 IP。
// 解析 X-Real-IP 和 X-Forwarded-For 以便于反向代理（nginx 或 haproxy）可以正常工作。
func ClientIP(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	ip := strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
	if ip != "" {
		return ip
	}

	ip = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	if ip != "" {
		return ip
	}

	if ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return ip
	}

	return ""
}

// StrExplode2IntArr 字符串切割成int型数组
func StrExplode2IntArr(s string, step string) []int {
	strs := strings.Split(s, ",")
	var outData []int
	for _, v := range strs {
		if len(v) == 0 {
			continue
		}
		intv, _ := strconv.Atoi(v)
		outData = append(outData, intv)
	}
	return outData
}

// Timestamp2DateTime 将时间戳字符串根据格式转换为时间字符串
func Timestamp2DateTime(timestampStr string, layout ...string) (dataTime string) {
	timestamp, _ := strconv.ParseInt(timestampStr, 10, 64)
	var format string
	if len(layout) == 0 {
		format = "2006-01-02 15:04"
	} else {
		format = layout[0]
	}
	dataTime = time.Unix(timestamp, 0).Format(format)
	return
}

// ParseTimeStrToDate 将时间字符串根据时间格式转换为time.Time
func ParseTimeStrToDate(str, layout string) (t time.Time, err error) {
	t, err = time.ParseInLocation(layout, str, loc)
	return
}

// GetFirstAndLastOfMonth 获取指定时间的开始和结束月份 eg: 2020-10-01 00:00:00~2020-11-01 00:00:00
func GetFirstAndLastOfMonth(timestamp int64) (firstMonth, lastMonth int64) {
	now := time.Unix(timestamp, 0)
	loc, _ := time.LoadLocation("Local")
	currentYear, currentMonth, _ := now.Date()
	firstOfMonth := time.Date(currentYear, currentMonth, 1, 0, 0, 0, 0, loc)
	lastOfMonth := firstOfMonth.AddDate(0, 1, 0)
	firstMonth = firstOfMonth.Unix()
	lastMonth = lastOfMonth.Unix()
	return
}

// GetAge 根据出生日期获取用户年龄
func GetAge(date string) int64 {
	layout := "2006-01-02"
	t, err := time.ParseInLocation(layout, date, time.Local)
	if err != nil {
		fmt.Printf("date format timestamp error errmsg:%s\n", err.Error())
		return 0
	}
	return (time.Now().Unix() - t.Unix()) / (60 * 60 * 24 * 365)
}

// GetAcceptLanguage 获取接收的语言
func GetAcceptLanguage(acceptLanguage string) string {
	language := "zh-CN"

	lang := strings.Split(acceptLanguage, ";")
	if len(lang) >= 1 {
		langs := strings.Split(lang[0], ",")
		language = langs[0]
	}

	return language
}

// RandCode 生成验证码，l-验证码位数
func RandCode(l int) string {
	var code string
	for i := 0; i < l; i++ {
		code += strconv.Itoa(rand.Intn(10))
	}
	return code
}

// GetNowMillisecond 获取毫秒
func GetNowMillisecond() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

// ParseInt 将字符串转换为int
func ParseInt(s string, defaultInt int64 /*转换失败后的默认值*/) int64 {
	intt, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return defaultInt
	} else {
		return intt
	}
}

// GetRandomString 生成随机字符串
func GetRandomString(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()+[]{}/<>;:=.,?"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

// PathExists 路径是否存在
func PathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		} else {
			return false, err
		}
	} else {
		return true, nil
	}
}

// CreatedDir 创建路径
func CreatedDir(dir string, mode os.FileMode) {
	ok, err := PathExists(dir)
	if err == nil && !ok {
		os.MkdirAll(dir, mode)
	}
}

// GenerateFileName 随机生成文件名
func GenerateFileName(path, fileName string) string {
	now := time.Now().UnixNano()
	random := HashMd5(GetRandomString(12))

	number := len(random)

	path = fmt.Sprintf("%s/%s/%s",
		strings.Trim(path, "/"),
		string([]byte(random)[:6]),
		string([]byte(random)[number-6:number]))

	CreatedDir(path, os.ModePerm)

	return fmt.Sprintf("%s/%d_%s%s",
		path,
		now,
		string([]byte(random)[10:20]),
		filepath.Ext(fileName))
}

// HashMd5 md5加密
// str 待加密md5字符串
func HashMd5(str string) string {
	md5Inst := md5.New()
	md5Inst.Write([]byte(str))
	result := md5Inst.Sum([]byte(""))
	return fmt.Sprintf("%x", result)
}

// GetPemPublic 公钥转换
func GetPemPublic(publicKey string) string {
	res := "-----BEGIN PUBLIC KEY-----\n"
	strlen := len(publicKey)
	for i := 0; i < strlen; i += 64 {
		if i+64 >= strlen {
			res += publicKey[i:] + "\n"
		} else {
			res += publicKey[i:i+64] + "\n"
		}
	}
	res += "-----END PUBLIC KEY-----"
	return res
}

// GetPemPrivate 私钥转换
func GetPemPrivate(privateKey string) string {
	res := "-----BEGIN RSA PRIVATE KEY-----\n"
	strlen := len(privateKey)
	for i := 0; i < strlen; i += 64 {
		if i+64 >= strlen {
			res += privateKey[i:] + "\n"
		} else {
			res += privateKey[i:i+64] + "\n"
		}
	}
	res += "-----END RSA PRIVATE KEY-----"
	return res
}


package main

import (
	"time"
	"fmt"
	"crypto/hmac"
	"crypto/sha1"
	"io"
	"io/ioutil"
	"encoding/base64"
	"net/http"
)


func calcAuthorization(source string, secretId string, secretKey string) (sign string, dateTime string, err error) {
	timeLocation, _ := time.LoadLocation("Etc/GMT")
	dateTime = time.Now().In(timeLocation).Format("Mon, 02 Jan 2006 15:04:05 GMT")
	sign = fmt.Sprintf("x-date: %s\nsource: %s", dateTime, source)
	fmt.Println(sign)

	//hmac-sha1
	h := hmac.New(sha1.New, []byte(secretKey))
	io.WriteString(h, sign)
	sign = fmt.Sprintf("%x", h.Sum(nil))
	sign = string(h.Sum(nil))
	fmt.Println("sign:", fmt.Sprintf("%s", h.Sum(nil)))

	//base64
	sign = base64.StdEncoding.EncodeToString([]byte(sign))
	fmt.Println("sign:", sign)

	auth := fmt.Sprintf("hmac id=\"%s\", algorithm=\"hmac-sha1\", headers=\"x-date source\", signature=\"%s\"", 
		secretId, sign)
	fmt.Println("auth:", auth)
		
	return auth, dateTime, nil
}

func main () {
	SecretId := "AKIDgz33go7zufbgrt6azbakwbx7tx0jampv84kz"
	SecretKey := "lCIC0ZQhtcI5u36Lojuh2bnOBqaKy6r5FF4Qc1"
	source := "yousali"

	sign, dateTime, err := calcAuthorization(source, SecretId, SecretKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	defaultDomain := "service-3mm3bc6g-1251762227.ap-guangzhou.apigateway.myqcloud.com"

	reqUrl := "https://service-3mm3bc6g-1251762227.ap-guangzhou.apigateway.myqcloud.com/release/yousa"
	client := &http.Client{
		Timeout: 7 * time.Second,//set timeout
	}

	req, err := http.NewRequest("GET", reqUrl, nil) //set body
	if err != nil {
		fmt.Println(err)		
		return 
	}

	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Charset", "utf-8;")
	req.Header.Set("Host", defaultDomain)
	req.Header.Set("Source", source)
	req.Header.Set("X-Date", dateTime)
	req.Header.Set("Authorization", sign)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)		
		return 
	}
	defer resp.Body.Close()

	fmt.Println("status code:", resp.StatusCode)
	
	//get resp header
	var headerMsg string
	for key, _ := range resp.Header {
		headerMsg += fmt.Sprintf("\n%s:%s", key, resp.Header.Get(key))
	}
	fmt.Println(headerMsg)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)		
		return 
	}

	fmt.Println(string(body))
	
}

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"html/template"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	Debug     = true
	Bucket    = "public"
	S3Path    = "tmp/upload/"
	Algorithm = "AWS4-HMAC-SHA256"
)

var awsSession *session.Session

func AWSSession() *session.Session {
	var once sync.Once
	if awsSession == nil {
		once.Do(func() {
			cfg := defaults.Config().WithRegion("cn-north-1").WithCredentials(nil).WithMaxRetries(3)
			if Debug {
				cfg.WithLogLevel(aws.LogDebugWithHTTPBody)
			}
			awsSession = session.New(cfg)
			log.Println("Init aws session.")
		})
	}
	return awsSession
}

func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func makeSha256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// 计算 police 的签名
func sign(stringToSign string) string {
	cs, _ := awsSession.Config.Credentials.Get()
	secret := cs.SecretAccessKey

	date := makeHmac([]byte("AWS4"+secret), []byte(time.Now().UTC().Format("20060102")))
	region := makeHmac(date, []byte(*awsSession.Config.Region))
	service := makeHmac(region, []byte("s3"))
	credentials := makeHmac(service, []byte("aws4_request"))
	signature := makeHmac(credentials, []byte(stringToSign))
	return hex.EncodeToString(signature)
}

func credential() string {
	cs, _ := awsSession.Config.Credentials.Get()
	return strings.Join([]string{
		cs.AccessKeyID,
		time.Now().UTC().Format("20060102"),
		*awsSession.Config.Region,
		"s3",
		"aws4_request",
	}, "/")
}

//
func policy(uuid, credential, amzDate string) string {
	expiration := time.Now().Add(time.Minute * 15).UTC().Format(time.RFC3339)
	s := `{
    "expiration": "` + expiration + `",
    "conditions": [
        {"x-amz-meta-uuid":"` + uuid + `"},
        {"acl": "public-read"},
        {"x-amz-date":"` + amzDate + `"},
        {"bucket": "` + Bucket + `"},
        {"x-amz-algorithm":"` + Algorithm + `"},
        ["starts-with","$key","` + S3Path + `"],
        ["starts-with", "$Content-Type", "image/"],
        ["starts-with","$Cache-Control",""],
        ["starts-with","$x-amz-credential","` + credential + `"],
        ["content-length-range", 100, 10485760],
        ["starts-with","$success_action_redirect","https://"]
    ]
}`
	return s
}

func init() {
	awsSession = AWSSession()
}

func UUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type Form struct {
	Action string
	Params map[string]string
}

func preSignForm(w http.ResponseWriter, r *http.Request) {
	t, err := template.New("foo").Parse(formPage1)

	if err != nil {
		io.WriteString(w, err.Error())
		return
	}

	form := &Form{
		Params: make(map[string]string),
	}
	uuid := UUID()
	credential := credential()
	amzDate := time.Now().UTC().Format("20060102T150405Z")

	b64policy := base64.StdEncoding.EncodeToString([]byte(policy(uuid, credential, amzDate)))
	form.Action = fmt.Sprintf("https://%s.s3.cn-north-1.amazonaws.com.cn", Bucket)
	form.Params["acl"] = "public-read"
	form.Params["key"] = S3Path + "${filename}"
	form.Params["Content-Type"] = "image/jpeg"
	form.Params["Cache-Control"] = "max-age=864000"
	form.Params["x-amz-meta-uuid"] = uuid
	form.Params["x-amz-algorithm"] = Algorithm
	form.Params["x-amz-credential"] = credential
	form.Params["x-amz-date"] = amzDate
	form.Params["x-amz-signature"] = sign(b64policy)
	form.Params["policy"] = b64policy
	form.Params["success_action_redirect"] = form.Action + fmt.Sprintf("/%s${filename}", S3Path)

	t.Execute(w, form)

}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", preSignForm)
	http.ListenAndServe(":8000", mux)
}

var formPage1 string = `
<html>
    <head>
        <title>s3 uploader</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    </head>
    <body>
        <form action="{{.Action}}" method="post" enctype="multipart/form-data">
        {{range $k,$v := .Params}}<input type="hidden" name="{{$k}}" value="{{$v}}"/>
        {{end}}
        上传图片: <input type="file" name="file"/>
        <input type="submit"/>
        </form>
    </body>
</html>
`

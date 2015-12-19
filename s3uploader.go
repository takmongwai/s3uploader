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
	"os"
	"strings"
	"sync"

	"time"

	"flag"

	"github.com/aws/aws-sdk-go/service/s3"

	"html/template"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	Algorithm = "AWS4-HMAC-SHA256"
)

var awsSession *session.Session
var SecretAccessKey string
var AccessKeyID string
var S3BucketURL string
var S3 *s3.S3

var Bucket string
var S3Path string
var Verbose bool
var Port int

func logger(v ...interface{}) {
	if Verbose {
		log.Println(v...)
	}
}

func init() {
	awsSession = AWSSession()
	cs, err := awsSession.Config.Credentials.Get()
	if err != nil {
		panic(err)
	}

	SecretAccessKey = cs.SecretAccessKey
	AccessKeyID = cs.AccessKeyID

	flag.Usage = func() {
		fmt.Fprintf(os.Stdout,
			"Usage: %s \n",
			os.Args[0])
		flag.PrintDefaults()
	}

	flag.StringVar(&Bucket, "bucket", "public", "set s3 bucket name")
	flag.StringVar(&S3Path, "s3path", "tmp/upload/", "set s3 path prefix")
	flag.BoolVar(&Verbose, "verbose", false, "Make the operation more talkative")
	flag.IntVar(&Port, "port", 8000, "set listen port")
	flag.Parse()

	if !strings.HasSuffix(S3Path, "/") {
		S3Path += "/"
	}

	S3 = s3.New(awsSession)
	S3BucketURL = fmt.Sprintf("%s/%s", S3.Endpoint, Bucket)
	logger("s3 bucket url:", S3BucketURL)
}

func AWSSession() *session.Session {
	var once sync.Once
	if awsSession == nil {
		once.Do(func() {
			cfg := defaults.Config().WithRegion("cn-north-1").WithCredentials(nil).WithMaxRetries(3)
			if Verbose {
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

func sign(stringToSign string) string {
	date := makeHmac([]byte("AWS4"+SecretAccessKey), []byte(time.Now().UTC().Format("20060102")))
	region := makeHmac(date, []byte(*awsSession.Config.Region))
	service := makeHmac(region, []byte(S3.ServiceName))
	credentials := makeHmac(service, []byte("aws4_request"))
	signature := makeHmac(credentials, []byte(stringToSign))
	return hex.EncodeToString(signature)
}

func credential() string {
	return strings.Join([]string{
		AccessKeyID,
		time.Now().UTC().Format("20060102"),
		*awsSession.Config.Region,
		S3.ServiceName,
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
	t, err := template.New("main").Parse(formPage1)

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
	form.Action = S3BucketURL
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
        Upload Picture: <input type="file" name="file"/>
        <input type="submit"/>
        </form>
    </body>
</html>
`

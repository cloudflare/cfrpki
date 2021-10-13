module github.com/cloudflare/cfrpki

go 1.12

require (
	github.com/HdrHistogram/hdrhistogram-go v1.1.2 // indirect
	github.com/cloudflare/gortr v0.14.7
	github.com/getsentry/sentry-go v0.11.0
	github.com/golang/protobuf v1.5.2
	github.com/google/certificate-transparency-go v1.1.2
	github.com/kentik/patricia v0.0.0-20210909164817-21603333b70e
	github.com/opentracing/opentracing-go v1.2.0
	github.com/prometheus/client_golang v1.11.0
	github.com/rs/cors v1.8.0
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/uber/jaeger-client-go v2.29.1+incompatible
	github.com/uber/jaeger-lib v2.4.1+incompatible // indirect
	google.golang.org/grpc v1.41.0
)

replace github.com/codahale/hdrhistogram => github.com/HdrHistogram/hdrhistogram-go v0.9.0

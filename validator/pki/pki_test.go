package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	//"fmt"

	librpki "github.com/cloudflare/cfrpki/validator/lib"
)

func CreateKeys() []*rsa.PrivateKey {
	keys := []string{
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAvi4HGCrEwfW6nzBufYCjD68spQx+Rnr7KnGDVTYvAvN1PESKtMF86fMJXXlK0R6ZZEmxZzdDjiWbYeNjgrbTtUiQdcY/1b1CFtlTrJyKJIvvWn32bZfLSL1MCR4BlBI5tnHzgNDy2CSaXrW0Cq/5xfnFEM+GclvHoa47NiQPDUbGJQj4KkmmmW+GP7rrjIuj6fgMzX0YzoMVELP2NM17OI0QjwLveh7P0PmdeY9fdj8IaWnlVLqIFtALDBXJkbdSdBUCMDxUfnOuu+Zl0IwQOVs8qsJBu0XgodP5fuwnlOw56lhxmbjQ39F2zwzA+vaOKa1vzh0lQ1ydUEDURIuZfwIDAQABAoIBACiB10L/gQ8rDsfvYelbZ9/kWOcCxTav5SWCLg4NT3AaeQMQOlcLy1ZtTLZbKmNmWBezVpT8gWgafIEaFMz3shovzY04X8pf2F7ThW4DnazxHVcx8zYemc7xeuuKN53ZT++bT9lFKCR/j13S5/lKyDGx5JaTDTj4cYnveW8ruQUDin4KA33GRTy2ec7V9EZDkRTUqvWLJUZ+Vtxh8y2Evj4Sue9qV/Y+eTfaS4MvhdRPmvkJ86Jva4rwSzLa0eflL5p9OsLz9tc3VAR7/3yIomlEA9cbtODWyoT3s76Zur2tq9owEVGIlJKdSkYTyutXrNyO4w9n2n/mJR3/XkS/YSkCgYEA92qQRAAzNZMI1uLRCH95ntJOCTiDffiEXbdU+OJrTkoihFrgXumXH8marbb+7dGlnw6Dqkxb3TIBQMdbQ1vhzNtPpJemZbjIU1TSfqm09GuTyQ1ZTYgu0P4yER7NIWdM3SOw/VpzIHNBx5r2XEUi2zJzd69XEWHqJ/nmsNYArosCgYEAxMcdzcnYxAxBtAP0FOTDZHfurj6mQWazOYJTkne+CsSx0IPxbS1S+L0WNsxR9hMyQ/L9U290ZnHJMa6HRRxNzQ2YnOHNOtc8RVgAoPT90vrUzP+8ZgW5czoHra8LnWEX/UkDH6Lpg2WvvmZtj4x17QYoysxSP2LkrQzD87Xjs10CgYBc3dPOomCWUF02AybA0NA+q+N8lIjOhLRyVLkBPkNWvH7ePRoQpg8CcHKtl41yiIlo/VKwXj7w9K8BuJJp4xgLA5qORhm//q66kJD92AdC4woyod8OOfqQmYkDYhNO4W45Zwcs4YFrAbgECwdDtPOTYQl0OA0vShhQ7v0HDRxuZwKBgD9gsmS5giuClxbXvyGLnLMbPbC5VOrznP4Ez8346yikuXCjTnsPgg3DOQhlPnC3NhVUier5ls/4DgkGYWMM/rHwkxrUTzmIYU0kTu+IeMgfKbLtG0zwww4tvpNeMat6vjNB9NOXsQY1FimI6/i0ELdKqJDIxiTMQULLPcGc772xAoGAMCiikm4KZ5pRPxcQ+FWfG+fCPui98l9EFgQZh8ytCJjHa/ZCE4FVNB/Iz1+5zTWItF8YP2GIm0I3RrHKSnla5ZhkvHso4IFkp7KfoSSP5Vc4GfxQRnZt3MnrJE+FniG7NxzRsGEKIk8Sv+W1FGWBOm1eNfkokRhAzWWuFO1+G9w=\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA0sKJ32aHMpOyu9ahUD5v6R4Oy6jjmFU5E1BAQ1HkmI/+E7swTbunXTkyuWdFMRiBXNu4f2lU2jHaXl7JMGgmEsQRI+S1vIWe4xn7MC7hw3Yd/EBoJQs4rclbE45oiNKywCvLZhZc/kfq//mLmqrCRvqjRIAMlmsyFKbqWzc/popPOYClFPOu1kw5WaOEbjj/OXEX/pmRpczVHyIAfl8nisZSVyQJsnqk0gX0D7HaRNQuk5llvC1nJPzga6LyxNgsV4+84TcSfLL6RBTKhwNm+eYvAL3Ir2CSJC7mip8noC2JrqWHaAtyLx4JWkBhLi8tEk+xAmnh3JuYf/e67D5npwIDAQABAoIBAQDKpkF5bBUdHYUjNbl/9bkXVk51ptvIMlGh720LDegWhYWRJVDJvWCss33BZbnS/jQMvDwHTplG/95vFQawI8RQEPRGJfhU38oppWawKrPrhFxKmwdIbyS9fTm0cR60SJuVScbWTzR1T2N3Y1PHkN8i7oYkLFduHn5V+zSmJlZuYxg5QM8yYt/YyFlW81zF6DwMZApDOxqeR+beRZO5hhgaRIjrUDDvNHtgQeA5LR960P0go1zjAaSn05ls/1b8uWGAUJQokq3iWPSwjkfxRb9nnFNW52OzzWqG7BLZ+L/5uP3KWLbXtHKc0HNnEq/raXZepFaBz/yCAmK/82eqI60ZAoGBAP60Cc/nfkjYFtBs4YsS1cY8YNEWjmPIr8u9HIl8St23kGn8bvn3d989kC1y1q6V1/vMRGrn/4bwdbsJ3FwZdAXxsQwpp5aP3M/aJVJFXD26vH9Cv/wCGaylUXQm48etN4BL1cqScCWoZz3eV1m9aFWZRv34AuvjrmFjfTiCly7lAoGBANPVOkh0eazgmJmXuN79d07TfMKOb2C8tnHykG14ChngrefeEIMOTIyH7A3lyxWdu9gYssHKGyYgoO4KMEumkUeYFAurEJfkNmYLqBKqrbo7k6QzGEOwEDe1HyWbkJi8t+gJDEXFtGmD7UjdFNj068VbiYRyabrscFivx/BLLcebAoGAYVDIrvbz+UEW9mujgU+g/izzkO/dV6LGCEIpNR6YPD52nwgkHr2+vzz2aWcHP41hCIPzYCVkLFqToPMTjtzqx5qg2tTPg2dUJtZijByUMcG3Y6hNUiw7QwunI4n4XcKBAjP3a36n+rttNuZM2azUwF/gEAlClH5ZkjxBC+ZZfUECgYEAxWaeuYZRHNjvW7IXhTWOSNasHGG/SNaS7fysulZyk0rcxIYbvQVGMG85enn5lls3AVmCuzQruIwPa8Py3YyLNbxyca0n+WOhjdau+TY0TqfWHd2/btRTSJZwQAuH4815U7Gazio+xVU7efsLwmH6lB+JNvOns5lB2GN2XmawcqECgYEAjIQddjvxGrGvXRknTLtyUVXWpes1HdJ8fRcTFRADBvS3AFUYAeo7DJ+s3j8Z8KUVaQ4XJSgRfp0rtMR9DPAiAroEp3sdMVp+Ml5reIfiWplti8pDje3Gjo9hIeFNIZAZvM+OYwdZwpSS4l7lCPJk4BR19wBkLAdgsV6oXWW2wKM=\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA8FXsDj5waD/2dNtRHxb9gQxEPdQOtpeQE4y/AlDphoU6KSejKqjkDFuFTw6HVtckQZl7UuJA+eGQyFhkPaczqXALimj7+cw8OCYDfaohOv8fmCEDoen5EOQksw7rZKonReu19Rumw7YVM00iS+UKp/3oVtbAmWQYD+S1P1ynzd69UITQB2uOmDOlxw/qn2fWFLWf0CpHUAGeb8P1q7W5yfF1h3ZHj59tSGkRjmcra/LFRXHM7OuxVN9//qOavNQIGHZ7SA3OzHJi04kUEC/dkzvbd7QWIJXPwoxZ7JTiJX7vP+GnsI9x8WmMSds78v/0niJ0S5AQQJ/I/amUrtjdGQIDAQABAoIBAA/sQWV4MY5WnoeDeE5tAYKpQ2QtRoRGal9BNe57Wd11ujK7042h/unqrlxchA721goalxcYsmFb1nHPmWSUTVHugHU9G2SjaWH28shCm00DVh6IIWt6yuuZkezjEilrNIrnYPjKSjQxPhpWA+2vURNsORZ3x+7huM5kwrVd+CgldtgG8GnDDx20iVHUwdUtjjHiAB5O92iIWe5/kBMQoA2NT7uUfbnNvSax9OO0MKkVSXvmUh9XhYSznxuBJPZavj7VrO9PW6H8xWkhYe1UQpdFR6fvE3smXJ1AgEBcYZoKcO0QXIHVg4FCwSH/xsFIlGl5AQYmb6MGvIW6G5wiv+ECgYEA/yDfok5QhtLUUpxW8FvSgvCp0UG6WpXtiWKAf4SVZNxT1QW8koCnsnayxvTyUDmzjN03YvGGY5627CCHI3AFG5JZMXGIERO6Gl3FTzlq4QqgPQ5o9MwfgByoB5E/CE3K5aWQK35sV6uFW1GC6OiNell03ixrdKO2Mg5eh2tDzR0CgYEA8SgcfFVCmVrLg1+pyTbELNm/CstWPDuvPCaHHNoVpzl5d+PwG79nk+FyoYZodA+VB/2kTZVq6bQ0YXNDO8fum8ZiZufW0CfGWcy9z4cLvfJjUTirCDM38kecETcY47kKxKZjUOiOF952RLxjmZx4CadKvejuu11VKEziBqVu2y0CgYBmAmLopp+UCOBUV6Z7XHuDV27O+JTme2QKtpPiaMTDG0V5u112xnJG7Sb2XiI06Z1dCWaH7UJqup8xMqBWDwg7yfxXxKk/CsAyoqOt1atiZ7lCMGzO1H8T3mFhBTZKv7AMunI2scnoE/CyXpkVP0ayUOplmyUr8fl7cjthsgXeEQKBgFrL8mWxqECbGdLd2sxCjXwhg7dptY86HZE1JFvtlIeAsUY9kPKxjyrzkDhWpc9E6qS2j/0SC83wJmSmhCLm9OS7veLm2U9IGntHBhQz0Wzz7QbwohyVRDQ5V/53UyyyR+agivY0iQNdpAPfNlTov51K2m5EXFY5Hs3snJFKCkIFAoGBANPitPLtpnOY0OnrqZnyztUfLX6aKJhHIF9ji+8j4euRe7bcGh4z8ObJuYAcW5mJC1eZrcIyIydRUpZr3c+Mem1vYmzp45ms9pCk76w2Y6yqVFuP1r93mW/4qCwaUUKWTBu7ziLb85qIfumsWRq6C04UKyFX06IHdd+JHwGfAUPm\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAor/CjcHdpqztuj6kYaDbKGFLPXilQgK/MXOjQd84ghzqit56zDk3LNnd8j+9RJPU6Pz68IMZecd23me8PktCx0TU3wvKS4zAtU1hvi4u1JnosYGdo2+1CR45xYASa2vMZfXgiDqgVfUlt1k4I6EAIV4YkkN4jx3edcvZv6Sg7IeCMSeAXlmxP3zVll+7L9V1eIt08R6G49UK4D+Y/GW1vv42K+nTHszLqh5vVA6JYij9qtj3n+uc2VY1/izRLPlOYWmXmVKCMIeTo7IYz0A6gR4RH99d+8hw3yLcpSBE6cJ7EOKAse40ns0kzEtZOzGkHogbNV+93QdGap+UdZuNDQIDAQABAoIBACC0jHJUTSibg8JzqDD+VExPEQGvZvZW+vkDFgG8y+xJx1BU2TSFIvNebN2rtWs8kgKoI/2FOu9gCCE1k3ypPygwSt7vzZ1VEbzdahD/0uVicIKLW5RmdGj6q/1meU0hAphSyuZVcbcUZpnr0f5G8nHCKQnriSSpifT+HCoI+VXOq2SDNQlyNAb/kE/xiA1FqJonrA/zVExMbxRg0CHrbgI9PhP4qwKEOEDUPTdFHoACr25j82R3migWo3OVnz3ChN7TOHeULWxQjnCFrsZJTHq+EnSSfY7RALVdtJzNsLfI+A9jL85a13U+qTF75bkT+OFtGLo+tTKA+QJmH/S0zzkCgYEA0sl96AAnetEElUN+SEtCEp+H67OLsQBtsMbBd3zzdiAKPK+QCrcbvNiM1WeHM4/cRoelZjdSYXnkhUhxT8ct8ye/+beCVcW6oOxBGiHGsNex5vjZwcGYN8oSNgdBXMTKWbQsoVRqImpQV/76hb/fbZDbKBsPyVCi94WASkhKnxcCgYEAxah1HvvQrrD0vxHh9EvWLY1RAx/2MsVWkcsey+DNBqKBXHrb4ex4DOSvsMru3fukFMT6OtK2GtblM1RnhElXdDxD+BkpEGC7ZngSHJL1sYxLIqz4lY3W0R68t6xnkOqVT1iGxSvvpTHDi9ZGYkFS3/Lo5M8i/H6WY+Z/7d5h63sCgYAPyR8wvLI4NGcPdpqCd4BfPKtFL5EKlGmij3/1ntnswsGBgfRbmRLutZj2cmZhqiho78enPAVjX2mJwb8apmP+jb+GyANuwPwVCRxnBJiIrd6Y2ZIVPJZVt0Bd43U1qVcuGJwvCM9Z/HQ/4syIL7Jf1jVTb5NjFDLgLpNI/Nj5yQKBgQCwoKyol1YQBUlwRMapy+sEobe3FySmkfmeJujKP4R3XVhED/XVmb5dpy3oyi9SZsBlXvBNCGZ67XW7vL0UVYW09PW4CqPLYuWT19A3gIvVsQyjW/Z3jlxcWx9A8utJcJckZHNqVqy77hBUMZKL0twAC81aSk91WpmBhETlh0fxaQKBgQDHvMUBc0LmWiSIkINfwr3+It/aqNrHUdFjHGaZGwuQbnbeMuelu0hiIHcEh1l4YeKQSl/hw9E5BX9qW3+4b85jgdSOrpNFZYYy2zzTHE+PAJC55xfM81Ot5dZAEBcdIu+rYVseZrXN6w4fNw8JJjW5uYu1hQgsoDx7sCIVo6Pr8g==\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwaN35ikG+8XxYdnvwH/aVedI5KS03gfcKKgmc/UENgy95P9kIdNpRZtDjiHaxxvynGyC8KpVbydIf6rpvR/GnRBHJAN7qm/mg6/JBxK4qEtzHE0FElDTLrqutSMTkH9ThHx1Uc5Cyf3GosWL8LtGe+fCUCmYIJwI3JaMj5bu+ax6eTsJIzqEpBaY1QhUuL8kl57BpGvbkTIu+wCkqt0ZcGKqmuHMxQDQBzXog5nqi6F0edyOHEWfW5x0Z9Lgmks2iwbBY5NEqy0CRy3XmijCdIUGwxS8+GF/+/B9qCGGeOMJ3Tff0jwGEqB1tre0F1odtZDUI4EjQ43eSeDItdnq3wIDAQABAoIBAQCBEVei1yfre9XX1i8jTVUXuzDwDgTslaqegu4WjnM/H6EXWU/B6CucFNCjlVdBLhS5RO7GQZLuou2FA0QHJn35RNdWXuf4A9xPXEUPbOAedSQF8iR2P99zn0VCQV4SC3x8q4R7gZMtFfVnm2sai4mAn0r6qa7X1Ylmlwab0wv46F3LPdpMuI571MwgWntoFBTvL8WdZ1lgOAw5S//wZNh+xabBWeYM1tdMFvCO96D+vwprZYye/FSRW0Hny1Pd00QG7uVETC04mm9u07IE+YkXrjuRvVGPXtAciUlQ4ySYNzSP2ILSj2GXG8Hynq3ecRn9CwCVh68kU3tb/kM0AJ+5AoGBAP5hhq4RszXIV/xC6SG0dEqxWbpFqVAPQ2aJYFcx9Nb30EbBm2QjzJgYyFZehl+N96es0kjYlnhi5QjD4vvDPhKkzxIViRjpHGrQ/9BxbjJ8hCW3AII1VoOEPstChnJkuQkKhKAdJhlSG3Qw0ybCGdAOUh9tmaXzdzaejDMdLV11AoGBAMLe+NZVNJBVmqoE//J5DV0eQvwTfTe5USKyqeOMjvcgQrP6Xuog6h5l4pTt10fXFYNkFhpE80gzrdTRFZKKoAI35/hsiOAr/92n8JIg92GZmKZ9fX4KiCNd6vEwqoMMnHbMbFuFOngrDEUD28U0lGFI6PtrSDwmpVuNMsxIu7iDAoGAf3XSjAnmZ/54x7enJPJMitiOgx1AlxLuzMPs+APaEJSfUbTU7bpaW6OfTleSsPJrsyKPQ1zzGGNFK70rUMclpSXbc85Coa68RHFwnLsZYkat2E/3+0ZKkR+Eb0hoIY2CgZs5lRjF7E4N34xPYM5FLNDgKUs7f8GcbEvJKBtojbkCgYEAvMvVfaITSPsG2034wuww3FSjRSGEoWYzi1BZdBILuLVSqpgZOPAmosjHGs7LUdi6CRAAsfa3VO5srdDb+5u+pieP4IkWm0lFnXRFiO3TfoWW9UaDPIfrmYg2RPKHYGvpctde69RJ736VZo/0bj0gvJgs0NkBpPU0I1zLKEwXQw0CgYBBCe/NFx/c4CW1hjp8cFgNZpGRXP8KS6Kq4VbAij3ydM+4pDkkr92D/GAp7hJRPkRfoSKqfqR5lNjediFztans7uj+XHVasTFMnO/uMohkhALGcS7jbQNXRNXMCoQmY21hRQPOYhNAvvQToiWw5Pc9x/nGl8dYJgxDRJ/xckcjwQ==\n-----END RSA PRIVATE KEY-----",
	}
	keysDec := make([]*rsa.PrivateKey, len(keys))
	for i, key := range keys {
		block, _ := pem.Decode([]byte(key))
		dec, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		keysDec[i] = dec
	}
	return keysDec
}

type TestingFileSeeker struct {
	Repo  string
	Files map[string][]byte
}

func NewFileSeeker() *TestingFileSeeker {
	return &TestingFileSeeker{
		Files: make(map[string][]byte),
	}
}

func (fs *TestingFileSeeker) GetFile(file *PKIFile) (*SeekFile, error) {
	path := file.ComputePath()
	data, ok := fs.Files[path]
	//fmt.Printf("GetFile %v %v\n", path, ok)
	if !ok {
		return nil, errors.New("File could not be found")
	}
	sf := &SeekFile{
		Repo: fs.Repo,
		File: file.Path,
		Data: data,
	}

	return sf, nil
}

func (fs *TestingFileSeeker) GetRepository(*PKIFile, CallbackExplore) error {
	//fmt.Printf("GetRepo\n")
	// Unused
	return nil
}

func (fs *TestingFileSeeker) AddFile(path string, payload []byte) {
	fs.Files[path] = payload
}

func Validate(talPath string, fs FileSeeker) int {
	validator := NewValidator()
	validator.DecoderConfig.ValidateStrict = false
	validator.Time = time.Now().UTC()

	manager := NewSimpleManager()
	manager.Validator = validator
	manager.FileSeeker = fs

	manager.AddInitial([]*PKIFile{
		&PKIFile{
			Path: talPath,
			Type: TYPE_TAL,
		},
	})

	manager.Explore(false, false)

	var count int
	for _, roa := range manager.Validator.ValidROA {
		d := roa.Resource.(*librpki.RPKIROA)
		count += len(d.Valids)
		/* for _, entry := range d.Valids {
		    fmt.Printf("Found ROA: AS%v %v-%v (%v)", d.ASN, entry.IPNet.String(), entry.MaxLength, manager.PathOfResource[roa].ComputePath())
		}*/
	}
	return count
}

func TestPKI(t *testing.T) {
	fs := NewFileSeeker()

	t.Logf("Creating keys\n")
	keys := CreateKeys()

	privkeyRoot := keys[0]
	pubkeyRoot := privkeyRoot.Public()

	privkeyManifest := keys[1]
	pubkeyManifest := privkeyManifest.Public()

	privkeyManifest2 := keys[2]
	pubkeyManifest2 := privkeyManifest2.Public()

	privkeyRoa := keys[3]
	pubkeyRoa := privkeyRoa.Public()

	privkeySubCert := keys[4]
	pubkeySubCert := privkeySubCert.Public()

	skiRoot, err := librpki.HashPublicKey(pubkeyRoot)
	assert.Nil(t, err)
	skiManifest, err := librpki.HashPublicKey(pubkeyManifest)
	assert.Nil(t, err)
	skiManifest2, err := librpki.HashPublicKey(pubkeyManifest2)
	assert.Nil(t, err)
	skiROA, err := librpki.HashPublicKey(pubkeyRoa)
	assert.Nil(t, err)
	skiSubCert, err := librpki.HashPublicKey(pubkeySubCert)
	assert.Nil(t, err)

	genTime := time.Now().UTC()
	validity := time.Duration(time.Hour * 24 * 365 * 10)

	// TAL
	t.Logf("Creating TAL\n")

	tal, err := librpki.CreateTAL([]string{"rsync://lambda/module/root.cer"}, privkeyRoot.Public())
	assert.Nil(t, err)
	data, err := librpki.EncodeTAL(tal)
	assert.Nil(t, err)

	talPath := "rsync://lambda/module/example.tal"
	fs.AddFile(talPath, data)

	// CERT
	t.Logf("Creating certificates\n")
	_, net1, _ := net.ParseCIDR("0.0.0.0/0")
	_, net2, _ := net.ParseCIDR("::/0")

	ipBlocks := []librpki.IPCertificateInformation{
		&librpki.IPNet{
			IPNet: net1,
		},
		&librpki.IPNet{
			IPNet: net2,
		},
	}
	ipblocksExtension, err := librpki.EncodeIPAddressBlock(ipBlocks)
	ipBlocks2 := []librpki.IPCertificateInformation{
		&librpki.IPAddressNull{
			Family: 1,
		},
	}
	ipblocksExtension2, err := librpki.EncodeIPAddressBlock(ipBlocks2)
	assert.Nil(t, err)

	parentPath, err := librpki.EncodeInfoAccess(true, "rsync://lambda/module/root.cer")
	assert.Nil(t, err)
	manifestPath, err := librpki.EncodeInfoAccess(false, "rsync://lambda/module/root.mft")
	assert.Nil(t, err)
	manifestPath2, err := librpki.EncodeInfoAccess(false, "rsync://lambda/module/certs/test.mft")
	assert.Nil(t, err)
	roaPath, err := librpki.EncodeInfoAccess(false, "rsync://lambda/module/certs/test.roa")
	assert.Nil(t, err)
	parentSubPath, err := librpki.EncodeInfoAccess(true, "rsync://lambda/module/test.cer")
	assert.Nil(t, err)

	policy, err := librpki.EncodePolicyInformation("http://example.com/cps.html")
	assert.Nil(t, err)

	asnsBlock := []librpki.ASNCertificateInformation{
		&librpki.ASNRange{
			Min: 0,
			Max: 1<<31 - 1,
		},
	}
	asnExtension, err := librpki.EncodeASN(asnsBlock, nil)
	assert.Nil(t, err)
	asnsBlock2 := []librpki.ASNCertificateInformation{
		&librpki.ASNull{},
	}
	asnExtension2, err := librpki.EncodeASN(asnsBlock2, nil)
	assert.Nil(t, err)

	sias := []*librpki.SIA{
		&librpki.SIA{
			AccessMethod: librpki.CertRepository,
			GeneralName:  []byte("rsync://lambda/module/"),
		},
		&librpki.SIA{
			AccessMethod: librpki.SIAManifest,
			GeneralName:  []byte("rsync://lambda/module/root.mft"),
		},
	}
	siaExtension, err := librpki.EncodeSIA(sias)
	assert.Nil(t, err)

	siasSub := []*librpki.SIA{
		&librpki.SIA{
			AccessMethod: librpki.CertRepository,
			GeneralName:  []byte("rsync://lambda/module/certs/"),
		},
		&librpki.SIA{
			AccessMethod: librpki.SIAManifest,
			GeneralName:  []byte("rsync://lambda/module/certs/test.mft"),
		},
	}
	siaExtensionSub, err := librpki.EncodeSIA(siasSub)
	assert.Nil(t, err)

	t.Logf("Creating root certificate\n")
	rootCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Root",
		},
		ExtraExtensions: []pkix.Extension{
			*siaExtension,
			*ipblocksExtension,
			*asnExtension,
			*policy,
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skiRoot,
		NotBefore:             genTime,
		NotAfter:              genTime.Add(validity),
	}

	certBytesRoot, err := x509.CreateCertificate(rand.Reader, rootCert, rootCert, pubkeyRoot, privkeyRoot)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/root.cer", certBytesRoot)

	// CRL
	t.Logf("Creating CRL\n")
	crlBytes, err := librpki.CreateCRL(rootCert, rand.Reader, privkeyRoot, []pkix.RevokedCertificate{}, genTime, genTime.Add(validity), big.NewInt(1))
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/root.crl", crlBytes)

	// Organization
	orgCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(43),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Sub",
		},
		ExtraExtensions: []pkix.Extension{
			*siaExtensionSub,
			*ipblocksExtension,
			*asnExtension,
			*policy,
			*parentPath,
		},
		AuthorityKeyId:        skiRoot,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skiSubCert,
		NotBefore:             genTime,
		NotAfter:              genTime.Add(validity),
		CRLDistributionPoints: []string{"rsync://lambda/module/root.crl"},
	}

	certBytesOrg, err := x509.CreateCertificate(rand.Reader, orgCert, rootCert, pubkeySubCert, privkeyRoot)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/test.cer", certBytesOrg)

	orghash := sha256.Sum256(certBytesOrg)

	// CRL
	crlBytes, err = librpki.CreateCRL(orgCert, rand.Reader, privkeySubCert, []pkix.RevokedCertificate{}, genTime, genTime.Add(validity), big.NewInt(1))
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/certs/test.crl", crlBytes)
	crlhash := sha256.Sum256(crlBytes)

	// ROA
	t.Logf("Creating ROAs\n")
	_, prefix, _ := net.ParseCIDR("10.0.0.0/24")
	roaContent := []*librpki.ROAEntry{
		&librpki.ROAEntry{
			IPNet:     prefix,
			MaxLength: 24,
		},
	}
	roaContentEnc, err := librpki.EncodeROAEntries(65001, roaContent)
	assert.Nil(t, err)

	roaCms, err := librpki.EncodeCMS(nil, roaContentEnc, genTime)
	assert.Nil(t, err)

	roaCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(4453),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-ROA",
		},
		ExtraExtensions: []pkix.Extension{
			*policy,
			*ipblocksExtension,
			*parentSubPath,
			*roaPath,
		},
		NotBefore:             genTime,
		NotAfter:              genTime.Add(validity),
		SubjectKeyId:          skiROA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		AuthorityKeyId:        skiSubCert,
		CRLDistributionPoints: []string{"rsync://lambda/module/certs/test.crl"},
	}
	certBytesRoa, err := x509.CreateCertificate(rand.Reader, roaCert, orgCert, pubkeyRoa, privkeySubCert)
	assert.Nil(t, err)

	encap, err := librpki.ROAToEncap(roaContentEnc)
	assert.Nil(t, err)
	err = roaCms.Sign(rand.Reader, skiROA, encap, privkeyRoa, certBytesRoa)
	assert.Nil(t, err)

	cmsBytes, err := asn1.Marshal(*roaCms)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/certs/test.roa", cmsBytes)

	roahash := sha256.Sum256(cmsBytes)

	// Manifest Organization
	t.Logf("Creating manifest\n")
	manifestContent := librpki.ManifestContent{
		ManifestNumber: big.NewInt(7845),
		ThisUpdate:     time.Now().UTC(),
		NextUpdate:     time.Now().UTC(),
		FileHashAlg:    librpki.SHA256OID,
		FileList: []librpki.File{
			librpki.File{
				Name: "test.roa",
				Hash: asn1.BitString{
					Bytes:     roahash[:],
					BitLength: 256,
				},
			},
			librpki.File{
				Name: "test.crl",
				Hash: asn1.BitString{
					Bytes:     crlhash[:],
					BitLength: 256,
				},
			},
		},
	}
	manifestContentEnc, err := librpki.EncodeManifestContent(manifestContent)
	assert.Nil(t, err)

	manifestCms, err := librpki.EncodeCMS(nil, manifestContentEnc, genTime)
	assert.Nil(t, err)

	manifestCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(6542),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Manifest2",
		},
		NotBefore:      genTime,
		NotAfter:       genTime.Add(validity),
		SubjectKeyId:   skiManifest2,
		AuthorityKeyId: skiSubCert,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			*policy,
			*ipblocksExtension2,
			*parentSubPath,
			*manifestPath2,
			*asnExtension2,
		},
		CRLDistributionPoints: []string{"rsync://lambda/module/certs/test.crl"},
	}
	certBytesMft, err := x509.CreateCertificate(rand.Reader, manifestCert, orgCert, pubkeyManifest2, privkeySubCert)
	assert.Nil(t, err)

	encap, err = librpki.ManifestToEncap(manifestContentEnc)
	assert.Nil(t, err)
	err = manifestCms.Sign(rand.Reader, skiManifest2, encap, privkeyManifest2, certBytesMft)
	assert.Nil(t, err)

	cmsBytes, err = asn1.Marshal(*manifestCms)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/certs/test.mft", cmsBytes)

	// Manifest
	manifestContent = librpki.ManifestContent{
		ManifestNumber: big.NewInt(14562123),
		ThisUpdate:     time.Now().UTC(),
		NextUpdate:     time.Now().UTC().Add(time.Hour * 48),
		FileHashAlg:    librpki.SHA256OID,
		FileList: []librpki.File{
			librpki.File{
				Name: "test.cer",
				Hash: asn1.BitString{
					Bytes:     orghash[:],
					BitLength: 256,
				},
			},
			librpki.File{
				Name: "root.crl",
				Hash: asn1.BitString{
					Bytes:     orghash[:],
					BitLength: 256,
				},
			},
		},
	}
	manifestContentEnc, err = librpki.EncodeManifestContent(manifestContent)
	assert.Nil(t, err)

	manifestCms, err = librpki.EncodeCMS(nil, manifestContentEnc, genTime)
	assert.Nil(t, err)

	manifestCert = &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(55555),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Manifest",
		},
		NotBefore:      genTime,
		NotAfter:       genTime.Add(validity),
		SubjectKeyId:   skiManifest,
		AuthorityKeyId: skiRoot,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			*policy,
			*ipblocksExtension2,
			*parentPath,
			*manifestPath,
			*asnExtension2,
		},
		CRLDistributionPoints: []string{"rsync://lambda/module/root.crl"},
	}
	certBytesMft2, err := x509.CreateCertificate(rand.Reader, manifestCert, rootCert, pubkeyManifest, privkeyRoot)
	assert.Nil(t, err)

	encap, err = librpki.ManifestToEncap(manifestContentEnc)
	assert.Nil(t, err)
	err = manifestCms.Sign(rand.Reader, skiManifest, encap, privkeyManifest, certBytesMft2)
	assert.Nil(t, err)

	cmsBytes, err = asn1.Marshal(*manifestCms)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/root.mft", cmsBytes)

	t.Logf("Validating\n")
	count := Validate(talPath, fs)
	assert.Equal(t, 1, count)
}

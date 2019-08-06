package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cloudflare/cfrpki/sync/api"
	"github.com/cloudflare/cfrpki/sync/lib"
	"github.com/go-redis/redis"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"time"
)

var (
	Addr            = flag.String("addr", ":8080", "Listen address")
	RedisSrv        = flag.String("redis.srv", "localhost:6379", "Redis server for tops")
	RedisPrefix     = flag.String("redis.prefix", "cfrpkiapi:", "Redis prefix for keys")
	RedisExpiration = flag.String("redis.expiration", "10m", "Redis expiration time")
	RedisBatch      = flag.Int("redis.batch", 1000, "Batches when scanning")
	RedisExpiry     = flag.Int("redis.expiry", 3600, "Expiry")
	LogLevel        = flag.String("loglevel", "info", "Log level")
)

type RPKIServer struct {
	rclient     *redis.Client
	redisexpire time.Duration
	prefix      string
	batch       int64
	expiry      int64
}

func (server *RPKIServer) DeleteSIA(path string) error {
	keyRSYNC := fmt.Sprintf("%v%v", server.prefix, "fetch.rsync")
	data := server.rclient.HDel(keyRSYNC, path)
	if data == nil {
		log.Error("Data is nil")
		return errors.New("Data is nil")
	}
	keyRRDP := fmt.Sprintf("%v%v", server.prefix, "fetch.rrdp")
	data = server.rclient.HDel(keyRRDP, path)
	if data == nil {
		log.Error("Data is nil")
		return errors.New("Data is nil")
	}
	return nil
}

type rrdpInfo struct {
	SessionID string `json:"sessionid"`
	Serial    int64  `json:"serial"`
}

func (server *RPKIServer) GetRRDPInfo(ctx context.Context, query *cfrpki.RRDPInfoQuery) (*cfrpki.RRDPInfo, error) {
	key := fmt.Sprintf("%v%v", server.prefix, "rrdp.info")
	if query.RRDP != "" {
		data := server.rclient.HGet(key, query.RRDP)
		if data == nil {
			errMsg := fmt.Sprintf("GetRRDPInfo: Data at %v is nil", key)
			log.Error(errMsg)
			return nil, errors.New(errMsg)
		}
		dataR, err := data.Result()
		if err != nil && err != redis.Nil {
			return nil, err
		} else if err != nil && err == redis.Nil {
			return &cfrpki.RRDPInfo{}, nil
		}

		var dataEnc rrdpInfo

		buf := bytes.NewBufferString(dataR)
		dec := json.NewDecoder(buf)
		err = dec.Decode(&dataEnc)
		if err != nil {
			return nil, err
		}

		return &cfrpki.RRDPInfo{
			RRDP:      query.RRDP,
			SessionID: dataEnc.SessionID,
			Serial:    dataEnc.Serial,
		}, nil
	}

	return nil, nil
}

func (server *RPKIServer) PostRRDP(ctx context.Context, query *cfrpki.RRDPInfo) (*cfrpki.OperationResponse, error) {
	key := fmt.Sprintf("%v%v", server.prefix, "rrdp.info")
	if query.RRDP != "" {
		dataEnc := &rrdpInfo{
			SessionID: query.SessionID,
			Serial:    query.Serial,
		}

		buf := bytes.NewBufferString("")
		enc := json.NewEncoder(buf)
		err := enc.Encode(dataEnc)
		if err != nil {
			return nil, err
		}

		data := server.rclient.HSet(key, query.RRDP, buf.String())
		if data == nil {
			errMsg := fmt.Sprintf("PostRRDP: Data at %v is nil", key)
			log.Error(errMsg)
			return nil, errors.New(errMsg)
		}
	}

	return &cfrpki.OperationResponse{}, nil
}

func (server *RPKIServer) PostSIA(ctx context.Context, query *cfrpki.SIA) (*cfrpki.OperationResponse, error) {
	key := fmt.Sprintf("%v%v", server.prefix, "fetch.rsync")
	newExpiry := time.Now().UTC().UnixNano()/1000000000 + server.expiry

	data := server.rclient.HSet(key, query.RSYNC, fmt.Sprintf("%v", newExpiry))
	if data == nil {
		errMsg := fmt.Sprintf("PostSIA: Data at %v is nil", key)
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	if query.RRDP != "" {
		key = fmt.Sprintf("%v%v", server.prefix, "fetch.rrdp")
		data = server.rclient.HSet(key, query.RSYNC, query.RRDP)
		if data == nil {
			errMsg := fmt.Sprintf("PostSIA: Data at %v is nil", key)
			log.Error(errMsg)
			return nil, errors.New(errMsg)
		}
	}

	return &cfrpki.OperationResponse{}, nil
}

func (server *RPKIServer) PublishFile(ctx context.Context, query *cfrpki.ResourceData) (*cfrpki.OperationResponse, error) {
	dataStr := base64.RawStdEncoding.EncodeToString([]byte(query.Data))
	key := fmt.Sprintf("%v%v", server.prefix, "get.files")
	data := server.rclient.HSet(key, query.Path, dataStr)
	if data == nil {
		errMsg := fmt.Sprintf("PublishFile: Data at %v is nil", key)
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}
	return &cfrpki.OperationResponse{}, nil
}

func (server *RPKIServer) DeleteFile(ctx context.Context, query *cfrpki.ResourceData) (*cfrpki.OperationResponse, error) {
	key := fmt.Sprintf("%v%v", server.prefix, "get.files")
	data := server.rclient.HDel(key, query.Path)
	if data == nil {
		errMsg := fmt.Sprintf("DeleteFile: Data at %v is nil", key)
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}
	return &cfrpki.OperationResponse{}, nil
}

func (server *RPKIServer) DeleteDirectory(ctx context.Context, query *cfrpki.ResourceData) (*cfrpki.OperationResponse, error) {
	key := fmt.Sprintf("%v%v", server.prefix, "get.files")
	var offset uint64
	for {
		data := server.rclient.HScan(key, offset, fmt.Sprintf("%v*", query.Path), server.batch)

		if data == nil {
			errMsg := fmt.Sprintf("DeleteDirectory: Data at %v is nil", key)
			log.Error(errMsg)
			return nil, errors.New(errMsg)
		}
		_, cursor, err := data.Result()
		if err != nil {
			errMsg := fmt.Sprintf("DeleteDirectory: error getting results for %v: %v", key, err)
			log.Error(errMsg)
			return nil, errors.New(errMsg)
		}
		offset = cursor
		iter := data.Iterator()

		isKey := true
		for iter.Next() {
			val := iter.Val()
			if isKey {
				data := server.rclient.HDel(key, val)
				if data == nil {
					errMsg := fmt.Sprintf("DeleteFile: Data at %v is nil", key)
					log.Error(errMsg)
					return nil, errors.New(errMsg)
				}
			}
			isKey = !isKey
		}
		if cursor == 0 {
			break
		}
	}
	return &cfrpki.OperationResponse{}, nil
}

func (server *RPKIServer) GetRepository(query *cfrpki.ResourceQuery, srv cfrpki.RPKIAPI_GetRepositoryServer) error {
	key := fmt.Sprintf("%v%v", server.prefix, "get.files")
	var offset uint64
	for {
		data := server.rclient.HScan(key, offset, fmt.Sprintf("%v*", query.Path), server.batch)

		if data == nil {
			errMsg := fmt.Sprintf("GetRepository: Data at %v is nil", key)
			log.Error(errMsg)
			return errors.New(errMsg)
		}
		_, cursor, err := data.Result()
		if err != nil {
			errMsg := fmt.Sprintf("GetRepository: error getting results for %v: %v", key, err)
			log.Error(errMsg)
			return errors.New(errMsg)
		}
		offset = cursor
		iter := data.Iterator()

		isKey := true
		var prevKey string
		for iter.Next() {
			val := iter.Val()
			if !isKey {
				rr, err := MakeRessourceReply(prevKey, val)
				if err != nil {
					errMsg := fmt.Sprintf("GetRepository: error making ressource reply for %v: %v", val, err)
					log.Error(errMsg)
				} else {
					srv.Send(rr)
				}
			} else {
				prevKey = val
			}
			isKey = !isKey
		}
		if cursor == 0 {
			break
		}
	}

	return nil
}

func MakeRessourceReply(path string, data string) (*cfrpki.ResourceData, error) {
	dataB, err := base64.RawStdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	return &cfrpki.ResourceData{
		Path: path,
		Data: dataB}, nil
}

func (server *RPKIServer) GetResource(ctx context.Context, query *cfrpki.ResourceQuery) (*cfrpki.ResourceData, error) {
	key := fmt.Sprintf("%v%v", server.prefix, "get.files")
	data := server.rclient.HGet(key, query.Path)
	if data == nil {
		errMsg := fmt.Sprintf("GetResource: Data at %v %v is nil", key, query.Path)
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}
	dataD, err := data.Result()
	if err != nil {
		errMsg := fmt.Sprintf("GetResource: error getting results for %v %v: %v", key, query.Path, err)
		log.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	return MakeRessourceReply(query.Path, dataD)
}

func (server *RPKIServer) GetFetch(query *cfrpki.FetchQuery, srv cfrpki.RPKIAPI_GetFetchServer) error {
	key := fmt.Sprintf("%v%v", server.prefix, "fetch.rsync")
	var offset uint64
	rsyncMap := make(map[string]syncpki.SubMap)
	for {
		scan := fmt.Sprintf("%v*", query.Path)
		data := server.rclient.HScan(key, offset, scan, server.batch)

		if data == nil {
			errMsg := fmt.Sprintf("GetFetch: Data at %v %v is nil", key, scan)
			log.Error(errMsg)
			return errors.New(errMsg)
		}
		_, cursor, err := data.Result()
		if err != nil {
			errMsg := fmt.Sprintf("GetFetch: error getting results for %v %v: %v", key, scan, err)
			log.Error(errMsg)
			return errors.New(errMsg)
		}
		offset = cursor
		iter := data.Iterator()

		isKey := true
		for iter.Next() {
			val := iter.Val()
			if !isKey {
				// toDelete
			} else {
				syncpki.AddInMap(val, rsyncMap)
			}
			isKey = !isKey
		}
		if cursor == 0 {
			break
		}
	}

	rsyncRedMap := syncpki.ReduceMap(rsyncMap)
	for _, v := range rsyncRedMap {
		srv.Send(&cfrpki.SIA{
			RSYNC: v,
		})
	}
	return nil
}

func (server *RPKIServer) GetFetchRRDP(query *cfrpki.FetchQuery, srv cfrpki.RPKIAPI_GetFetchRRDPServer) error {
	key := fmt.Sprintf("%v%v", server.prefix, "fetch.rrdp")
	var offset uint64
	RRDPMap := make(map[string]map[string]syncpki.SubMap)
	for {
		scan := fmt.Sprintf("%v*", query.Path)
		data := server.rclient.HScan(key, offset, scan, server.batch)

		if data == nil {
			errMsg := fmt.Sprintf("GetFetchRRDP: Data at %v %v is nil", key, scan)
			log.Error(errMsg)
			return errors.New(errMsg)
		}
		_, cursor, err := data.Result()
		if err != nil {
			errMsg := fmt.Sprintf("GetFetchRRDP: error getting results for %v %v: %v", key, scan, err)
			log.Error(errMsg)
			return errors.New(errMsg)
		}
		offset = cursor
		iter := data.Iterator()

		isKey := true
		var rsyncVal string
		for iter.Next() {
			val := iter.Val()
			if !isKey {
				tmpRRDPMap, ok := RRDPMap[val]
				if !ok {
					tmpRRDPMap = make(map[string]syncpki.SubMap)
					RRDPMap[val] = tmpRRDPMap
				}
				syncpki.AddInMap(rsyncVal, tmpRRDPMap)
			} else {
				rsyncVal = val
			}
			isKey = !isKey
		}
		if cursor == 0 {
			break
		}
	}

	for k, v := range RRDPMap {
		tmpRedMap := syncpki.ReduceMap(v)
		for _, vv := range tmpRedMap {
			srv.Send(&cfrpki.SIA{
				RSYNC: vv,
				RRDP:  k,
			})
		}
	}
	return nil
}

func main() {
	flag.Parse()
	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	redisDur, err := time.ParseDuration(*RedisExpiration)
	if err != nil {
		log.Fatal(err)
	}

	server := &RPKIServer{
		redisexpire: redisDur,
		prefix:      *RedisPrefix,
		batch:       int64(*RedisBatch),
		expiry:      int64(*RedisExpiry),
	}

	server.rclient = redis.NewClient(&redis.Options{
		Addr:     *RedisSrv,
		Password: "",
		DB:       0,
	})
	pong, err := server.rclient.Ping().Result()
	if err != nil {
		log.Fatalf("%v %v", pong, err)
	} else {
		log.Infof("Successful ping to Redis %v: %v", *RedisSrv, pong)
	}

	fmt.Printf("Server started\n")
	conn, err := net.Listen("tcp", *Addr)
	if err != nil {
		log.Fatal(err)
	}
	gs := grpc.NewServer()
	cfrpki.RegisterRPKIAPIServer(gs, server)
	gs.Serve(conn)
}

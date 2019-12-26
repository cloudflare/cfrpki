# Cloudflare RPKI Validator Tools and Libraries

CFRPKI is a collection of tools and libraries to perform RPKI relying party software
operations.

To get started with Cloudflare's Relying Party software, go to the section **[OctoRPKI](#octorpki)** 🐙.

## Disclaimer

_This software comes with no warranties._

## Components

### Libraries

`sync/lib` can synchronize RRDP and RSYNC repositories.

`sync/api` provides an easy method to scale a validator using an API for storage.
Includes protobuf and basic functions.

`validator/pki` maintains a certificate store and performs validation.

`validator/lib` decodes RPKI resources.

### Tools

`cmd/localrpki` performs simple validation against files and generate a JSON prefix list.

`cmd/ctrpki` performs simple validation against files and send them to a Certificate Transparency Log.

`cmd/octorpki` perfoms complete validation, with RRDP and Rsync.
See the section below for more information.

The tools prefixed by `api` are modules that can live independently
of each other. This is useful for development or setting up a
distributed setup.

## Getting started

### Fetching the TALs

All the TALs files are included in the repo except ARIN.

You can download the RFC 7730 format at the following address: https://www.arin.net/resources/rpki/tal.html
and drop it in the `tals/` folder.

### OctoRPKI

This is the standalone tool provided by Cloudflare to perform RPKI Validation.
It should cover the most common use cases. It is the data provider behind
https://rpki.cloudflare.com/rpki.json.

![OctoRPKI](resources/octorpki.png)

It can be used as a one-off or as an HTTP server (set `-mode server|oneoff`).

The generated ROA list is compatible with [GoRTR](https://github.com/cloudflare/gortr)
to provide routers the prefixes.
The list can be signed using ECDSA signatures to be redistributed more securely
(via a CDN or other caches).

It provides metrics on validation (times, numbers of files) and logs the requests.

All the files will be stored locally.
The initialization time will vary and use by default RRDP then Rsync (failed RRDP
will failover to Rsync).

It will keep fetching/revalidating until in a stable state (no new endpoints added).
By default, when unstable, the server will return `503` in order to avoid distributing partial data.
This feature can be disabled by passing `-output.wait=false`.

The initial startup requires at least 3 iterations which takes around 5 minutes
(while a refresh takes 2 minutes):

- Fetching root certificates listed in TAL (via rsync)
- Fetching repositories listed in the root certificates (RRDP and Rsync)
- Fetching sub-repositories (National Internet Registries and delegated organizations)

To install, you can either:

- Fetch a binary on the [Releases page](https://github.com/cloudflare/cfrpki/releases)
- Use `go get`
- Compile it manually

If you choose to use `go get` (your binary will be in: `~/go/bin/octorpki` or in `$GOPATH/bin/octorpki`)
```
$ go get github.com/cloudflare/cfrpki/cmd/octorpki
```

If you choose to compile, after you cloned the repository:
```
$ cd cmd/octorpki && go build octorpki.go
```

To run

```
$ ./octorpki -h
```

It is also available as a docker container. Do not forget to add the TAL files in the `tals/` folder.

```
$ mkdir tals && mkdir cache && touch cache/rrdp.json
$ chmod 770 -R tals && chmod 770 -R cache && chmod 770 cache/rrdp.json
$ docker run -ti --net=host -v $PWD/tals:/tals -v $PWD/cache:/cache -p 8080:8080 cloudflare/octorpki
```

Depending on your Docker configuration, you may need to set `--net=host` and set permissions for the files in order to avoid some errors.

Using the default settings, you can access the generated ROAs list on
http://localhost:8080/output.json.
Statistics are available on http://localhost:8080/infos in JSON.
You can also plug a Prometheus server on the metrics endpoint http://localhost:8080/metrics.
The current state of RRDP fetch will be stored in cache/rrdp.json file.

#### [GoRTR](https://github.com/cloudflare/gortr)

In order to send the computed list of ROAs to the router, the router must be
connected to a cache using RTR protocol.

OctoRPKI does not embed a RTR server. Since generating list of ROAs takes a lot of compute time,
it was designed separate the distribution of files from the cryptographic operations.

[GoRTR](https://github.com/cloudflare/gortr) was created by Cloudflare to use a list of ROAs
from either OctoRPKI or similar tools able to produce a JSON file.

To connect with GoRTR **securely**, you will need to setup a private key.

```
$ openssl ecparam -genkey -name prime256v1 -noout -outform pem > private.pem
```

You can force OctoRPKI to use the key by passing `-output.sign.key private.pem`.

Then extract the public key

```
$ openssl ec -in private.pem -pubout -outform pem > public.pem
```

If OctoRPKI is running locally using the default port and file (http://localhost:8080/output.json), you can connect GoRTR:

```
$ ~/go/bin/gortr -verify.key public.pem -cache http://localhost:8080/output.json
```

To disable signing, use the following flag on OctoRPKI `-output.sign=false` and `-verify=false` on GoRTR.

### Connect your routers and start filtering

You can then connect your router to GoRTR using the RPKI to Router Protocol (RTR).

Juniper instructions are available on the [project's page](https://github.com/cloudflare/gortr#configure-on-juniper).

### Developing and distributed use cases

To develop or implement RPKI features, it is advised to
use the API which will store the certificates in a Redis database.

Other use-cases include being able to run multiple validators
on the same data and without relying on filesystem storage (limitation caused by Rsync).

Start docker-compose:

```
$ cd cmd/api/
$ docker-compose up
```

Start the API:

```
$ cd cmd/api/
$ go run api.go
```

Start the components to synchronize the files:

```
$ cd cmd/api-rsync && go run rsync.go
$ cd cmd/api-rrdp && go run rrdp.go
```

Finally, start the Validator

```
$ cd cmd/api-validator && go run validator.go
```

It will work iteratively. Each validation may bring more endpoints to synchronize
until a stable state.

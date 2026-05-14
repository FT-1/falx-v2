module github.com/ft-1/falx-v2/soc-backend

go 1.22

require (
	github.com/BurntSushi/toml           v1.3.2
	github.com/cilium/ebpf              v0.15.0
	github.com/golang-jwt/jwt/v5        v5.2.1
	github.com/gorilla/mux              v1.8.1
	github.com/gorilla/websocket        v1.5.3
	github.com/mattn/go-sqlite3         v1.14.22
	github.com/prometheus/client_golang  v1.19.1
	go.uber.org/zap                     v1.27.0
	golang.org/x/crypto                 v0.24.0
	golang.org/x/sys                    v0.21.0
	google.golang.org/grpc              v1.64.0
	google.golang.org/protobuf          v1.34.2
	github.com/ft-1/falx-v2/control-plane v0.1.0
)

replace github.com/ft-1/falx-v2/control-plane => ../control-plane

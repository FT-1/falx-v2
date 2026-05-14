module github.com/ft-1/falx-v2/tests

go 1.22

require (
	github.com/ft-1/falx-v2/control-plane v0.1.0
	go.uber.org/zap                       v1.27.0
)

replace github.com/ft-1/falx-v2/control-plane => ../control-plane

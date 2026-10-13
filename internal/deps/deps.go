//go:build deps

// Package deps pins the module dependencies shared by every wg-tunnel package,
// so go mod tidy keeps them in go.mod while individual packages are written.
// It is never compiled into a binary (build tag "deps").
package deps

import (
	_ "github.com/golang-jwt/jwt/v5"
	_ "github.com/pion/turn/v5"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "golang.org/x/crypto/ssh"
	_ "golang.zx2c4.com/wireguard/conn"
	_ "golang.zx2c4.com/wireguard/device"
	_ "golang.zx2c4.com/wireguard/tun/netstack"
	_ "k8s.io/api/core/v1"
	_ "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/kubernetes"
)

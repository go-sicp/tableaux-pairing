//go:build tools

// This file anchors build-time dependencies that no runtime Go file
// imports. Without it, `go mod tidy` drops golang.org/x/mobile/bind from
// go.mod and `gomobile bind` fails with "no Go package in
// golang.org/x/mobile/bind".
package tools

import _ "golang.org/x/mobile/bind"

# tableaux-pairing

Go module powering the **QR-driven fleet-pairing companion app** for
[`tableaux-eink`](../tableaux-eink). The Philips Tableaux 32BDL5150I/00
has no NFC controller (Ethernet / Wi-Fi / Bluetooth 5.1 only), so
pairing happens through the QR shown by the running display + a
workstation-side or phone-side OpenBao client.

Exposes the same `Bundle` / OpenBao / connection-URI primitives to:

- a Go CLI (`tableaux-pair`) for workstation use, and
- an Android Compose app via `gomobile bind` (the runbook's
  long-promised QR-driven onboarding companion).

The Android app's UI shell (camera + ZXing QR scanner, Compose screens)
lives in the `tableaux-companion-android` repo (separate, not in this
module). All non-trivial logic — URI parsing, OpenBao KV v2 ops,
AppRole login, Bundle serialisation — sits here so it can be unit
tested without an emulator.

## Layout

```
tableaux-pairing/
├── connecturi/        parse/build tableaux:// URIs
├── openbao/           AppRole + KV v2 client (stdlib net/http only)
├── pair/              gomobile-friendly facade: Bundle + OpenBao
└── cmd/tableaux-pair/ workstation CLI exercising the above
```

The `pair` package is the *only* one consumed by the Android binding.
`connecturi` and `openbao` are internal building blocks that callers
should reach through `pair`.

## Why a separate module?

- Any code shipped in the AAR pulls in its transitive dependencies on
  the JVM side. Keeping the dependency surface to **stdlib only** (no
  CBOR libs, no Vault SDK, no logger) means the AAR weighs
  ~1.5 MB stripped — small enough to stash inside the companion APK.
- The `tableaux-eink` Android project compiles for `arm64-v8a` only;
  the companion may need `arm64-v8a` + `armeabi-v7a` + `x86_64` (for
  emulators). Keeping the modules separate avoids polluting the
  display app's NDK config.
- The display-side `eink-grpc` already has its own canonical
  `ConnectUri.kt`. This module's `connecturi` is the **client** side;
  shapes match, but they're independent codebases that each enforce
  the contract in unit tests.

## Build & test from the workspace root

The parent `go.work` references this module so all `go` commands work
from anywhere in the repo:

```sh
# from /…/sicp
go build ./tableaux-pairing/...
go vet   ./tableaux-pairing/...
go test  ./tableaux-pairing/...
```

The CLI:

```sh
go install github.com/go-sicp/tableaux-pairing/cmd/tableaux-pair@latest
tableaux-pair parse 'tableaux://10.0.0.1:50051?token=op&fp=AB%3ACD&serial=panel-7'
```

## gomobile bind for Android

Prerequisites:

- Go ≥ 1.22
- Android NDK r26+ (typically already on `$ANDROID_NDK_ROOT` from
  the tableaux-eink Android setup)
- `gomobile` toolchain:
  ```sh
  go install golang.org/x/mobile/cmd/gomobile@latest
  go install golang.org/x/mobile/cmd/gobind@latest
  gomobile init
  ```

Build the AAR:

```sh
cd tableaux-pairing
gomobile bind \
  -target=android \
  -androidapi 26 \
  -o tableaux-pairing.aar \
  ./pair
```

Output: `tableaux-pairing.aar` (~1.5 MB). The companion app's
`build.gradle.kts`:

```kotlin
dependencies {
    implementation(files("libs/tableaux-pairing.aar"))
}
```

Kotlin usage from the companion app:

```kotlin
import pair.Pair       // package generated from `pair`
import pair.Bundle
import pair.OpenBao

// 1. operator scans QR
val qrPayload = "tableaux://10.0.0.1:50051?token=op&fp=AB%3ACD&serial=panel-7"
val skeleton: Bundle = Pair.parseURI(qrPayload)

// 2. fetch the rest of the credentials from OpenBao
val bao: OpenBao = Pair.newOpenBao(
    "https://bao.internal:8200",
    /* roleID */   "...",
    /* secretID */ "...",
)
val full: Bundle = bao.getBundle(skeleton.serial())

// 3. companion app now holds Operator/Admin tokens, cert/key PEMs, …
//    — drop them into the gRPC client of the Kotlin tableaux-cli, do
//    Health, Refresh, Rotate, … from the phone.
```

Type mapping notes (gomobile bind):

| Go              | Java/Kotlin           |
|-----------------|-----------------------|
| `string`        | `String`              |
| `int32`         | `int` / `Int`         |
| `[]byte`        | `byte[]` / `ByteArray`|
| `error`         | thrown `Exception`    |
| `Bundle` iface  | `pair.Bundle` Java iface |
| `OpenBao` iface | `pair.OpenBao` Java iface |

Constructors are generated as static methods on a `Pair` Java class
(named after the Go package).

## Threat model

The companion app holds the **OpenBao AppRole `secret_id`** for the
operator. That is the only sensitive material that lives on the phone
between sessions. Every other credential is fetched on-demand from
OpenBao for the duration of a single screen interaction and is
discarded by the JVM GC.

Lose the phone → revoke its `secret_id` (cf. `tableaux-eink`
RUNBOOK §3.7); never do a full fleet-wide rotation just because one
phone disappeared. The phone never holds the display's TLS material
at rest.

## Contract with `tableaux-eink`

| Concern | Owner |
|---|---|
| Display QR generation | `tableaux-eink/eink-grpc/.../qr/ConnectUri.kt` |
| Display QR parsing on phone | `tableaux-pairing/connecturi/` |
| OpenBao schema (`secret/fleet/<serial>`) | both must agree on field names — checked by [pair tests](pair/pair_test.go) and [RUNBOOK §1.7](../tableaux-eink/RUNBOOK.md#17-store-in-the-secret-manager) |
| AppRole roles (`fleet-manager`, `fleet-display`) | runbook §0.3 / §0.4 |
| Bundle on-the-wire JSON | `pair.Bundle.MarshalJSON` (this repo) |

Any change to the QR shape or the OpenBao schema must land in both
modules in lockstep, gated by a CI run on the workspace root.

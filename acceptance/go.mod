module github.com/zlint/internalca-acceptance

go 1.27.0

require (
	github.com/zmap/zcrypto v0.0.0-20261019024832-30d2182c7466
	github.com/zmap/zlint/v3 v3.0.0
)

require (
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/weppos/publicsuffix-go v0.50.4-0.20261018191641-fa5685825dd4 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/zmap/zlint/v3 => ../v3

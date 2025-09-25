.PHONY: clean build-rust generate run

install:
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.4.0+v0.28.3

clean:
	cargo clean
	rm -rf go/uniffi_example/

build-rust:
	cargo build

generate: build-rust
	uniffi-bindgen-go --library ../target/debug/libiroh_streamplace.dylib --out-dir go/
	cp ../target/debug/libiroh_streamplace.dylib go/

run: generate
	cd go && CGO_LDFLAGS="-L. -liroh_streamplace" go run main.go $(TICKET)


target/debug/bakatsugi: target/debug/injector target/debug/libbakatsugi.so
	objcopy \
		--add-section .bakatsugi=target/debug/libbakatsugi.so \
		--set-section-flags .bakatsugi=noload,readonly \
		target/debug/injector $@

.PHONY: target/debug/injector
target/debug/injector:
	cargo build --bin injector

.PHONY: target/debug/libbakatsugi.so
target/debug/libbakatsugi.so:
	cargo build --lib

.PHONY: clean
clean:
	cargo clean

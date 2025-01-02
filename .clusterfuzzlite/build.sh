#!/bin/bash -eu
go mod tidy && go mod vendor
go get github.com/AdaLogics/go-fuzz-headers@latest
go mod vendor

compile_go_fuzzer github.com/opencontainers/umoci/oci/casext Fuzz casext_fuzz
compile_go_fuzzer github.com/opencontainers/umoci/oci/layer FuzzUnpack fuzz_unpack
compile_go_fuzzer github.com/opencontainers/umoci/oci/layer FuzzGenerateLayer fuzz_generate_layer
compile_go_fuzzer github.com/opencontainers/umoci/mutate FuzzMutate fuzz_mutate
compile_go_fuzzer github.com/opencontainers/umoci/pkg/hardening Fuzz fuzz_hardening



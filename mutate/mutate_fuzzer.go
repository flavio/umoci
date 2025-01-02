//go:build gofuzz
// +build gofuzz

/*
 * umoci: Umoci Modifies Open Containers' Images
 * Copyright (C) 2021 SUSE LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mutate

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/opencontainers/go-digest"
	imeta "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci/oci/cas"
	casdir "github.com/opencontainers/umoci/oci/cas/dir"
	"github.com/opencontainers/umoci/oci/casext"
)

// fuzzSetup() does the necessary setup for the fuzzer
// It takes a data parameter provided by the fuzzer
func fuzzSetup(dir string, data []byte) (cas.Engine, ispec.Descriptor, error) {
	dir = filepath.Join(dir, "image")
	if err := casdir.Create(dir); err != nil {
		return nil, ispec.Descriptor{}, err
	}

	engine, err := casdir.Open(dir)
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}
	engineExt := casext.NewEngine(engine)

	// Write a tar layer.
	var buffer bytes.Buffer
	tw := tar.NewWriter(&buffer)
	tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "test",
		Mode:     0644,
		Size:     int64(len(data)),
	})
	tw.Write(data)
	tw.Close()

	// Push the base layer.
	diffidDigester := cas.BlobAlgorithm.Digester()
	hashReader := io.TeeReader(&buffer, diffidDigester.Hash())
	layerDigest, layerSize, err := engine.PutBlob(context.Background(), hashReader)
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}

	// Create a config.
	config := ispec.Image{
		Config: ispec.ImageConfig{
			User: "default:user",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []digest.Digest{diffidDigester.Digest()},
		},
		History: []ispec.History{
			{EmptyLayer: false},
		},
	}

	configDigest, configSize, err := engineExt.PutBlobJSON(context.Background(), config)
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}

	// Create the manifest.
	manifest := ispec.Manifest{
		Versioned: imeta.Versioned{
			SchemaVersion: 2,
		},
		MediaType: ispec.MediaTypeImageManifest,
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      configSize,
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Digest:    layerDigest,
				Size:      layerSize,
			},
		},
	}

	manifestDigest, manifestSize, err := engineExt.PutBlobJSON(context.Background(), manifest)
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}

	return engine, ispec.Descriptor{
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    manifestDigest,
		Size:      manifestSize,
	}, nil
}

// FuzzMutate implements the fuzzer
func FuzzMutate(data []byte) int {
	c := fuzz.NewConsumer(data)
	byteArray, err := c.GetBytes()
	if err != nil {
		return -1
	}
	dir, err := ioutil.TempDir("", "umoci-TestMutateAdd")
	if err != nil {
		return -1
	}
	defer os.RemoveAll(dir)

	engine, fromDescriptor, err := fuzzSetup(dir, byteArray)
	if err != nil {
		return 0
	}
	defer engine.Close()

	mutator, err := New(engine, casext.DescriptorPath{Walk: []ispec.Descriptor{fromDescriptor}})
	if err != nil {
		return 0
	}

	// This isn't a valid image, but whatever.
	fuzzedBytes, err := c.GetBytes()
	if err != nil {
		return -1
	}
	buffer := bytes.NewReader(fuzzedBytes)

	m := make(map[string]string)
	err = c.FuzzMap(&m)
	if err != nil {
		return 0
	}

	// Add a new layer.
	_, err = mutator.Add(context.Background(), ispec.MediaTypeImageLayer, buffer, &ispec.History{
		Comment: "new layer",
	}, GzipCompressor, m)
	if err != nil {
		return 0
	}

	newDescriptor, err := mutator.Commit(context.Background())
	if err != nil {
		return 0
	}

	mutator, err = New(engine, newDescriptor)
	if err != nil {
		return 0
	}

	// Cache the data to check it.
	if err := mutator.cache(context.Background()); err != nil {
		return 0
	}

	_, err = mutator.Manifest(context.Background())
	if err != nil {
		return 0
	}
	return 1
}

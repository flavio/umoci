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

package layer

import (
	"bytes"
	"encoding/base64"
	"io"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/umoci/oci/cas/dir"

	"context"

	"github.com/apex/log"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/umoci/oci/casext"

	"archive/tar"

	"io/ioutil"
	"os"
	"path/filepath"
	"unicode"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	fuzzheaders "github.com/AdaLogics/go-fuzz-headers"
	"github.com/vbatts/go-mtree"
)

// createRandomFile is a helper function
func createRandomFile(dirpath string, filename []byte, filecontents []byte) error {
	fileP := filepath.Join(dirpath, string(filename))
	if err := ioutil.WriteFile(fileP, filecontents, 0644); err != nil {
		return err
	}
	defer os.Remove(fileP)
	return nil
}

// createRandomDir is a helper function
func createRandomDir(basedir string, dirname []byte, dirArray []string) ([]string, error) {
	dirPath := filepath.Join(basedir, string(dirname))
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return dirArray, err
	}
	defer os.RemoveAll(dirPath)
	dirArray = append(dirArray, string(dirname))
	return dirArray, nil
}

// isLetter is a helper function
func isLetter(input []byte) bool {
	s := string(input)
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// FuzzGenerateLayer implements a fuzzer
// that targets layer.GenerateLayer().
func FuzzGenerateLayer(data []byte) int {
	if len(data) < 5 {
		return -1
	}
	if !fuzzheaders.IsDivisibleBy(len(data), 2) {
		return -1
	}
	half := len(data) / 2
	firstHalf := data[:half]
	f1 := fuzzheaders.NewConsumer(firstHalf)
	err := f1.Split(3, 30)
	if err != nil {
		return -1
	}

	secondHalf := data[half:]
	f2 := fuzzheaders.NewConsumer(secondHalf)
	err = f2.Split(3, 30)
	if err != nil {
		return -1
	}
	baseDir := "fuzz-base-dir"
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return -1
	}
	defer os.RemoveAll(baseDir)

	var dirArray []string
	iteration := 0
	chunkSize := len(f1.RestOfArray) / f1.NumberOfCalls
	for i := 0; i < len(f1.RestOfArray); i = i + chunkSize {
		from := i           //lower
		to := i + chunkSize //upper
		inputData := firstHalf[from:to]
		if len(inputData) > 6 && isLetter(inputData[:5]) {
			dirArray, err = createRandomDir(baseDir, inputData[:5], dirArray)
			if err != nil {
				continue
			}
		} else {
			if len(dirArray) == 0 {
				continue
			}
			dirp := int(inputData[0]) % len(dirArray)
			fp := filepath.Join(baseDir, dirArray[dirp])
			if len(inputData) > 10 {
				filename := inputData[5:8]
				err = createRandomFile(fp, filename, inputData[8:])
				if err != nil {
					continue
				}
			}
		}
		iteration++
	}

	// Get initial.
	initDh, err := mtree.Walk(baseDir, nil, append(mtree.DefaultKeywords, "sha256digest"), nil)
	if err != nil {
		return 0
	}
	iteration = 0
	chunkSize = len(f2.RestOfArray) / f2.NumberOfCalls
	for i := 0; i < len(f2.RestOfArray); i = i + chunkSize {
		from := i           //lower
		to := i + chunkSize //upper
		inputData := secondHalf[from:to]
		if len(inputData) > 6 && isLetter(inputData[:5]) {
			dirArray, err = createRandomDir(baseDir, inputData[:5], dirArray)
			if err != nil {
				continue
			}
		} else {
			if len(dirArray) == 0 {
				continue
			}
			dirp := int(inputData[0]) % len(dirArray)
			fp := filepath.Join(baseDir, dirArray[dirp])
			if len(inputData) > 10 {
				filename := inputData[5:8]
				err = createRandomFile(fp, filename, inputData[8:])
				if err != nil {
					continue
				}
			}
		}
		iteration++
	}

	// Get post.
	postDh, err := mtree.Walk(baseDir, nil, initDh.UsedKeywords(), nil)
	if err != nil {
		return 0
	}

	diffs, err := mtree.Compare(initDh, postDh, initDh.UsedKeywords())
	if err != nil {
		return -1
	}
	reader, err := GenerateLayer(baseDir, diffs, &RepackOptions{})
	if err != nil {
		return -1
	}
	defer reader.Close()

	tr := tar.NewReader(reader)
	for {
		_, err = tr.Next()
		if err != nil {
			break
		}
	}
	return 1
}

// mustDecodeString is a helper function
func mustDecodeString(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// makeImage is a helper function
func makeImage(base641, base642 string) (string, ispec.Manifest, casext.Engine, error) {

	ctx := context.Background()

	var layers = []struct {
		base64 string
		digest digest.Digest
	}{
		{
			base64: base641,
			digest: digest.NewDigestFromHex(digest.SHA256.String(), "e489a16a8ca0d682394867ad8a8183f0a47cbad80b3134a83412a6796ad9242a"),
		},
		{
			base64: base642,
			digest: digest.NewDigestFromHex(digest.SHA256.String(), "39f100ed000b187ba74b3132cc207c63ad1765adaeb783aa7f242f1f7b6f5ea2"),
		},
	}

	root, err := ioutil.TempDir("", "umoci-TestUnpackManifestCustomLayer")
	if err != nil {
		return "nil", ispec.Manifest{}, casext.Engine{}, err
	}

	// Create our image.
	image := filepath.Join(root, "image")
	if err := dir.Create(image); err != nil {
		return "nil", ispec.Manifest{}, casext.Engine{}, err
	}
	engine, err := dir.Open(image)
	if err != nil {
		return "nil", ispec.Manifest{}, casext.Engine{}, err
	}
	engineExt := casext.NewEngine(engine)

	// Set up the CAS and an image from the above layers.
	var layerDigests []digest.Digest
	var layerDescriptors []ispec.Descriptor
	for _, layer := range layers {
		var layerReader io.Reader

		layerReader = bytes.NewBuffer(mustDecodeString(layer.base64))
		layerDigest, layerSize, err := engineExt.PutBlob(ctx, layerReader)
		if err != nil {
			return "nil", ispec.Manifest{}, casext.Engine{}, err
		}

		layerDigests = append(layerDigests, layer.digest)
		layerDescriptors = append(layerDescriptors, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageLayerGzip,
			Digest:    layerDigest,
			Size:      layerSize,
		})
	}

	// Create the config.
	config := ispec.Image{
		OS: "linux",
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: layerDigests,
		},
	}
	configDigest, configSize, err := engineExt.PutBlobJSON(ctx, config)
	if err != nil {
		return "nil", ispec.Manifest{}, casext.Engine{}, err
	}
	configDescriptor := ispec.Descriptor{
		MediaType: ispec.MediaTypeImageConfig,
		Digest:    configDigest,
		Size:      configSize,
	}

	// Create the manifest.
	manifest := ispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: ispec.MediaTypeImageManifest,
		Config:    configDescriptor,
		Layers:    layerDescriptors,
	}

	return root, manifest, engineExt, nil
}

// FuzzUnpack implements a fuzzer
// that targets UnpackManifest().
func FuzzUnpack(data []byte) int {
	// We would like as little log output as possible:
	level, err := log.ParseLevel("fatal")
	if err != nil {
		return -1
	}
	log.SetLevel(level)
	ctx := context.Background()
	c := fuzz.NewConsumer(data)
	base641, err := c.GetString()
	if err != nil {
		return -1
	}

	base642, err := c.GetString()
	if err != nil {
		return -1
	}
	root, manifest, engineExt, err := makeImage(base641, base642)
	if err != nil {
		return 0
	}
	defer os.RemoveAll(root)

	bundle, err := ioutil.TempDir("", "umoci-TestUnpackManifestCustomLayer_bundle")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(bundle)

	unpackOptions := &UnpackOptions{MapOptions: MapOptions{
		UIDMappings: []rspec.LinuxIDMapping{
			{HostID: uint32(os.Geteuid()), ContainerID: 0, Size: 1},
			{HostID: uint32(os.Geteuid()), ContainerID: 1000, Size: 1},
		},
		GIDMappings: []rspec.LinuxIDMapping{
			{HostID: uint32(os.Getegid()), ContainerID: 0, Size: 1},
			{HostID: uint32(os.Getegid()), ContainerID: 100, Size: 1},
		},
		Rootless: os.Geteuid() != 0,
	}}

	unpackOptions.AfterLayerUnpack = func(m ispec.Manifest, d ispec.Descriptor) error {
		return nil
	}

	_ = UnpackManifest(ctx, engineExt, bundle, manifest, unpackOptions)

	return 1
}

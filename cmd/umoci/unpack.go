/*
 * umoci: Umoci Modifies Open Containers' Images
 * Copyright (C) 2016-2024 SUSE LLC
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

package main

import (
	"errors"
	"fmt"

	"github.com/opencontainers/umoci"
	"github.com/opencontainers/umoci/oci/cas/dir"
	"github.com/opencontainers/umoci/oci/casext"
	"github.com/opencontainers/umoci/oci/layer"
	"github.com/urfave/cli"
)

var unpackCommand = uxRemap(cli.Command{
	Name:  "unpack",
	Usage: "unpacks a reference into an OCI runtime bundle",
	ArgsUsage: `--image <image-path>[:<tag>] <bundle>

Where "<image-path>" is the path to the OCI image, "<tag>" is the name of the
tagged image to unpack (if not specified, defaults to "latest") and "<bundle>"
is the destination to unpack the image to.

It should be noted that this is not the same as oci-create-runtime-bundle,
because this command also will create an mtree specification to allow for layer
creation with umoci-repack(1).`,

	// unpack reads manifest information.
	Category: "image",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "keep-dirlinks",
			Usage: "don't clobber underlying symlinks to directories",
		},
	},

	Action: unpack,

	Before: func(ctx *cli.Context) error {
		if ctx.NArg() != 1 {
			return errors.New("invalid number of positional arguments: expected <bundle>")
		}
		if ctx.Args().First() == "" {
			return errors.New("bundle path cannot be empty")
		}
		ctx.App.Metadata["bundle"] = ctx.Args().First()
		return nil
	},
})

func unpack(ctx *cli.Context) error {
	imagePath := ctx.App.Metadata["--image-path"].(string)
	fromName := ctx.App.Metadata["--image-tag"].(string)
	bundlePath := ctx.App.Metadata["bundle"].(string)

	var unpackOptions layer.UnpackOptions
	var meta umoci.Meta
	meta.Version = umoci.MetaVersion

	// Parse and set up the mapping options.
	err := umoci.ParseIdmapOptions(&meta, ctx)
	if err != nil {
		return err
	}

	unpackOptions.KeepDirlinks = ctx.Bool("keep-dirlinks")
	unpackOptions.MapOptions = meta.MapOptions

	// Get a reference to the CAS.
	engine, err := dir.Open(imagePath)
	if err != nil {
		return fmt.Errorf("open CAS: %w", err)
	}
	engineExt := casext.NewEngine(engine)
	defer engine.Close()
	return umoci.Unpack(engineExt, fromName, bundlePath, unpackOptions)
}

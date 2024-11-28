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
	"context"
	"errors"
	"fmt"

	"github.com/opencontainers/umoci/oci/cas/dir"
	"github.com/opencontainers/umoci/oci/casext"
	"github.com/opencontainers/umoci/pkg/fmtcompat"
	"github.com/urfave/cli"
)

var gcCommand = cli.Command{
	Name:  "gc",
	Usage: "garbage-collects an OCI image's blobs",
	ArgsUsage: `--layout <image-path>

Where "<image-path>" is the path to the OCI image.

This command will do a mark-and-sweep garbage collection of the provided OCI
image, only retaining blobs which can be reached by a descriptor path from the
root set of references. All other blobs will be removed.`,

	// create modifies an image layout.
	Category: "layout",

	Before: func(ctx *cli.Context) error {
		if ctx.NArg() != 0 {
			return errors.New("invalid number of positional arguments: expected none")
		}
		if _, ok := ctx.App.Metadata["--image-path"]; !ok {
			return errors.New("missing mandatory argument: --layout")
		}
		return nil
	},

	Action: gc,
}

func gc(ctx *cli.Context) error {
	imagePath := ctx.App.Metadata["--image-path"].(string)

	// Get a reference to the CAS.
	engine, err := dir.Open(imagePath)
	if err != nil {
		return fmt.Errorf("open CAS: %w", err)
	}
	engineExt := casext.NewEngine(engine)
	defer engine.Close()

	// Run the GC.
	return fmtcompat.Errorf("gc: %w", engineExt.GC(context.Background()))
}

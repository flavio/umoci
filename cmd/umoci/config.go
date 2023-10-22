/*
 * umoci: Umoci Modifies Open Containers' Images
 * Copyright (C) 2016-2020 SUSE LLC
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
	"strings"
	"time"

	"github.com/apex/log"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci/mutate"
	"github.com/opencontainers/umoci/oci/cas/dir"
	"github.com/opencontainers/umoci/oci/casext"
	igen "github.com/opencontainers/umoci/oci/config/generate"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

// FIXME: We should also implement a raw mode that just does modifications of
//
//	JSON blobs (allowing this all to be used outside of our build setup).
var configCommand = uxHistory(uxTag(cli.Command{
	Name:  "config",
	Usage: "modifies the image configuration of an OCI image",
	ArgsUsage: `--image <image-path>[:<tag>] [--tag <new-tag>]

Where "<image-path>" is the path to the OCI image, and "<tag>" is the name of
the tagged image from which the config modifications will be based (if not
specified, it defaults to "latest"). "<new-tag>" is the new reference name to
save the new image as, if this is not specified then umoci will replace the old
image.`,

	// config modifies a particular image manifest.
	Category: "image",

	// Verify the metadata.
	Before: func(ctx *cli.Context) error {
		if ctx.NArg() != 0 {
			return errors.Errorf("invalid number of positional arguments: expected none")
		}
		if _, ok := ctx.App.Metadata["--image-path"]; !ok {
			return errors.Errorf("missing mandatory argument: --image")
		}
		if _, ok := ctx.App.Metadata["--image-tag"]; !ok {
			return errors.Errorf("missing mandatory argument: --image")
		}
		return nil
	},

	// Do not re-order arguments.
	//
	// It turns out that urfave/cli incorrectly handles cases like
	// [--config.cmd -c] during argument re-ordering for subcommands, causing
	// us a fair number of issues when users are trying to pass a flag an
	// argument that starts with a dash. Luckily 'umoci config' doesn't take
	// positional arguments, so disabling argument re-ordering has no other
	// real effect.
	//
	// See <https://github.com/urfave/cli/issues/1152> for more details.
	SkipArgReorder: true,

	Flags: []cli.Flag{
		cli.StringFlag{Name: "config.user"},
		cli.StringSliceFlag{Name: "config.exposedports"},
		cli.StringSliceFlag{Name: "config.env"},
		cli.StringSliceFlag{Name: "config.entrypoint"}, // FIXME: This interface is weird.
		cli.StringSliceFlag{Name: "config.cmd"},        // FIXME: This interface is weird.
		cli.StringSliceFlag{Name: "config.volume"},
		cli.StringSliceFlag{Name: "config.label"},
		cli.StringFlag{Name: "config.workingdir"},
		cli.StringFlag{Name: "config.stopsignal"},
		cli.StringFlag{Name: "created"}, // FIXME: Implement TimeFlag.
		cli.StringFlag{Name: "author"},
		cli.StringFlag{Name: "architecture"},
		cli.StringFlag{Name: "os"},
		cli.StringSliceFlag{Name: "manifest.annotation"},
		cli.StringSliceFlag{Name: "clear"},
	},

	Action: config,
}))

func toImage(config ispec.ImageConfig, meta mutate.Meta) ispec.Image {
	created := meta.Created
	return ispec.Image{
		Config:  config,
		Created: &created,
		Author:  meta.Author,
		Platform: ispec.Platform{
			Architecture: meta.Architecture,
			OS:           meta.OS,
		},
	}
}

func fromImage(image ispec.Image) (ispec.ImageConfig, mutate.Meta) {
	var created time.Time
	if image.Created != nil {
		created = *image.Created
	}
	return image.Config, mutate.Meta{
		Created:      created,
		Author:       image.Author,
		Architecture: image.Architecture,
		OS:           image.OS,
	}
}

// parseKV splits a given string (of the form name=value) into (name,
// value). An error is returned if there is no "=" in the line or if the
// name is empty.
func parseKV(input string) (string, string, error) {
	parts := strings.SplitN(input, "=", 2)
	if len(parts) != 2 {
		return "", "", errors.Errorf("must contain '=': %s", input)
	}

	name, value := parts[0], parts[1]
	if name == "" {
		return "", "", errors.Errorf("must have non-empty name: %s", input)
	}
	return name, value, nil
}

func config(ctx *cli.Context) error {
	imagePath := ctx.App.Metadata["--image-path"].(string)
	fromName := ctx.App.Metadata["--image-tag"].(string)

	// By default we clobber the old tag.
	tagName := fromName
	if val, ok := ctx.App.Metadata["--tag"]; ok {
		tagName = val.(string)
	}

	// Get a reference to the CAS.
	engine, err := dir.Open(imagePath)
	if err != nil {
		return errors.Wrap(err, "open CAS")
	}
	engineExt := casext.NewEngine(engine)
	defer engine.Close()

	fromDescriptorPaths, err := engineExt.ResolveReference(context.Background(), fromName)
	if err != nil {
		return errors.Wrap(err, "get descriptor")
	}
	if len(fromDescriptorPaths) == 0 {
		return errors.Errorf("tag not found: %s", fromName)
	}
	if len(fromDescriptorPaths) != 1 {
		// TODO: Handle this more nicely.
		return errors.Errorf("tag is ambiguous: %s", fromName)
	}

	mutator, err := mutate.New(engine, fromDescriptorPaths[0])
	if err != nil {
		return errors.Wrap(err, "create mutator for manifest")
	}

	config, err := mutator.Config(context.Background())
	if err != nil {
		return errors.Wrap(err, "get base config")
	}

	imageMeta, err := mutator.Meta(context.Background())
	if err != nil {
		return errors.Wrap(err, "get base metadata")
	}

	annotations, err := mutator.Annotations(context.Background())
	if err != nil {
		return errors.Wrap(err, "get base annotations")
	}

	g, err := igen.NewFromImage(toImage(config.Config, imageMeta))
	if err != nil {
		return errors.Wrap(err, "create new generator")
	}

	if ctx.IsSet("clear") {
		for _, key := range ctx.StringSlice("clear") {
			switch key {
			case "config.labels":
				g.ClearConfigLabels()
			case "manifest.annotations":
				annotations = nil
			case "config.exposedports":
				g.ClearConfigExposedPorts()
			case "config.env":
				g.ClearConfigEnv()
			case "config.volume":
				g.ClearConfigVolumes()
			case "rootfs.diffids":
				//g.ClearRootfsDiffIDs()
				return errors.Errorf("--clear=rootfs.diffids is not safe")
			case "config.cmd":
				g.ClearConfigCmd()
			case "config.entrypoint":
				g.ClearConfigEntrypoint()
			default:
				return errors.Errorf("unknown key to --clear: %s", key)
			}
		}
	}

	if ctx.IsSet("created") {
		// How do we handle other formats?
		created, err := time.Parse(igen.ISO8601, ctx.String("created"))
		if err != nil {
			return errors.Wrap(err, "parse --created")
		}
		g.SetCreated(created)
	}
	if ctx.IsSet("author") {
		g.SetAuthor(ctx.String("author"))
	}
	if ctx.IsSet("architecture") {
		g.SetArchitecture(ctx.String("architecture"))
	}
	if ctx.IsSet("os") {
		g.SetOS(ctx.String("os"))
	}
	if ctx.IsSet("config.user") {
		g.SetConfigUser(ctx.String("config.user"))
	}
	if ctx.IsSet("config.stopsignal") {
		g.SetConfigStopSignal(ctx.String("config.stopsignal"))
	}
	if ctx.IsSet("config.workingdir") {
		g.SetConfigWorkingDir(ctx.String("config.workingdir"))
	}
	if ctx.IsSet("config.exposedports") {
		for _, port := range ctx.StringSlice("config.exposedports") {
			g.AddConfigExposedPort(port)
		}
	}
	if ctx.IsSet("config.env") {
		for _, env := range ctx.StringSlice("config.env") {
			name, value, err := parseKV(env)
			if err != nil {
				return errors.Wrap(err, "config.env")
			}
			g.AddConfigEnv(name, value)
		}
	}
	// FIXME: This interface is weird.
	if ctx.IsSet("config.entrypoint") {
		g.SetConfigEntrypoint(ctx.StringSlice("config.entrypoint"))
	}
	// FIXME: This interface is weird.
	if ctx.IsSet("config.cmd") {
		g.SetConfigCmd(ctx.StringSlice("config.cmd"))
	}
	if ctx.IsSet("config.volume") {
		for _, volume := range ctx.StringSlice("config.volume") {
			g.AddConfigVolume(volume)
		}
	}
	if ctx.IsSet("config.label") {
		for _, label := range ctx.StringSlice("config.label") {
			name, value, err := parseKV(label)
			if err != nil {
				return errors.Wrap(err, "config.label")
			}
			g.AddConfigLabel(name, value)
		}
	}
	if ctx.IsSet("manifest.annotation") {
		if annotations == nil {
			annotations = map[string]string{}
		}
		for _, label := range ctx.StringSlice("manifest.annotation") {
			parts := strings.SplitN(label, "=", 2)
			annotations[parts[0]] = parts[1]
		}
	}

	var history *ispec.History
	if !ctx.Bool("no-history") {
		created := time.Now()
		history = &ispec.History{
			Author:     g.Author(),
			Comment:    "",
			Created:    &created,
			CreatedBy:  "umoci config",
			EmptyLayer: true,
		}

		if ctx.IsSet("history.author") {
			history.Author = ctx.String("history.author")
		}
		if ctx.IsSet("history.comment") {
			history.Comment = ctx.String("history.comment")
		}
		if ctx.IsSet("history.created") {
			created, err := time.Parse(igen.ISO8601, ctx.String("history.created"))
			if err != nil {
				return errors.Wrap(err, "parsing --history.created")
			}
			history.Created = &created
		}
		if ctx.IsSet("history.created_by") {
			history.CreatedBy = ctx.String("history.created_by")
		}
	}

	newConfig, newMeta := fromImage(g.Image())
	if err := mutator.Set(context.Background(), newConfig, newMeta, annotations, history); err != nil {
		return errors.Wrap(err, "set modified configuration")
	}

	newDescriptorPath, err := mutator.Commit(context.Background())
	if err != nil {
		return errors.Wrap(err, "commit mutated image")
	}

	log.Infof("new image manifest created: %s->%s", newDescriptorPath.Root().Digest, newDescriptorPath.Descriptor().Digest)

	if err := engineExt.UpdateReference(context.Background(), tagName, newDescriptorPath.Root()); err != nil {
		return errors.Wrap(err, "add new tag")
	}

	log.Infof("created new tag for image manifest: %s", tagName)
	return nil
}

package mutate

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"

	zstd "github.com/klauspost/compress/zstd"
	gzip "github.com/klauspost/pgzip"
	"github.com/stretchr/testify/assert"
)

const (
	fact = "meshuggah rocks!!!"
)

func TestNoopCompressor(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBufferString(fact)

	r, err := NoopCompressor.Compress(buf)
	assert.NoError(err)
	assert.Equal(NoopCompressor.MediaTypeSuffix(), "")

	content, err := ioutil.ReadAll(r)
	assert.NoError(err)

	assert.Equal(string(content), fact)
}

func TestGzipCompressor(t *testing.T) {
	assert := assert.New(t)

	buf := bytes.NewBufferString(fact)
	c := GzipCompressor

	r, err := c.Compress(buf)
	assert.NoError(err)
	assert.Equal(c.MediaTypeSuffix(), "gzip")

	r, err = gzip.NewReader(r)
	assert.NoError(err)

	content, err := ioutil.ReadAll(r)
	assert.NoError(err)

	assert.Equal(string(content), fact)

	// with options
	buf = bytes.NewBufferString(fact)
	c = GzipCompressor.WithOpt(GzipBlockSize(256 << 12))

	r, err = c.Compress(buf)
	assert.NoError(err)
	assert.Equal(c.MediaTypeSuffix(), "gzip")

	r, err = gzip.NewReader(r)
	assert.NoError(err)

	content, err = ioutil.ReadAll(r)
	assert.NoError(err)

	assert.Equal(string(content), fact)
}

func TestZstdCompressor(t *testing.T) {
	assert := assert.New(t)

	buf := bytes.NewBufferString(fact)
	c := ZstdCompressor

	r, err := c.Compress(buf)
	assert.NoError(err)
	assert.Equal(c.MediaTypeSuffix(), "zstd")

	dec, err := zstd.NewReader(r)
	assert.NoError(err)

	var content bytes.Buffer
	_, err = io.Copy(&content, dec)
	assert.NoError(err)
	assert.Equal(content.String(), fact)
}

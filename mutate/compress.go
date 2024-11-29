package mutate

import (
	"fmt"
	"io"
	"io/ioutil"
	"runtime"

	"github.com/apex/log"
	zstd "github.com/klauspost/compress/zstd"
	gzip "github.com/klauspost/pgzip"
	"github.com/opencontainers/umoci/pkg/system"
)

// Compressor is an interface which users can use to implement different
// compression types.
type Compressor interface {
	// Compress sets up the streaming compressor for this compression type.
	Compress(io.Reader) (io.ReadCloser, error)

	// MediaTypeSuffix returns the suffix to be added to the layer to
	// indicate what compression type is used, e.g. "gzip", or "" for no
	// compression.
	MediaTypeSuffix() string

	// BytesRead returns the number of bytes read from the uncompressed input
	// stream at the current time, no guarantee of completion.
	BytesRead() int64
}

type noopCompressor struct{}

func (nc noopCompressor) Compress(r io.Reader) (io.ReadCloser, error) {
	return ioutil.NopCloser(r), nil
}

func (nc noopCompressor) MediaTypeSuffix() string {
	return ""
}

func (nc noopCompressor) BytesRead() int64 {
	return -1
}

// NoopCompressor provides no compression.
var NoopCompressor Compressor = noopCompressor{}

// GzipCompressor provides gzip compression.
var GzipCompressor Compressor = &gzipCompressor{}

type gzipCompressor struct {
	bytesRead int64
}

func (gz *gzipCompressor) Compress(reader io.Reader) (io.ReadCloser, error) {
	pipeReader, pipeWriter := io.Pipe()

	gzw := gzip.NewWriter(pipeWriter)
	if err := gzw.SetConcurrency(256<<10, 2*runtime.NumCPU()); err != nil {
		return nil, fmt.Errorf("set concurrency level to %v blocks: %w", 2*runtime.NumCPU(), err)
	}
	go func() {
		bytesRead, err := system.Copy(gzw, reader)
		if err != nil {
			log.Warnf("gzip compress: could not compress layer: %v", err)
			// #nosec G104
			_ = pipeWriter.CloseWithError(fmt.Errorf("compressing layer: %w", err))
			return
		}
		gz.bytesRead = bytesRead
		if err := gzw.Close(); err != nil {
			log.Warnf("gzip compress: could not close gzip writer: %v", err)
			// #nosec G104
			_ = pipeWriter.CloseWithError(fmt.Errorf("close gzip writer: %w", err))
			return
		}
		if err := pipeWriter.Close(); err != nil {
			log.Warnf("gzip compress: could not close pipe: %v", err)
			// We don't CloseWithError because we cannot override the Close.
			return
		}
	}()

	return pipeReader, nil
}

func (gz gzipCompressor) MediaTypeSuffix() string {
	return "gzip"
}

func (gz gzipCompressor) BytesRead() int64 {
	return gz.bytesRead
}

// ZstdCompressor provides zstd compression.
var ZstdCompressor Compressor = &zstdCompressor{}

type zstdCompressor struct {
	bytesRead int64
}

func (zs *zstdCompressor) Compress(reader io.Reader) (io.ReadCloser, error) {

	pipeReader, pipeWriter := io.Pipe()
	zw, err := zstd.NewWriter(pipeWriter)
	if err != nil {
		return nil, err
	}
	go func() {
		bytesRead, err := system.Copy(zw, reader)
		if err != nil {
			log.Warnf("zstd compress: could not compress layer: %v", err)
			// #nosec G104
			_ = pipeWriter.CloseWithError(fmt.Errorf("compressing layer: %w", err))
			return
		}
		zs.bytesRead = bytesRead
		if err := zw.Close(); err != nil {
			log.Warnf("zstd compress: could not close gzip writer: %v", err)
			// #nosec G104
			_ = pipeWriter.CloseWithError(fmt.Errorf("close zstd writer: %w", err))
			return
		}
		if err := pipeWriter.Close(); err != nil {
			log.Warnf("zstd compress: could not close pipe: %v", err)
			// We don't CloseWithError because we cannot override the Close.
			return
		}
	}()

	return pipeReader, nil
}

func (zs zstdCompressor) MediaTypeSuffix() string {
	return "zstd"
}

func (zs zstdCompressor) BytesRead() int64 {
	return zs.bytesRead
}

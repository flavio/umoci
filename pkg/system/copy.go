/*
 * umoci: Umoci Modifies Open Containers' Images
 * Copyright (C) 2016-2022 SUSE LLC
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

package system

import (
	"errors"
	"io"

	"golang.org/x/sys/unix"
)

// Copy has identical semantics to io.Copy except it will automatically resume
// the copy after it receives an EINTR error.
func Copy(dst io.Writer, src io.Reader) (int64, error) {
	// Make a buffer so io.Copy doesn't make one for each iteration.
	var buf []byte
	size := 256 << 12 // 1 MiB
	if lr, ok := src.(*io.LimitedReader); ok && lr.N < int64(size) {
		if lr.N < 1 {
			size = 1
		} else {
			size = int(lr.N)
		}
	}
	buf = make([]byte, size)

	var written int64
	for {
		n, err := io.CopyBuffer(dst, src, buf)
		written += n // n is always non-negative
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return written, err
	}
}

// CopyN has identical semantics to io.CopyN except it will automatically
// resume the copy after it receives an EINTR error.
func CopyN(dst io.Writer, src io.Reader, n int64) (written int64, err error) {
	// This is based on the stdlib io.CopyN implementation.
	written, err = Copy(dst, io.LimitReader(src, n))
	if written == n {
		err = nil // somewhat confusing io.CopyN semantics
	}
	if written < n && err == nil {
		err = io.EOF // if the source ends prematurely, io.EOF
	}
	return
}

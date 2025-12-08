***REMOVED*** Go support for Protocol Buffers - Google's data interchange format
***REMOVED***
***REMOVED*** Copyright 2010 The Go Authors.  All rights reserved.
***REMOVED*** https://github.com/golang/protobuf
***REMOVED***
***REMOVED*** Redistribution and use in source and binary forms, with or without
***REMOVED*** modification, are permitted provided that the following conditions are
***REMOVED*** met:
***REMOVED***
***REMOVED***     * Redistributions of source code must retain the above copyright
***REMOVED*** notice, this list of conditions and the following disclaimer.
***REMOVED***     * Redistributions in binary form must reproduce the above
***REMOVED*** copyright notice, this list of conditions and the following disclaimer
***REMOVED*** in the documentation and/or other materials provided with the
***REMOVED*** distribution.
***REMOVED***     * Neither the name of Google Inc. nor the names of its
***REMOVED*** contributors may be used to endorse or promote products derived from
***REMOVED*** this software without specific prior written permission.
***REMOVED***
***REMOVED*** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
***REMOVED*** "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
***REMOVED*** LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
***REMOVED*** A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
***REMOVED*** OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
***REMOVED*** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
***REMOVED*** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
***REMOVED*** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
***REMOVED*** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
***REMOVED*** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
***REMOVED*** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

install:
	go install

test: install generate-test-pbs
	go test


generate-test-pbs:
	make install
	make -C test_proto
	make -C proto3_proto
	make

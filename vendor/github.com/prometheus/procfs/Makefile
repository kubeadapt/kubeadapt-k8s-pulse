***REMOVED*** Copyright 2018 The Prometheus Authors
***REMOVED*** Licensed under the Apache License, Version 2.0 (the "License");
***REMOVED*** you may not use this file except in compliance with the License.
***REMOVED*** You may obtain a copy of the License at
***REMOVED***
***REMOVED*** http://www.apache.org/licenses/LICENSE-2.0
***REMOVED***
***REMOVED*** Unless required by applicable law or agreed to in writing, software
***REMOVED*** distributed under the License is distributed on an "AS IS" BASIS,
***REMOVED*** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
***REMOVED*** See the License for the specific language governing permissions and
***REMOVED*** limitations under the License.

include Makefile.common

%/.unpacked: %.ttar
	@echo ">> extracting fixtures $*"
	./ttar -C $(dir $*) -x -f $*.ttar
	touch $@

fixtures: testdata/fixtures/.unpacked

update_fixtures:
	rm -vf testdata/fixtures/.unpacked
	./ttar -c -f testdata/fixtures.ttar -C testdata/ fixtures/

.PHONY: build
build:

.PHONY: test
test: testdata/fixtures/.unpacked common-test

//go:build !darwin && !linux
// +build !darwin,!linux

/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package inventory

import (
	"runtime"

	log "github.com/sirupsen/logrus"
)

// fetchOSVersionInfo returns "" if not on linux and not on darwin.
func (c *fetchConfig) fetchOSVersionInfo() string {
	log.Warningf("fetchOSVersionInfo is not implemented for %s", runtime.GOOS)
	return ""
}

// fetchGlibcVersionInfo returns "" if not on linux and not on darwin.
func (c *fetchConfig) fetchGlibcVersionInfo() string {
	log.Warningf("fetchGlibcVersionInfo is not implemented for %s", runtime.GOOS)
	return ""
}

// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/lib/config"
	logutils "github.com/gravitational/teleport/lib/utils/log"
)

func TestSetLogLevel(t *testing.T) {
	configFilePath, dataDir := newConfigWithDataDir(t)
	closeFn := newSocketMockService(t, dataDir, []byte{})
	defer closeFn()

	// All supported log levels should be accepted here.
	for _, level := range logutils.SupportedLevelsText {
		t.Run(level, func(t *testing.T) {
			err := onSetLogLevel(configFilePath, level)
			require.NoError(t, err)
		})
	}

	// Random or any other slog format should be rejected.
	for _, level := range []string{"RANDOM", "DEBUG-1", "INFO+1", "INVALID"} {
		t.Run(level, func(t *testing.T) {
			err := onSetLogLevel(configFilePath, level)
			require.Error(t, err)
		})
	}
}

func TestCollectProfiles(t *testing.T) {
	configFilePath, dataDir := newConfigWithDataDir(t)

	for _, test := range []struct {
		desc                      string
		profilesInput             string
		seconds                   int
		expectErr                 bool
		collectedProfilesExpected []string
		expectedArgs              string
	}{
		{
			desc:                      "default profiles",
			profilesInput:             "",
			collectedProfilesExpected: defaultCollectProfiles,
		},
		{
			desc:                      "single profile",
			profilesInput:             "goroutine",
			collectedProfilesExpected: []string{"goroutine"},
		},
		{
			desc:                      "profile with seconds flag",
			profilesInput:             "block",
			seconds:                   10,
			collectedProfilesExpected: []string{"block"},
			expectedArgs:              "seconds=10",
		},
		{
			desc:                      "multiple profiles",
			profilesInput:             "allocs,goroutine",
			collectedProfilesExpected: []string{"allocs", "goroutine"},
		},
		{
			desc:                      "all valid profiles",
			profilesInput:             "allocs,block,cmdline,goroutine,heap,mutex,profile,threadcreate,trace",
			collectedProfilesExpected: []string{"allocs", "block", "cmdline", "goroutine", "heap", "mutex", "profile", "threadcreate", "trace"},
		},
		{
			desc:          "invalid profile",
			profilesInput: "random",
			expectErr:     true,
		},
		{
			desc:          "invalid profile on the list",
			profilesInput: "goroutine,random",
			expectErr:     true,
		},
		{
			desc:          "invalid profiles separator",
			profilesInput: "goroutine random",
			expectErr:     true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			closeFn := newSocketMockService(t, dataDir, []byte("collected profile"))
			// We need to ensure that the socket is always closed after the test
			// completion, otherwise next tests will fail to open the socket.
			defer closeFn()

			var out bytes.Buffer
			err := onCollectProfile(configFilePath, test.profilesInput, test.seconds, &out)
			if test.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			var requestedProfiles []string
			requestedPaths := closeFn()
			for _, uri := range requestedPaths {
				path, args, _ := strings.Cut(uri, "?")
				require.True(t, strings.HasPrefix(path, constants.PProfEndpointsPrefix), "expected %q request but got %q", constants.PProfEndpointsPrefix, path)
				require.Equal(t, test.expectedArgs, args)

				requestedProfiles = append(requestedProfiles, strings.TrimPrefix(path, constants.PProfEndpointsPrefix))
			}
			require.ElementsMatch(t, test.collectedProfilesExpected, requestedProfiles)

			reader, err := gzip.NewReader(&out)
			require.NoError(t, err)
			var files []string
			tarReader := tar.NewReader(reader)
			for {
				header, err := tarReader.Next()
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				files = append(files, strings.TrimSuffix(header.Name, ".pprof"))
			}

			// We should have one file per profile collected.
			require.ElementsMatch(t, test.collectedProfilesExpected, files)
		})
	}
}

// newConfigWithDataDir creates a temporary directory with a configuration file.
// The configuration has data directory set to the temporary directory.
func newConfigWithDataDir(t *testing.T) (string, string) {
	t.Helper()
	dataDir := t.TempDir()

	cfg, err := config.MakeSampleFileConfig(config.SampleFlags{
		DataDir: dataDir,
	})
	require.NoError(t, err)

	configFilePath := filepath.Join(dataDir, "config.yaml")
	_, err = dumpConfigFile("file://"+configFilePath, cfg.DebugDumpToYAML(), "")
	require.NoError(t, err)

	return configFilePath, dataDir
}

// newSocketMockService creates a unix socket that access HTTP requests and
// always replies with success. `closeFn` returns the requested paths.
func newSocketMockService(t *testing.T, dataDir string, contents []byte) func() []string {
	t.Helper()

	l, err := net.Listen("unix", filepath.Join(dataDir, constants.DebugServiceSocketName))
	require.NoError(t, err)

	var requests []string
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests = append(requests, r.URL.RequestURI())
			w.Write(contents)
		}),
	}

	go func() {
		err := srv.Serve(l)
		if err != nil && err != http.ErrServerClosed {
			t.Logf("failed to serve service: %s", err)
		}
	}()

	return func() []string {
		srv.Shutdown(context.Background())
		return requests
	}
}

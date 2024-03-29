/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package diff

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gravitational/trace"
	"github.com/r3labs/diff/v3"

	apievents "github.com/gravitational/teleport/api/types/events"
)

// CreateDiff returns a list of changes between two resources that is
// ready to be added to an audit event.
func CreateDiff(a, b any) (apievents.DiffChangelog, error) {
	changes, err := diff.Diff(a, b)
	if err != nil {
		return apievents.DiffChangelog{}, trace.Wrap(err)
	}
	if len(changes) == 0 {
		return apievents.DiffChangelog{}, nil
	}

	diffChanges := make([]*apievents.DiffChange, len(changes))
	var sb strings.Builder
	for i, change := range changes {
		diffChange := &apievents.DiffChange{
			Type: change.Type,
			From: fmt.Sprintf("%v", change.From),
			To:   fmt.Sprintf("%v", change.To),
		}

		// build the path to the changed field
		for i, path := range change.Path {
			// if the path is an integer, surround it in braces to make
			// it clear that this part of the path is an array or slice
			// index; Go identifiers can't start with a number so this
			// isn't a struct field
			if _, err := strconv.ParseInt(path, 10, 64); err == nil {
				sb.WriteRune('[')
				sb.WriteString(path)
				sb.WriteRune(']')
			} else {
				sb.WriteString(path)
			}
			if i < len(change.Path)-1 {
				sb.WriteRune('.')
			}
		}
		diffChange.Path = sb.String()
		sb.Reset()

		diffChanges[i] = diffChange
	}

	return apievents.DiffChangelog{
		Changes: diffChanges,
	}, nil
}

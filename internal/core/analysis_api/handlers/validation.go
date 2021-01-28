package handlers

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"context"

	"github.com/pkg/errors"

	resourceTypesProvider "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

// Populated by a call to refreshLogTypes
var logtypeSetMap map[string]struct{}

// Traverse a passed set of resource and return an error if any of them are not found in the current
// list of valid resource types
//
// CAVEAT: This method uses a hardcoded list of existing resource types. If this method is returning
// unexpected errors the hardcoded list is up to date.
func ValidResourceTypeSet(checkResourceTypeSet []string) error {
	for _, writeResourceTypeEntry := range checkResourceTypeSet {
		if _, exists := resourceTypesProvider.ResourceTypes[writeResourceTypeEntry]; !exists {
			// Found a resource type that doesnt exist
			return errors.Errorf("%s", writeResourceTypeEntry)
		}
	}
	return nil
}

// Request the logtypes-api for the current set of logtypes and assign the result list to 'logtypeSetMap'
func refreshLogTypes() error {
	// Temporary get log types for testing
	logtypes, err := logtypesAPI.ListAvailableLogTypes(context.Background())
	if err != nil {
		return err
	}
	logtypeSetMap = make(map[string]struct{})
	for _, logtype := range logtypes.LogTypes {
		logtypeSetMap[logtype] = struct{}{}
	}
	return nil
}

// Return the existence of the passed logtype in the current logtypes.
// NOTE: Accuret results require an updated logtypeSetMap - currently accomplished using the call to
// 'refreshLogTypes'. That method makes a call to the log-types api, so use it as infrequently as possible
// The refresh method can be called a single time for multiple individual log type validation checks.
func logtypeIsValid(logtype string) (found bool) {
	_, found = logtypeSetMap[logtype]
	return
}

// Traverse a passed set of resource and return an error if any of them are not found in the current
// list of valid resource types
//
// CAVEAT: This method will trigger a request to the log-types api EVERY time it is called.
func validateLogtypeSet(logtypes []string) error {
	if err := refreshLogTypes(); err != nil {
		return err
	}
	for _, logtype := range logtypes {
		if !logtypeIsValid(logtype) {
			return errors.Errorf("%s", logtype)
		}
	}
	return nil
}

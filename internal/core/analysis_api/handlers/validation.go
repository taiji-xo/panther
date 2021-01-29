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

// Retrieve a set of log types from the logtypes api and validate every entry in the passed set
// is a value found in the logtypes-api returned set
//
// CAVEAT: This method will trigger a request to the log-types api EVERY time it is called.
func validateLogtypeSet(logtypes []string) error {
	availableLogTypes, err := logtypesAPI.ListAvailableLogTypes(context.TODO())
	if err != nil {
		return err
	}

	// Potential imrpovement - if you want the set of invalid log types the parameter could be used to
	// build the map and we could iterate through availableLogTypes / remove the keys from the map that
	// are found. At the end we would end up with a map of logtypes that are invalid.
	logtypeSetMap := make(map[string]struct{})
	for _, logtype := range availableLogTypes.LogTypes {
		logtypeSetMap[logtype] = struct{}{}
	}
	for _, lt := range logtypes {
		if _, found := logtypeSetMap[lt]; !found {
			return errors.Errorf("%s", lt)
		}
	}
	return nil
}

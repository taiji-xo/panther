package api

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
	"strings"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
)

func integrationToItem(input *models.SourceIntegration) *ddb.Integration {
	// Initializing the fields common for all integration types
	item := &ddb.Integration{
		CreatedAtTime:    input.CreatedAtTime,
		CreatedBy:        input.CreatedBy,
		IntegrationID:    input.IntegrationID,
		IntegrationLabel: input.IntegrationLabel,
		IntegrationType:  input.IntegrationType,
		PantherVersion:   input.PantherVersion,
	}
	item.LastEventReceived = input.LastEventReceived

	switch input.IntegrationType {
	case models.IntegrationTypeAWS3:
		item.AWSAccountID = input.AWSAccountID
		item.S3Bucket = input.S3Bucket
		item.S3PrefixLogTypes = input.S3PrefixLogTypes
		item.KmsKey = input.KmsKey
		item.StackName = input.StackName
		item.LogProcessingRole = generateLogProcessingRoleArn(input.AWSAccountID, input.IntegrationLabel)
	case models.IntegrationTypeAWSScan:
		item.AWSAccountID = input.AWSAccountID
		item.CWEEnabled = input.CWEEnabled
		item.EventStatus = input.EventStatus
		item.LastScanErrorMessage = input.LastScanErrorMessage
		item.LastScanEndTime = input.LastScanEndTime
		item.LastScanStartTime = input.LastScanStartTime
		item.LogProcessingRole = input.LogProcessingRole
		item.RemediationEnabled = input.RemediationEnabled
		item.S3Bucket = input.S3Bucket
		item.ScanIntervalMins = input.ScanIntervalMins
		item.ScanStatus = input.ScanStatus
		item.StackName = input.StackName
		item.Enabled = input.Enabled
		item.RegionIgnoreList = input.RegionIgnoreList
		item.ResourceTypeIgnoreList = input.ResourceTypeIgnoreList
		item.ResourceRegexIgnoreList = input.ResourceRegexIgnoreList
	case models.IntegrationTypeSqs:
		item.SqsConfig = &ddb.SqsConfig{
			QueueURL:             input.SqsConfig.QueueURL,
			S3Bucket:             input.SqsConfig.S3Bucket,
			LogProcessingRole:    input.SqsConfig.LogProcessingRole,
			LogTypes:             input.SqsConfig.LogTypes,
			AllowedPrincipalArns: input.SqsConfig.AllowedPrincipalArns,
			AllowedSourceArns:    input.SqsConfig.AllowedSourceArns,
		}
	}
	return item
}

func itemToIntegration(item *ddb.Integration) *models.SourceIntegration {
	// Initializing the fields common for all integration types
	integration := &models.SourceIntegration{}
	integration.IntegrationID = item.IntegrationID
	integration.IntegrationType = item.IntegrationType
	integration.IntegrationLabel = item.IntegrationLabel
	integration.CreatedAtTime = item.CreatedAtTime
	integration.CreatedBy = item.CreatedBy
	integration.LastEventReceived = item.LastEventReceived
	integration.PantherVersion = item.PantherVersion
	switch item.IntegrationType {
	case models.IntegrationTypeAWS3:
		integration.AWSAccountID = item.AWSAccountID
		integration.S3Bucket = item.S3Bucket
		integration.S3PrefixLogTypes = item.S3PrefixLogTypes
		if len(integration.S3PrefixLogTypes) == 0 {
			// Backwards compatibility: Use the old fields, maybe the info is there.
			s3prefixLogTypes := models.S3PrefixLogtypesMapping{S3Prefix: item.S3Prefix, LogTypes: item.LogTypes}
			integration.S3PrefixLogTypes = models.S3PrefixLogtypes{s3prefixLogTypes}
		}
		integration.KmsKey = item.KmsKey
		integration.StackName = item.StackName
		integration.LogProcessingRole = item.LogProcessingRole
	case models.IntegrationTypeAWSScan:
		integration.AWSAccountID = item.AWSAccountID
		integration.CWEEnabled = item.CWEEnabled
		integration.RemediationEnabled = item.RemediationEnabled
		integration.ScanIntervalMins = item.ScanIntervalMins
		integration.ScanStatus = item.ScanStatus
		integration.S3Bucket = item.S3Bucket
		integration.LogProcessingRole = item.LogProcessingRole
		integration.EventStatus = item.EventStatus
		integration.LastScanStartTime = item.LastScanStartTime
		integration.LastScanEndTime = item.LastScanEndTime
		integration.LastScanErrorMessage = item.LastScanErrorMessage
		integration.StackName = item.StackName
		integration.Enabled = item.Enabled
		integration.RegionIgnoreList = item.RegionIgnoreList
		integration.ResourceTypeIgnoreList = item.ResourceTypeIgnoreList
		integration.ResourceRegexIgnoreList = item.ResourceRegexIgnoreList
	case models.IntegrationTypeSqs:
		integration.SqsConfig = &models.SqsConfig{
			S3Bucket:             item.SqsConfig.S3Bucket,
			LogProcessingRole:    item.SqsConfig.LogProcessingRole,
			QueueURL:             item.SqsConfig.QueueURL,
			LogTypes:             item.SqsConfig.LogTypes,
			AllowedPrincipalArns: item.SqsConfig.AllowedPrincipalArns,
			AllowedSourceArns:    item.SqsConfig.AllowedSourceArns,
		}
	}
	return integration
}

// reduceNoPrefixStrings reduces a list of strings to a list where no string is a prefix of another.
// e.g [pref, prefi, prefix, abc] -> [pref, abc]
func reduceNoPrefixStrings(strs []string) (reduced []string) {
	uniques := make(map[string]struct{})
	for i := 0; i < len(strs); i++ {
		smallestPrefix := strs[i]
		for j := 0; j < len(strs); j++ {
			if strings.HasPrefix(smallestPrefix, strs[j]) {
				smallestPrefix = strs[j]
			}
		}
		uniques[smallestPrefix] = struct{}{}
	}
	for k := range uniques {
		reduced = append(reduced, k)
	}
	return
}

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/service/cloudwatch"

	alertdelivery "github.com/panther-labs/panther/internal/core/alert_delivery/alarms"
	logprocessor "github.com/panther-labs/panther/internal/log_analysis/log_processor/alarms"
)

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

// Mapping of subsystem -> array of CW Alarms
var systemAlerts map[string][]*cloudwatch.PutMetricAlarmInput

func init() {
	registerAlarms(alertdelivery.CloudWatch())
	registerAlarms(logprocessor.CloudWatch())
}

func registerAlarms(input map[string][]*cloudwatch.PutMetricAlarmInput) {
	for key, value := range input {
		systemAlerts[key] = append(systemAlerts[key], value...)
	}
}

func systemAlarms(ctx context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	const physicalResourceID = "custom:alarms:system"
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:

		var err error
		for _, alarms := range systemAlerts {
			for _, alarm := range alarms {
				_, err = cloudWatchClient.PutMetricAlarmWithContext(ctx, alarm)
				if err != nil {
					break
				}
			}
		}

		return physicalResourceID, nil, err

	case cfn.RequestDelete:
		return event.PhysicalResourceID, nil, nil

	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

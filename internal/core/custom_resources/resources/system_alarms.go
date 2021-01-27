package resources

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
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"

	alertmetrics "github.com/panther-labs/panther/internal/core/alert_delivery/metrics"
	"github.com/panther-labs/panther/pkg/metrics"
)

func setupClassificationAlarms() error {
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmDescription:   aws.String("Failed to classify events"),
		AlarmName:          aws.String(""),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String(metrics.SubsystemDimension), Value: aws.String(alertmetrics.SubsystemAlerting)},
			{Name: aws.String(metrics.StatusDimension), Value: aws.String(metrics.StatusErr)},
		},
		EvaluationPeriods: aws.Int64(1),
		MetricName:        aws.String(alertmetrics.MetricAlertDelivery),
		Namespace:         aws.String(metrics.Namespace),
		Period:            aws.Int64(300),
		Statistic:         aws.String(cloudwatch.StatisticSum),
		Threshold:         aws.Float64(0),
		Unit:              aws.String(cloudwatch.StandardUnitCount),
		TreatMissingData:  aws.String("notBreaching"),
		Tags: []*cloudwatch.Tag{
			{Key: aws.String("Application"), Value: aws.String("Panther")},
		},
	}

	if _, err := cloudWatchClient.PutMetricAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}
	return nil
}

func setupAlertDeliveryAlarms() error {
	input := &cloudwatch.PutMetricAlarmInput{
		AlarmDescription:   aws.String("Failed to delivery alerts to destinations"),
		AlarmName:          aws.String(fmt.Sprintf("Panther-SystemHealth-%s-%s", alertmetrics.SubsystemAlerting, metrics.StatusErr)),
		ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
		Dimensions: []*cloudwatch.Dimension{
			{Name: aws.String(metrics.SubsystemDimension), Value: aws.String(alertmetrics.SubsystemAlerting)},
			{Name: aws.String(metrics.StatusDimension), Value: aws.String(metrics.StatusErr)},
		},
		EvaluationPeriods: aws.Int64(1),
		MetricName:        aws.String(alertmetrics.MetricAlertDelivery),
		Namespace:         aws.String(metrics.Namespace),
		Period:            aws.Int64(300),
		Statistic:         aws.String(cloudwatch.StatisticSum),
		Threshold:         aws.Float64(0),
		Unit:              aws.String(cloudwatch.StandardUnitCount),
		TreatMissingData:  aws.String("notBreaching"),
		Tags: []*cloudwatch.Tag{
			{Key: aws.String("Application"), Value: aws.String("Panther")},
		},
	}

	if _, err := cloudWatchClient.PutMetricAlarm(input); err != nil {
		return fmt.Errorf("failed to put alarm %s: %v", *input.AlarmName, err)
	}
	return nil
}

package alarms

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"

	logmetrics "github.com/panther-labs/panther/internal/log_analysis/log_processor/metrics"
	"github.com/panther-labs/panther/pkg/alarms"
	"github.com/panther-labs/panther/pkg/metrics"
)

func CloudWatch() map[string][]*cloudwatch.PutMetricAlarmInput {
	classificationAlarms := []*cloudwatch.PutMetricAlarmInput{
		{
			AlarmDescription:   aws.String("Panther is failing to classify incoming events. Please review your sources."),
			AlarmName:          aws.String(alarms.SystemAlarmName(metrics.SubsystemLogProcessor, "ClassificationFailures")),
			ComparisonOperator: aws.String(cloudwatch.ComparisonOperatorGreaterThanThreshold),
			Dimensions: []*cloudwatch.Dimension{
				{Name: aws.String(metrics.SubsystemDimension), Value: aws.String(metrics.SubsystemLogProcessor)},
				{Name: aws.String(metrics.StatusDimension), Value: aws.String(logmetrics.StatusErr)},
			},
			EvaluationPeriods: aws.Int64(1),
			MetricName:        aws.String(logmetrics.MetricEventsClassified),
			Namespace:         aws.String(metrics.Namespace),
			Period:            aws.Int64(300),
			Statistic:         aws.String(cloudwatch.StatisticSum),
			Threshold:         aws.Float64(0),
			Unit:              aws.String(cloudwatch.StandardUnitCount),
			TreatMissingData:  aws.String("notBreaching"),
		},
	}

	return map[string][]*cloudwatch.PutMetricAlarmInput{
		metrics.SubsystemClassification: classificationAlarms,
	}
}

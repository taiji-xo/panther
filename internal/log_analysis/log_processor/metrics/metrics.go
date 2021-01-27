package metrics

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
	"os"

	"github.com/panther-labs/panther/pkg/metrics"
)

const (
	SubsystemLogProcessor  = "LogProcessor"
	MetricGetObject        = "GetObject"
	MetricEventsClassified = "EventsClassified"
)

var (
	CWMetrics metrics.Manager

	// Counter for number of objects retrieved from S3
	GetObject metrics.Counter

	// Counter for number of events classified
	ClassifiedEvents metrics.Counter
)

func Setup() {
	CWMetrics = metrics.NewCWEmbeddedMetrics(os.Stdout)
	GetObject = CWMetrics.NewCounter(MetricGetObject).
		With(metrics.SubsystemDimension, SubsystemLogProcessor)
	ClassifiedEvents = CWMetrics.NewCounter(MetricEventsClassified).
		With(metrics.SubsystemDimension, SubsystemLogProcessor)
}

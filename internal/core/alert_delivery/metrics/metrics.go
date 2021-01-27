package metrics

import (
	"os"

	"github.com/panther-labs/panther/pkg/metrics"
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

const (
	SubsystemAlerting   = "Alerting"
	MetricAlertDelivery = "AlertDelivery"
)

var (
	AlertDeliveryCounter metrics.Counter
	CWMetrics            metrics.Manager
)

func Setup() {
	CWMetrics = metrics.NewCWEmbeddedMetrics(os.Stdout)
	AlertDeliveryCounter = CWMetrics.NewCounter(MetricAlertDelivery).
		With(metrics.SubsystemDimension, SubsystemAlerting)
}

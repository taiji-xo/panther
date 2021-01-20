package cost

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

type PantherBytesProcessedRow struct {
	AccountId      string
	AccountName    string
	LogType        string
	BytesProcessed float64
	Year           int
	Month          int
	Day            int
}

type PantherLambdaUsageRow struct {
	AccountId         string
	AccountName       string
	LambdaName        string
	LambdaDuration    float64
	LambdaInvocations float64
	LambdaMemory      int64
	Component         string
	Year              int
	Month             int
	Day               int
}

type PantherS3StorageRow struct {
	AccountId   string
	AccountName string
	Bucket      string
	StorageType string
	Bytes       float64
	Year        int
	Month       int
	Day         int
}

type PantherServiceCostRow struct {
	AccountId    string
	AccountName  string
	Service      string
	ServiceUsage float64
	Component    string
	CostCategory string
	Cost         float64
	Year         int
	Month        int
	Day          int
}

type PantherResourceCostRow struct {
	AccountId    string
	AccountName  string
	Resource     string
	CostCategory string
	Cost         int64
	Year         int
	Month        int
	Day          int
}

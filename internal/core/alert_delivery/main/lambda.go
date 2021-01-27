package main

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
	"encoding/json"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/internal/core/alert_delivery/api"
	"github.com/panther-labs/panther/internal/core/alert_delivery/metrics"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/oplog"
)

var router = genericapi.NewRouter("api", "delivery", nil, api.API{})

func main() {
	api.Setup()
	lambda.Start(lambdaHandler)
}

// lambdaHandler handles two different kinds of requests:
// 1. SQSMessage trigger that takes data from the queue or can be directly invoked
// 2. HTTP API for re-sending an alert to the specified outputs
// 3. HTTP API for sending a test alert
func lambdaHandler(ctx context.Context, input json.RawMessage) (output interface{}, err error) {
	lc, log := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := oplog.NewManager("core", "alert_delivery").Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err)
	}()

	var apiRequest models.LambdaInput
	if err := jsoniter.Unmarshal(input, &apiRequest); err != nil {
		return nil, err
	}

	///// Configure metrics /////

	cwCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Sync metrics every minute
	go metrics.CWMetrics.Run(cwCtx, time.Minute)
	defer func() {
		// Force syncing metrics at the end of the invocation
		if err := metrics.CWMetrics.Sync(); err != nil {
			log.Warn("failed to sync metrics", zap.Error(err))
		}
	}()

	return router.HandleWithContext(ctx, &apiRequest)
}

// flush_resource_table_deleted removes all items in the panther-resources table which have the
// field deleted set to true
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
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
)

// Explicitely delete columns in the panther-resources table where the table entry deleted is equal
// to the entrydeleted contant
const tableName = "panther-resources"
const entrydeleted = true

// Max Back Off is used in the request dynamodb batch write items
const maxBackoff = 10 * time.Second

var awsSession *session.Session
var sugar *zap.SugaredLogger

func init() {
	awsSession = session.Must(session.NewSession())
	logger, err := zap.Config{
		Encoding:    "console",
		Level:       zap.NewAtomicLevelAt(zapcore.DebugLevel),
		OutputPaths: []string{"stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey: "message",
			// Useful for debugging:
			// LevelKey:     "level",
			// EncodeLevel:  zapcore.CapitalLevelEncoder,
			// TimeKey:      "time",
			// EncodeTime:   zapcore.ISO8601TimeEncoder,
			// CallerKey:    "caller",
			// EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}.Build()
	if err != nil {
		log.Fatal(err)
	}
	sugar = logger.Sugar()
}

func main() {

	sugar.Info("\nFlush Resource Table entries where deleted=true")
	sugar.Infof("AWS_REGION=%v", *awsSession.Config.Region)

	client := dynamodb.New(awsSession)

	// Dynamdb scan expression If you would like to see the value of deleted (or any other field) add
	// it to the projection names set.
	// proj := expression.NamesList(expression.Name("id"), expression.Name("deleted"))
	proj := expression.NamesList(expression.Name("id"))
	filt := expression.Name("deleted").Equal(expression.Value(entrydeleted))
	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	if err != nil {
		sugar.Error(err)
		os.Exit(1)
	}

	// Scan entries with the specified expression above
	// https://docs.aws.amazon.com/sdk-for-go/api/service/dynamodb/#ScanInput
	input := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 aws.String(tableName),
	}

	// Slice passed to the batchWriteItem representing the set of all items to remove from the table
	var deleteRequests []*dynamodb.WriteRequest

	// Called for each scan response in the ScanPages method - used to build the set of table entries
	// to delete specified by entry id
	var scanResult = func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, item := range page.Items {
			// Delete request for the scan result item
			deleteEntry := &dynamodb.WriteRequest{DeleteRequest: &dynamodb.DeleteRequest{Key: item}}
			// Add the delete request to the set
			deleteRequests = append(deleteRequests, deleteEntry)
		}
		return !lastPage
	}

	// Scan for deleted entries
	if err = client.ScanPages(input, scanResult); err != nil {
		sugar.Error(err)
		os.Exit(1)
	}

	// Exit before calling batch write if no items are found
	if len(deleteRequests) == 0 {
		sugar.Info("Resources table scan found no entries where deleted=true\n")
		os.Exit(0)
	}

	// Batch write request parameter containing set of delete item requests
	batchWriteInput := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{tableName: deleteRequests},
	}

	// Execute the batch deletions
	if err = dynamodbbatch.BatchWriteItem(client, maxBackoff, batchWriteInput); err != nil {
		sugar.Errorf("BatchWriteItem error: %s\n", err)
		os.Exit(1)
	}

	sugar.Infof("Flushed %v deleted entries\n", len(deleteRequests))
	os.Exit(0)
}

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"

	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
)

// Explicitely delete columns in the panther-resources table where the table entry deleted is equal
// to the entrydeleted contant
const tableName = "panther-resources"
const entrydeleted = true

// Max Back Off is used in the request dynamodb batch write items
const maxBackoff = 10 * time.Second

func main() {
	// AWS Session construction
	sessOpts := session.Options{SharedConfigState: session.SharedConfigEnable}
	awsSession := session.Must(session.NewSessionWithOptions(sessOpts))
	client := dynamodb.New(awsSession)

	// Query expression
	proj := expression.NamesList(expression.Name("id"))

	// If you would like to see the value of deleted (or any other field) add it to the projection
	// names set.
	// proj := expression.NamesList(expression.Name("id"), expression.Name("deleted"))

	filt := expression.Name("deleted").Equal(expression.Value(entrydeleted))
	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	if err != nil {
		log.Fatalf("Got error building expression: %s", err)
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

	var deleteRequests []*dynamodb.WriteRequest

	// Scan for deleted entries
	err = client.ScanPages(input, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, item := range page.Items {
			// Useful for troubleshooting:
			// fmt.Printf("%v\n", item)
			deleteRequests = append(deleteRequests, &dynamodb.WriteRequest{
				DeleteRequest: &dynamodb.DeleteRequest{Key: item},
			})
		}
		return true
	})

	if err != nil {
		log.Fatalf("Scan pages error: %s", err)
	}

	// Batch delete all items
	err = dynamodbbatch.BatchWriteItem(client, maxBackoff, &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{tableName: deleteRequests},
	})

	// Batch Write Error
	if err != nil {
		log.Fatalf("BatchWriteItem error: %s", err)
	}
}

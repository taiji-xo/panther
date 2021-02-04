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
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
)

const tableName = "panther-resources"
const delVal = true

func main() {

	// AWS Session construction
	sessOpts := session.Options{SharedConfigState: session.SharedConfigEnable}
	awsSession := session.Must(session.NewSessionWithOptions(sessOpts))
	client := dynamodb.New(awsSession)

	// Query expression
	proj := expression.NamesList(expression.Name("id"), expression.Name("deleted"))
	filt := expression.Name("deleted").Equal(expression.Value(delVal))
	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	if err != nil {
		fmt.Println("Got error building expression:")
		log.Fatal(err)
	}

	// Query Input
	input := &dynamodb.ScanInput{
		// ConsistentRead:       aws.Bool(true),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 aws.String(tableName),
	}

  // Scan for deleted entries
	err = client.ScanPages(input, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, item := range page.Items {
			fmt.Printf("%v\n", item)
			_, err := client.DeleteItem(&dynamodb.DeleteItemInput{
				Key: map[string]*dynamodb.AttributeValue{
					"id": item["id"],
				},
				TableName: aws.String(tableName),
			})
			if err != nil {
				log.Fatal(err)
			}
		}
		return true
	})

	if err != nil {
		fmt.Println("Got error Scanning Pages:")
		log.Fatal(err)
	}
}

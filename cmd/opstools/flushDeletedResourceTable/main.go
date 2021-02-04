package main

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

  // Slice of delete item inputs
	deletes := []*dynamodb.DeleteItemInput{}

  // Scan for deleted entries
	err = client.ScanPages(input, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, item := range page.Items {
			input := &dynamodb.DeleteItemInput{
				Key: map[string]*dynamodb.AttributeValue{
					"id": item["id"],
				},
				TableName: aws.String(tableName),
			}
			deletes = append(deletes, input)
		}
		return true
	})

	if err != nil {
		fmt.Println("Got error Scanning Pages:")
		log.Fatal(err)
	}

  // Loop through deleted items and delete them
	for index, item := range deletes {
		fmt.Printf("Index: %v\nitem: %v\n\n", index, item)
		_, err := client.DeleteItem(item)
		if err != nil {
			log.Fatal(err)
		}
	}
}

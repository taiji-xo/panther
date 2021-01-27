package handlers

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/core/analysis_api/analysis"
	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/pkg/awsretry"
	"github.com/panther-labs/panther/pkg/gatewayapi"

	// Imports a hardcoded map[string]struct{} Where keys are the set of valid resource types.
	resourceTypesProvider "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

const systemUserID = "00000000-0000-4000-8000-000000000000"

// setting Max Retries to a higher number - we'd like to retry VERY hard before failing.
const maxRetries = 20

var (
	env envConfig

	awsSession       *session.Session
	dynamoClient     dynamodbiface.DynamoDBAPI
	s3Client         s3iface.S3API
	sqsClient        sqsiface.SQSAPI
	complianceClient gatewayapi.API

	policyEngine analysis.PolicyEngine
	ruleEngine   analysis.RuleEngine

	//
	lambdaLogTypesClient *lambda.Lambda
	logtypesAPI          *logtypesapi.LogTypesAPILambdaClient

	logtypeSetMap map[string]interface{}
)

//
type envConfig struct {
	Bucket               string `required:"true" split_words:"true"`
	LayerManagerQueueURL string `required:"true" split_words:"true"`
	RulesEngine          string `required:"true" split_words:"true"`
	PolicyEngine         string `required:"true" split_words:"true"`
	ResourceQueueURL     string `required:"true" split_words:"true"`
	Table                string `required:"true" split_words:"true"`
}

// API defines all of the handlers as receiver functions.
type API struct{}

// Setup parses the environment and constructs AWS and http clients on a cold Lambda start.
// All required environment variables must be present or this function will panic.
func Setup() {
	envconfig.MustProcess("", &env)

	awsSession = session.Must(session.NewSession())
	dynamoClient = dynamodb.New(awsSession)
	s3Client = s3.New(awsSession)
	sqsClient = sqs.New(awsSession)
	lambdaClient := lambda.New(awsSession)
	complianceClient = gatewayapi.NewClient(lambdaClient, "panther-compliance-api")

	policyEngine = analysis.NewPolicyEngine(lambdaClient, env.PolicyEngine)
	ruleEngine = analysis.NewRuleEngine(lambdaClient, env.RulesEngine)

	clientsSession := awsSession.Copy(
		request.WithRetryer(
			aws.NewConfig().WithMaxRetries(maxRetries),
			awsretry.NewConnectionErrRetryer(maxRetries),
		),
	)
	lambdaLogTypesClient = lambda.New(clientsSession)
	logtypesAPI = &logtypesapi.LogTypesAPILambdaClient{
		LambdaName: logtypesapi.LambdaName,
		LambdaAPI:  lambdaLogTypesClient,
	}

	refreshLogTypes()
}

// Traverse a passed set of resource and return an error if any of them are not found in the current
// list of valid resource types
//
// CAVEAT: This method uses a hardcoded list of existing resource types. If this method is returning
// unexpected errors the hardcoded list is up to date.
func ValidResourceTypeSet(checkResourceTypeSet []string) error {
	for _, writeResourceTypeEntry := range checkResourceTypeSet {
		if _, exists := resourceTypesProvider.ResourceTypes[writeResourceTypeEntry]; !exists {
			// Found a resource type that doesnt exist
			return errors.Errorf("%s", writeResourceTypeEntry)
		}
	}
	return nil
}

// Request the logtypes-api for the current set of logtypes and assign the result list to 'logtypeSetMap'
func refreshLogTypes() {
	// Temporary get log types for testing
	logtypes, err := logtypesAPI.ListAvailableLogTypes(context.Background())
	if err != nil {

		return
	}

	logtypeSetMap = make(map[string]interface{})
	for _, logtype := range logtypes.LogTypes {
		logtypeSetMap[logtype] = nil
	}
}

// Simply return the existance of the passed logtype in the current logtypes.
// NOTE: Accuret results require an updated logtypeSetMap - currently accomplished using the call to
// 'refreshLogTypes'. That method makes a call to the log-types api, so use it as infrequently as possible
// The refresh method can be called a single time for multiple individual log type validation checks.
func logtypeIsValid(logtype string) (found bool) {
	_, found = logtypeSetMap[logtype]
	return
}

// Traverse a passed set of resource and return an error if any of them are not found in the current
// list of valid resource types
//
// CAVEAT: This method will trigger a request to the log-types api EVERY time it is called.
func validateLogtypeSet(logtypes []string) (err error) {
	refreshLogTypes()
	for _, logtype := range logtypes {
		if !logtypeIsValid(logtype) {
			return errors.Errorf("%s", logtype)
		}
	}
	return
}

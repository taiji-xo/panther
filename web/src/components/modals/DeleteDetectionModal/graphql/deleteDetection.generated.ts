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

import * as Types from '../../../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type DeleteDetectionVariables = {
  id: Types.Scalars['ID'];
};

export type DeleteDetection = Pick<Types.Mutation, 'deleteDetections'>;

export const DeleteDetectionDocument = gql`
  mutation DeleteDetection($id: ID!) {
    deleteDetections(input: { detections: [{ id: $id }] })
  }
`;
export type DeleteDetectionMutationFn = ApolloReactCommon.MutationFunction<
  DeleteDetection,
  DeleteDetectionVariables
>;

/**
 * __useDeleteDetection__
 *
 * To run a mutation, you first call `useDeleteDetection` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteDetection` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteDetection, { data, loading, error }] = useDeleteDetection({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useDeleteDetection(
  baseOptions?: ApolloReactHooks.MutationHookOptions<DeleteDetection, DeleteDetectionVariables>
) {
  return ApolloReactHooks.useMutation<DeleteDetection, DeleteDetectionVariables>(
    DeleteDetectionDocument,
    baseOptions
  );
}
export type DeleteDetectionHookResult = ReturnType<typeof useDeleteDetection>;
export type DeleteDetectionMutationResult = ApolloReactCommon.MutationResult<DeleteDetection>;
export type DeleteDetectionMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteDetection,
  DeleteDetectionVariables
>;
export function mockDeleteDetection({
  data,
  variables,
  errors,
}: {
  data: DeleteDetection;
  variables?: DeleteDetectionVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: DeleteDetectionDocument, variables },
    result: { data, errors },
  };
}

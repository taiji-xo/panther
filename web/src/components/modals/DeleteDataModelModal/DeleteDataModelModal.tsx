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

import React from 'react';
import { Text, ModalProps, useSnackbar } from 'pouncejs';
import { DataModel } from 'Generated/schema';
import { extractErrorMessage, toPlural } from 'Helpers/utils';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import OptimisticConfirmModal from 'Components/modals/OptimisticConfirmModal';
import { useDeleteDataModel } from './graphql/deleteDataModel.generated';

export interface DeleteDataModelModalProps extends ModalProps {
  dataModels: DataModel[];
}

const DeleteDataModelModal: React.FC<DeleteDataModelModalProps> = ({ dataModels, ...rest }) => {
  const dataModelToString = toPlural('Data Model', dataModels.length);
  const { pushSnackbar } = useSnackbar();
  const [deleteDataModel] = useDeleteDataModel({
    variables: { input: { dataModels: dataModels.map(m => ({ id: m.id })) } },
    // FIXME: issue: https://github.com/apollographql/apollo-client/issues/5790
    update: cache => {
      cache.modify('ROOT_QUERY', {
        listDataModels(data, { toReference }) {
          const deletedDataModels = dataModels.map(
            dm => toReference({ __typename: 'DataModel', id: dm.id }).__ref
          );
          return {
            ...data,
            models: data.models.filter(d => !deletedDataModels.includes(d.__ref)),
          };
        },
      });
      cache.gc();
    },
    onCompleted: () => {
      trackEvent({ event: EventEnum.DeletedDataModel, src: SrcEnum.DataModels });
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to delete your ${dataModelToString}`,
        description: extractErrorMessage(error),
      });
      trackError({ event: TrackErrorEnum.FailedToDeleteDataModel, src: SrcEnum.DataModels });
    },
  });

  return (
    <OptimisticConfirmModal
      onConfirm={deleteDataModel}
      title={`Delete ${dataModelToString}`}
      subtitle={[
        <Text key={0} maxWidth={480}>
          Are you sure you want to delete{' '}
          <b>
            {dataModels.map((dm, i) => {
              const dataModel = dm.displayName || dm.id;
              if (i === 0) {
                return dataModel;
              }
              if (i === dataModels.length - 1) {
                return ` and ${dataModel}`;
              }
              return `, ${dataModel}`;
            })}
          </b>
          ?
        </Text>,
      ]}
      {...rest}
    />
  );
};

export default DeleteDataModelModal;

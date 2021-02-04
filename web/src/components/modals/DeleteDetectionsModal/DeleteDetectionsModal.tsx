/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { SavedQuery } from 'Generated/schema';
import differenceBy from 'lodash/differenceBy';
import OptimisticConfirmModal from 'Components/modals/OptimisticConfirmModal';
import { ModalProps, useSnackbar } from 'pouncejs';
import { useDeleteDetections } from 'Source/graphql/queries';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { extractErrorMessage } from 'Helpers/utils';

export interface DeleteDetectionsModalProps extends ModalProps {
  ids: SavedQuery['id'][];
  onConfirm?: () => void;
}

const DeleteDetectionsModal: React.FC<DeleteDetectionsModalProps> = ({
  ids,
  onConfirm = () => {},
  ...rest
}) => {
  const { pushSnackbar } = useSnackbar();
  const [deleteDetections] = useDeleteDetections({
    update: cache => {
      cache.modify('ROOT_QUERY', {
        listDetections: (savedQueryCacheData, { toReference }) => {
          const deletedQueriesRefs = ids.map(id => toReference({ __typename: 'SavedQuery', id }));
          return {
            ...savedQueryCacheData,
            savedQueries: differenceBy(
              savedQueryCacheData.savedQueries,
              deletedQueriesRefs,
              '__ref'
            ),
          };
        },
      });
      cache.gc();
    },
    onCompleted: () => {
      trackEvent({
        event: EventEnum.DeletedDetections,
        src: SrcEnum.Detections,
        data: { length: ids.length },
      });
      onConfirm();
      pushSnackbar({
        variant: 'success',
        title: `${
          ids.length === 1 ? 'Saved Query ' : `${ids.length} Saved queries`
        } deleted successfully`,
      });
    },
    onError: error => {
      pushSnackbar({
        variant: 'error',
        title: `Failed delete saved queries`,
        description: extractErrorMessage(error),
      });
      trackError({ event: TrackErrorEnum.FailedToDeleteDetections, src: SrcEnum.Detections });
    },
  });

  const onDelete = React.useCallback(
    () =>
      deleteDetections({
        variables: { input: { ids } },
      }),
    [ids]
  );

  return (
    <OptimisticConfirmModal
      title="Attention!"
      subtitle={`Are you sure you want to delete ${
        ids.length === 1
          ? 'the selected Saved Query?'
          : `these (${ids.length}) selected Saved Queries`
      }`}
      onConfirm={onDelete}
      {...rest}
    />
  );
};

export default DeleteDetectionsModal;

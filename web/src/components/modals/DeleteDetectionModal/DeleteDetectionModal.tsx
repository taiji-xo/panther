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
import { ModalProps, useSnackbar } from 'pouncejs';
import { Detection, DetectionTypeEnum } from 'Generated/schema';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import OptimisticConfirmModal from '../OptimisticConfirmModal';
import { useDeleteDetection } from './graphql/deleteDetection.generated';

export interface DeleteDetectionModalProps extends ModalProps {
  detection: Detection;
}

const DeleteDetectionModal: React.FC<DeleteDetectionModalProps> = ({ detection, ...rest }) => {
  const { location, history } = useRouter<{ id?: string }>();
  const { pushSnackbar } = useSnackbar();

  const isPolicy = detection.analysisType === DetectionTypeEnum.Policy;
  const detectionDisplayName = detection.displayName || detection.id;

  const [confirmDeletion] = useDeleteDetection({
    variables: {
      input: {
        detections: [
          {
            id: detection.id,
          },
        ],
      },
    },
    optimisticResponse: {
      deleteDetection: true,
    },
    update: async cache => {
      cache.modify('ROOT_QUERY', {
        detections: (data, helpers) => {
          const detectionRef = helpers.toReference({
            __typename: isPolicy ? 'Policy' : 'Rule',
            id: detection.id,
          });

          return {
            ...data,
            detections: data.detections.filter(r => r.__ref !== detectionRef.__ref),
          };
        },
        ...(!isPolicy && {
          rule: (data, helpers) => {
            const ruleRef = helpers.toReference({ __typename: 'Rule', id: detection.id });
            if (ruleRef.__ref !== data.__ref) {
              return data;
            }
            return helpers.DELETE;
          },
        }),
        ...(isPolicy && {
          policy: (data, helpers) => {
            const policyRef = helpers.toReference({ __typename: 'Policy', id: detection.id });
            if (policyRef.__ref !== data.__ref) {
              return data;
            }
            return helpers.DELETE;
          },
        }),
      });
      cache.gc();
    },
    onCompleted: () => {
      pushSnackbar({
        variant: 'success',
        title: `Successfully deleted rule: ${detectionDisplayName}`,
      });
    },
    onError: () => {
      pushSnackbar({
        variant: 'error',
        title: `Failed to delete rule: ${detectionDisplayName}`,
      });
    },
  });

  function onConfirm() {
    if (location.pathname.includes(detection.id)) {
      // if we were on the particular detection's details page or edit page --> redirect on delete
      history.push(urls.detections.list());
    }
    return confirmDeletion();
  }

  return (
    <OptimisticConfirmModal
      title={`Delete ${detectionDisplayName}`}
      subtitle={`Are you sure you want to delete ${detectionDisplayName}?`}
      onConfirm={onConfirm}
      {...rest}
    />
  );
};

export default DeleteDetectionModal;

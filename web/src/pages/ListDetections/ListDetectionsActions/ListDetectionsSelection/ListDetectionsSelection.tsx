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
import { Button, Flex, Text } from 'pouncejs';
import { useSelect } from 'Components/utils/SelectContext';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';

const ListSavedQueriesSelection: React.FC = () => {
  const { selection, resetSelection } = useSelect();
  const { showModal } = useModal();

  return (
    <Flex justify="flex-end" align="center" spacing={4}>
      <Text>{selection.length} Selected</Text>
      <Button
        variantColor="red"
        onClick={() =>
          showModal({
            modal: MODALS.DELETE,
            props: { ids: selection, onConfirm: resetSelection },
          })
        }
      >
        Delete
      </Button>
    </Flex>
  );
};

export default React.memo(ListSavedQueriesSelection);

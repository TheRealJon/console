import * as React from 'react';
import { useTranslation } from 'react-i18next';
import { Table, RowComponentProps } from '@console/internal/components/factory';
import { dimensifyHeader } from '@console/shared';
import { sortable } from '@patternfly/react-table';
import { AffinityRowData } from '../../types';

export type AffinityTableProps = {
  data?: AffinityRowData[];
  customData?: object;
  Row: React.FC<RowComponentProps>;
  columnClasses?: string[];
};

export const AffinityTable: React.FC<AffinityTableProps> = ({
  data,
  customData,
  Row,
  columnClasses,
}) => {
  const { t } = useTranslation();
  return (
    <Table
      aria-label={t('kubevirt-plugin~Affinity List')}
      data={data}
      Header={() =>
        dimensifyHeader(
          [
            {
              title: 'Type',
              sortField: 'type',
              transforms: [sortable],
            },
            {
              title: 'Condition',
              sortField: 'condition',
              transforms: [sortable],
            },
            {
              title: 'Weight',
              sortField: 'weight',
              transforms: [sortable],
            },
            {
              title: 'Terms',
            },
            {
              title: '',
            },
          ],
          columnClasses,
        )
      }
      Row={Row}
      customData={{ ...customData, columnClasses }}
      virtualize
      loaded
    />
  );
};

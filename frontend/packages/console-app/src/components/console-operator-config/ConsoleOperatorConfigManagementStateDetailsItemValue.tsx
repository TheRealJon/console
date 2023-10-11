import * as React from 'react';
import { K8sResourceKind } from '@console/dynamic-plugin-sdk/src/extensions/console-types';
import { DetailsItemComponentProps } from '@console/dynamic-plugin-sdk/src/extensions/details-item';

export const ConsoleOperatorConfigManagementStateDetailsItemValue: React.FC<DetailsItemComponentProps<
  K8sResourceKind,
  string
>> = ({ obj, path, value }) => {
  switch (obj.spec?.managementState) {
    case 'Managed':
      return (
        <div>
          <p>The operator is managed.</p>
          <code>
            {path}: {value}
          </code>
        </div>
      );
    case 'Unmanaged':
      return (
        <div>
          <p>The operator is unmanaged.</p>
          <code>
            {path}: {value}
          </code>
        </div>
      );
    case 'Removed':
      return (
        <div>
          <p>The operator is removed.</p>
          <code>
            {path}: {value}
          </code>
        </div>
      );
    default:
      return (
        <div>
          <p>The operator is in an unknown state.</p>
          <code>
            {path}: {value}
          </code>
        </div>
      );
  }
};

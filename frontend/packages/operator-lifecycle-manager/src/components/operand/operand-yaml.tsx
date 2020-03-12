import * as _ from 'lodash';
import * as React from 'react';
import { match as RouterMatch } from 'react-router-dom';
import { safeDump, safeLoad } from 'js-yaml';
import { resourcePathFromModel, BreadCrumbs } from '@console/internal/components/utils';
import { ClusterServiceVersionModel } from '../../models';
import { Button } from '@patternfly/react-core';
import { K8sKind, K8sResourceKind, K8sResourceKindReference } from '@console/internal/module/k8s';
import { CreateYAML } from '@console/internal/components/create-yaml';
import { ClusterServiceVersionKind } from '../../types';
import { ProvidedAPI } from './create-operand';

/**
 * Component which wraps the YAML editor to ensure the templates are added from the `ClusterServiceVersion` annotations.
 */
export const OperandYAML: React.FC<OperandYAMLProps> = ({
  activePerspective,
  clusterServiceVersion,
  data,
  match,
  onChange,
  onChangeEditMethod,
  operandModel,
}) => {
  const template = React.useMemo(() => _.attempt(() => safeDump(data)), [data]);
  if (_.isError(template)) {
    // eslint-disable-next-line no-console
    console.error('Error parsing example JSON from annotation. Falling back to default.');
  }

  const parseYaml = (newYAML) => {
    const newData = _.attempt(() => safeLoad(newYAML));
    return !_.isError(newData) ? newData : data;
  };

  const resourceObjPath = () =>
    activePerspective === 'dev'
      ? '/topology'
      : `${resourcePathFromModel(
          ClusterServiceVersionModel,
          match.params.appName,
          match.params.ns,
        )}/${match.params.plural}`;

  return (
    <>
      <div className="co-create-operand__header">
        <div className="co-create-operand__header-buttons">
          <BreadCrumbs
            breadcrumbs={[
              {
                name: clusterServiceVersion.spec.displayName,
                path: resourcePathFromModel(
                  ClusterServiceVersionModel,
                  clusterServiceVersion.metadata.name,
                  clusterServiceVersion.metadata.namespace,
                ),
              },
              { name: `Create ${operandModel.label}`, path: window.location.pathname },
            ]}
          />
          <div style={{ marginLeft: 'auto' }}>
            <Button variant="link" onClick={() => onChangeEditMethod('form')}>
              Edit Form
            </Button>
          </div>
        </div>
        <h1 className="co-create-operand__header-text">{`Create ${operandModel.label}`}</h1>
        <p className="help-block">
          Create by manually entering YAML or JSON definitions, or by dragging and dropping a file
          into the editor.
        </p>
      </div>
      <CreateYAML
        template={_.isError(template) ? null : template}
        match={match}
        resourceObjPath={resourceObjPath}
        hideHeader
        onChange={(yaml) => onChange(parseYaml(yaml))}
      />
    </>
  );
};

export type OperandYAMLProps = {
  data?: K8sResourceKind;
  onChange?: (newData: K8sResourceKind) => void;
  onChangeEditMethod?: (newMethod: string) => void;
  operandModel: K8sKind;
  providedAPI: ProvidedAPI;
  clusterServiceVersion: ClusterServiceVersionKind;
  match: RouterMatch<{ appName: string; ns: string; plural: K8sResourceKindReference }>;
  activePerspective: string;
};

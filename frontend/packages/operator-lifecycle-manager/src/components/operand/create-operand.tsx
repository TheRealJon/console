import {
  K8sKind,
  K8sResourceKind,
  K8sResourceKindReference,
  kindForReference,
  referenceFor,
  referenceForModel,
  nameForModel,
  CustomResourceDefinitionKind,
} from '@console/internal/module/k8s';
import { JSONSchema6 } from 'json-schema';
import { definitionFor } from '@console/internal/module/k8s/swagger';
import { CustomResourceDefinitionModel } from '@console/internal/models';
import { Firehose } from '@console/internal/components/utils/firehose';
import { StatusBox, FirehoseResult } from '@console/internal/components/utils';
import { RootState } from '@console/internal/redux';
import * as _ from 'lodash';
import { Helmet } from 'react-helmet';
import { match as RouterMatch } from 'react-router';
import { connect } from 'react-redux';
import * as React from 'react';
import { ClusterServiceVersionModel } from '../../models';
import { ClusterServiceVersionKind, CRDDescription, APIServiceDefinition } from '../../types';
import { OperandForm } from './operand-form';
import { OperandYAML } from './operand-yaml';
import { providedAPIsFor, referenceForProvidedAPI } from '../';
import { getActivePerspective } from '@console/internal/reducers/ui';

export const CreateOperand: React.FC<CreateOperandProps> = ({
  clusterServiceVersion,
  customResourceDefinition,
  loaded,
  loadError,
  match,
  operandModel,
  activePerspective,
}) => {
  const { data: csv } = clusterServiceVersion;
  const csvAnnotations = _.get(csv, 'metadata.annotations', {});
  const operandModelReference = referenceForModel(operandModel);
  const [method, setMethod] = React.useState<'yaml' | 'form'>('yaml');
  const providedAPI = React.useMemo<ProvidedAPI>(
    () =>
      providedAPIsFor(csv).find((crd) => referenceForProvidedAPI(crd) === operandModelReference),
    [csv, operandModelReference],
  );

  const openAPI = React.useMemo(
    () =>
      customResourceDefinition?.data?.spec?.validation?.openAPIV3Schema ||
      (definitionFor(operandModel) as JSONSchema6),
    [customResourceDefinition, operandModel],
  );

  const defaultSample = React.useMemo<K8sResourceKind>(
    () =>
      JSON.parse(_.get(csvAnnotations, 'alm-examples', '[]')).find(
        (s: K8sResourceKind) => referenceFor(s) === operandModelReference,
      ),
    [operandModelReference, csvAnnotations],
  );

  const [data, setData] = React.useState<K8sResourceKind>(defaultSample);

  const onChange = (newData) => {
    setData((currentData) => {
      return _.isEqual(currentData, newData) ? currentData : newData;
    });
  };

  const onChangeEditMethod = React.useCallback((newMethod) => {
    setMethod(newMethod);
  }, []);

  const editor = React.useMemo(() => {
    if (!loaded) {
      return null;
    }
    return method === 'yaml' ? (
      <OperandYAML
        activePerspective={activePerspective}
        match={match}
        data={data}
        operandModel={operandModel}
        providedAPI={providedAPI}
        clusterServiceVersion={clusterServiceVersion.data}
        onChangeEditMethod={onChangeEditMethod}
        onChange={onChange}
      />
    ) : (
      <OperandForm
        activePerspective={activePerspective}
        namespace={match.params.ns}
        operandModel={operandModel}
        providedAPI={providedAPI}
        data={data}
        clusterServiceVersion={clusterServiceVersion.data}
        openAPI={openAPI}
        onChangeEditMethod={onChangeEditMethod}
        onChange={onChange}
      />
    );
  }, [
    data,
    clusterServiceVersion.data,
    defaultSample,
    loaded,
    match,
    method,
    onChangeEditMethod,
    openAPI,
    operandModel,
    providedAPI,
    activePerspective,
  ]);

  return (
    <StatusBox loaded={loaded} loadError={loadError} data={clusterServiceVersion}>
      {editor}
    </StatusBox>
  );
};

const stateToProps = (state: RootState, props: Omit<CreateOperandPageProps, 'operandModel'>) => ({
  operandModel: state.k8s.getIn(['RESOURCES', 'models', props.match.params.plural]) as K8sKind,
  activePerspective: getActivePerspective(state),
});

export const CreateOperandPage = connect(stateToProps)((props: CreateOperandPageProps) => (
  <>
    <Helmet>
      <title>{`Create ${kindForReference(props.match.params.plural)}`}</title>
    </Helmet>
    {props.operandModel && (
      <Firehose
        resources={[
          {
            kind: referenceForModel(ClusterServiceVersionModel),
            name: props.match.params.appName,
            namespace: props.match.params.ns,
            isList: false,
            prop: 'clusterServiceVersion',
          },
          {
            kind: CustomResourceDefinitionModel.kind,
            isList: false,
            name: nameForModel(props.operandModel),
            prop: 'customResourceDefinition',
            optional: true,
          },
        ]}
      >
        {/* FIXME(alecmerdler): Hack because `Firehose` injects props without TypeScript knowing about it */}
        <CreateOperand {...(props as any)} operandModel={props.operandModel} match={props.match} />
      </Firehose>
    )}
  </>
));

export type ProvidedAPI = CRDDescription | APIServiceDefinition;

export type CreateOperandProps = {
  match: RouterMatch<{ appName: string; ns: string; plural: K8sResourceKindReference }>;
  operandModel: K8sKind;
  loaded: boolean;
  loadError?: any;
  clusterServiceVersion: FirehoseResult<ClusterServiceVersionKind>;
  customResourceDefinition?: FirehoseResult<CustomResourceDefinitionKind>;
  activePerspective: string;
};

export type CreateOperandFormProps = {
  onToggleEditMethod?: (newBuffer?: K8sResourceKind) => void;
  operandModel: K8sKind;
  providedAPI: ProvidedAPI;
  openAPI?: JSONSchema6;
  clusterServiceVersion: ClusterServiceVersionKind;
  buffer?: K8sResourceKind;
  namespace: string;
  activePerspective: string;
};

export type CreateOperandPageProps = {
  match: RouterMatch<{ appName: string; ns: string; plural: K8sResourceKindReference }>;
  operandModel: K8sKind;
};

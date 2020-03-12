import { Dropdown, NumberSpinner, ListDropdown } from '@console/internal/components/utils';
import * as _ from 'lodash';
import * as React from 'react';
import { cloneDeep } from 'lodash';
import { modelFor, ImagePullPolicy } from '@console/internal/module/k8s';
import { ResourceRequirements } from './resource-requirements';
import { Switch, Checkbox } from '@patternfly/react-core';
import { RadioGroup } from '@console/internal/components/radio';
import { ConfigureUpdateStrategy } from '@console/internal/components/modals/configure-update-strategy-modal';
import { NodeAffinity, PodAffinity } from './affinity';

export const SpecDescriptorPodCountInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
}) => {
  return (
    <NumberSpinner
      id={id}
      className="pf-c-form-control"
      value={value}
      onChange={({ currentTarget }) => onChange(_.toInteger(currentTarget.value))}
      changeValueBy={(operation) => onChange(_.toInteger(value) + operation)}
      autoFocus
      required
    />
  );
};

export const SpecDescriptorResourceRequirementsInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
}) => {
  const { limits, requests } = value;
  return (
    <dl style={{ marginLeft: '15px' }}>
      <dt>Limits</dt>
      <dd>
        <ResourceRequirements
          cpu={limits?.cpu || ''}
          memory={limits?.memory || ''}
          storage={limits?.['ephemeral-storage'] || ''}
          onChangeCPU={(cpu) => onChange(_.set(cloneDeep(value), 'limits.cpu', cpu))}
          onChangeMemory={(mem) => onChange(_.set(cloneDeep(value), 'limits.memory', mem))}
          onChangeStorage={(sto) =>
            onChange(_.set(cloneDeep(value), 'limits.ephemeral-storage', sto))
          }
          path={`${id}.limits`}
        />
      </dd>
      <dt>Requests</dt>
      <dd>
        <ResourceRequirements
          cpu={requests?.cpu || ''}
          memory={requests?.memory || ''}
          storage={requests?.['ephemeral-storage'] || ''}
          onChangeCPU={(cpu) => onChange(_.set(cloneDeep(value), 'requests.cpu', cpu))}
          onChangeMemory={(mem) => onChange(_.set(cloneDeep(value), 'requests.memory', mem))}
          onChangeStorage={(sto) =>
            onChange(_.set(cloneDeep(value), 'requests.ephemeral-storage', sto))
          }
          path={`${id}.requests`}
        />
      </dd>
    </dl>
  );
};

export const SpecDescriptorPasswordInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
  validation,
}) => {
  return (
    <div>
      <input
        className="pf-c-form-control"
        key={id}
        id={id}
        type="password"
        {...validation}
        onChange={({ currentTarget }) => onChange(currentTarget.value)}
        value={value || ''}
      />
    </div>
  );
};

export const SpecDescriptorK8sResourceInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  groupVersionKind,
  id,
  label,
  namespace,
  onChange,
}) => {
  const model = modelFor(groupVersionKind);
  const selectedKey = value ? `${value}-${model.kind}` : null;

  return (
    <div>
      {!_.isUndefined(model) ? (
        <ListDropdown
          key={id}
          id={id}
          resources={[{ kind: groupVersionKind, namespace: model.namespaced ? namespace : null }]}
          desc={label}
          placeholder={`Select ${model.label}`}
          onChange={(value) => onChange(value)}
          selectedKey={selectedKey}
        />
      ) : (
        <span>Cluster does not have resource {groupVersionKind}</span>
      )}
    </div>
  );
};

export const SpecDescriptorCheckboxInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  label,
  onChange,
  required,
}) => {
  return (
    <Checkbox
      id={id}
      key={id}
      isChecked={(_.isNil(value) ? false : value) as boolean}
      label={label}
      required={required}
      onChange={(checked) => onChange(checked)}
    />
  );
};

export const SpecDescriptorBooleanSwitchInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
}) => {
  return (
    <Switch
      key={id}
      id={id}
      isChecked={(_.isNil(value) ? false : value) as boolean}
      onChange={(checked) => onChange(checked)}
      label="True"
      labelOff="False"
    />
  );
};

export const SpecDescriptorImagePullPolicyInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
}) => {
  return (
    <RadioGroup
      currentValue={value}
      items={_.values(ImagePullPolicy).map((policy) => ({
        value: policy,
        title: policy,
      }))}
      onChange={({ currentTarget }) => onChange(currentTarget.value)}
    />
  );
};

export const SpecDescriptorUpdateStrategyInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
}) => {
  return (
    <ConfigureUpdateStrategy
      strategyType={value?.type || 'RollingUpdate'}
      maxUnavailable={value?.rollingUpdate?.maxUnavailable || ''}
      maxSurge={value?.rollingUpdate?.maxSurge || ''}
      onChangeStrategyType={(type) => onChange(_.set(_.cloneDeep(value), 'type', type))}
      onChangeMaxUnavailable={(maxUnavailable) =>
        onChange(_.set(_.cloneDeep(value), 'rollingUpdate.maxUnavailable', maxUnavailable))
      }
      onChangeMaxSurge={(maxSurge) =>
        onChange(_.set(_.cloneDeep(value), 'rollingUpdate.maxSurge', maxSurge))
      }
      replicas={1}
      uid={id}
    />
  );
};

export const SpecDescriptorTextInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
}) => {
  return (
    <div>
      <input
        key={id}
        className="pf-c-form-control"
        id={id}
        type="text"
        onChange={({ currentTarget }) => onChange(currentTarget.value)}
        value={value}
      />
    </div>
  );
};

export const SpecDescriptorNumberInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
}) => {
  return (
    <div>
      <input
        className="pf-c-form-control"
        id={id}
        key={id}
        onChange={({ currentTarget }) =>
          onChange(currentTarget.value !== '' ? _.toNumber(currentTarget.value) : '')
        }
        type="number"
        value={value !== '' ? _.toNumber(value) : ''}
      />
    </div>
  );
};

export const SpecDescriptorNodeAffinityInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
}) => {
  return (
    <div style={{ marginLeft: '15px' }}>
      <NodeAffinity affinity={value} onChangeAffinity={(affinity) => onChange(affinity)} uid={id} />
    </div>
  );
};

export const SpecDescriptorPodAffinityInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  onChange,
}) => {
  return (
    <div style={{ marginLeft: '15px' }}>
      <PodAffinity affinity={value} onChangeAffinity={(affinity) => onChange(affinity)} uid={id} />
    </div>
  );
};

export const SpecDescriptorSelectInput: React.FC<SpecDescriptorInputProps> = ({
  value,
  id,
  items,
  label,
  onChange,
}) => {
  return (
    <Dropdown
      id={id}
      key={id}
      title={`Select ${label}`}
      selectedKey={value}
      items={items}
      onChange={(selected) => onChange(selected)}
    />
  );
};

export enum SpecDescriptorInputType {
  PodCount = 'PodCount',
  ResourceRequirements = 'ResourceRequirements',
  Password = 'Password',
  K8sResource = 'K8sResource',
  Checkbox = 'Checkbox',
  BooleanSwitch = 'BooleanSwitch',
  ImagePullPolicy = 'ImagePullPolicy',
  UpdateStrategy = 'UpdateStrategy',
  Text = 'Text',
  Number = 'Number',
  NodeAffinity = 'NodeAffinity',
  PodAffinity = 'PodAffinity',
  Select = 'Select',
  Labels = 'Labels',
}

type SpecDescriptorInputProps = {
  value?: any;
  id?: string;
  onChange?: (val: any) => void;
  [key: string]: any;
};

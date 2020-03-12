import {
  SpecDescriptorInputType,
  SpecDescriptorPodCountInput,
  SpecDescriptorResourceRequirementsInput,
  SpecDescriptorPasswordInput,
  SpecDescriptorK8sResourceInput,
  SpecDescriptorBooleanSwitchInput,
  SpecDescriptorCheckboxInput,
  SpecDescriptorImagePullPolicyInput,
  SpecDescriptorTextInput,
  SpecDescriptorNumberInput,
  SpecDescriptorNodeAffinityInput,
  SpecDescriptorPodAffinityInput,
  SpecDescriptorSelectInput,
  SpecDescriptorUpdateStrategyInput,
} from '../descriptors/spec/spec-descriptor-input';
import { SelectorInput } from '@console/internal/components/utils';
import * as React from 'react';

enum MetadataInputType {
  Name = 'Name',
  Labels = 'Labels',
  Annotations = 'Annotations',
}

export const LabelsWidget = ({ value, id, onChange }) => (
  <SelectorInput
    onChange={(nextValue) => onChange(SelectorInput.objectify(nextValue))}
    tags={SelectorInput.arrayify(value)}
  />
);

export const OperandFormWidget: React.FC<OperandFormWidgetProps> = ({
  id,
  onChange,
  type,
  value,
  ...rest
}) => {
  const componentProps = {
    value,
    id,
    onChange,
    ...rest,
  };
  switch (type) {
    case SpecDescriptorInputType.PodCount:
      return <SpecDescriptorPodCountInput {...componentProps} />;
    case SpecDescriptorInputType.ResourceRequirements:
      return <SpecDescriptorResourceRequirementsInput {...componentProps} />;
    case SpecDescriptorInputType.Password:
      return <SpecDescriptorPasswordInput {...componentProps} />;
    case SpecDescriptorInputType.K8sResource:
      return <SpecDescriptorK8sResourceInput {...componentProps} />;
    case SpecDescriptorInputType.Checkbox:
      return <SpecDescriptorCheckboxInput {...componentProps} />;
    case SpecDescriptorInputType.BooleanSwitch:
      return <SpecDescriptorBooleanSwitchInput {...componentProps} />;
    case SpecDescriptorInputType.ImagePullPolicy:
      return <SpecDescriptorImagePullPolicyInput {...componentProps} />;
    case SpecDescriptorInputType.UpdateStrategy:
      return <SpecDescriptorUpdateStrategyInput {...componentProps} />;
    case SpecDescriptorInputType.Text:
      return <SpecDescriptorTextInput {...componentProps} />;
    case SpecDescriptorInputType.Number:
      return <SpecDescriptorNumberInput {...componentProps} />;
    case SpecDescriptorInputType.NodeAffinity:
      return <SpecDescriptorNodeAffinityInput {...componentProps} />;
    case SpecDescriptorInputType.PodAffinity:
      return <SpecDescriptorPodAffinityInput {...componentProps} />;
    case SpecDescriptorInputType.Select:
      return <SpecDescriptorSelectInput {...componentProps} />;
    case MetadataInputType.Labels: {
      return <LabelsWidget {...componentProps} />;
    }
    case MetadataInputType.Name: {
      return <SpecDescriptorTextInput {...componentProps} />;
    }
    default:
      return null;
  }
};

type OperandFormWidgetProps = {
  value?: any;
  id?: string;
  onChange?: (value: any) => void;
  type: SpecDescriptorInputType | MetadataInputType;
};

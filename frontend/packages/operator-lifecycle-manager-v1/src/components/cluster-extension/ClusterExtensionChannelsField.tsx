import type { FC } from 'react';
import { useState } from 'react';
import {
  Flex,
  FlexItem,
  FormGroup,
  FormHelperText,
  HelperText,
  HelperTextItem,
  Label,
  MenuToggle,
  Select,
  SelectList,
  SelectOption,
} from '@patternfly/react-core';
import { useTranslation } from 'react-i18next';
import { ClusterExtensionModel } from '@console/internal/models';
import { SchemaFieldHelp } from '@console/shared/src/components/utils/SchemaFieldHelp';

interface ChannelsFieldProps {
  fieldId: string;
  values: string[];
  availableChannels?: readonly string[];
  onChange: (values: string[]) => void;
}

export const ClusterExtensionChannelsField: FC<ChannelsFieldProps> = ({
  fieldId,
  values,
  onChange,
  availableChannels = [],
}) => {
  const { t } = useTranslation('olm-v1');
  const [isOpen, setIsOpen] = useState(false);
  const selectedChannels = [...new Set(values)];
  const channelOptions = [...new Set([...availableChannels, ...selectedChannels])].sort();
  const expanded = isOpen && channelOptions.length > 0;
  return (
    <FormGroup
      fieldId={fieldId}
      label={t('Channels')}
      labelHelp={
        <SchemaFieldHelp
          model={ClusterExtensionModel}
          propertyPath="spec.source.catalog.channels"
          headerContent={t('Channels')}
          ariaLabel={t('Channels help')}
          fallbackDescription={t(
            'Channels that constrain available versions and automatic update paths. If you leave this empty, Operator Lifecycle Manager considers all channels.',
          )}
        />
      }
    >
      <Select
        id={`${fieldId}-select`}
        role="menu"
        isOpen={expanded}
        selected={selectedChannels}
        onOpenChange={setIsOpen}
        onSelect={(_event, selection) => {
          if (typeof selection !== 'string') return;
          onChange(
            selectedChannels.includes(selection)
              ? selectedChannels.filter((channel) => channel !== selection)
              : [...selectedChannels, selection],
          );
        }}
        toggle={(toggleRef) => (
          <MenuToggle
            ref={toggleRef}
            id={fieldId}
            aria-label={t('Channels')}
            aria-describedby={`${fieldId}-selection ${fieldId}-helper`}
            onClick={() => setIsOpen((open) => !open)}
            isExpanded={expanded}
            isDisabled={!channelOptions.length}
            isFullWidth
          >
            <span id={`${fieldId}-selection`}>
              {selectedChannels.length ? (
                <Flex component="span" spaceItems={{ default: 'spaceItemsSm' }}>
                  {selectedChannels.map((channel) => (
                    <FlexItem key={channel} component="span">
                      <Label>{channel}</Label>
                    </FlexItem>
                  ))}
                </Flex>
              ) : (
                t('All channels')
              )}
            </span>
          </MenuToggle>
        )}
      >
        <SelectList aria-label={t('Available channels')}>
          {channelOptions.map((channel) => (
            <SelectOption
              key={channel}
              value={channel}
              hasCheckbox
              isSelected={selectedChannels.includes(channel)}
            >
              {channel}
            </SelectOption>
          ))}
        </SelectList>
      </Select>
      <FormHelperText>
        <HelperText id={`${fieldId}-helper`}>
          <HelperTextItem>{t('For example: stable, beta')}</HelperTextItem>
        </HelperText>
      </FormHelperText>
    </FormGroup>
  );
};

import type { FC } from 'react';
import { useMemo, useState } from 'react';
import {
  Button,
  ExpandableSection,
  Flex,
  FlexItem,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  FormSelectOptionGroup,
  HelperText,
  HelperTextItem,
  List,
  ListItem,
  Stack,
  StackItem,
  TextInput,
} from '@patternfly/react-core';
import { useTranslation } from 'react-i18next';
import * as semver from 'semver';

export interface SemverRangeInputProps {
  /** Unique input ID, also used to associate helper text. */
  id: string;
  /** Accessible name for the range input. */
  ariaLabel: string;
  /** Available versions used to build suggestions, sorted newest first. */
  versions: readonly string[];
  /** Controlled constraint text. Validation belongs to the API server. */
  value: string;
  /** Called on every edit, preserving arbitrary constraint text. */
  onChange: (value: string) => void;
  isDisabled?: boolean;
}

/** Free-form semver constraint with a comparison builder informed by available versions. */
export const SemverRangeInput: FC<SemverRangeInputProps> = ({
  id,
  ariaLabel,
  versions,
  value,
  onChange,
  isDisabled = false,
}) => {
  const { t } = useTranslation('console-shared');
  const [isExpanded, setIsExpanded] = useState(false);
  const [operator, setOperator] = useState('=');
  const [version, setVersion] = useState('');
  const { availableVersions, majorVersions, minorVersions } = useMemo(() => {
    const available = [...new Set(versions.filter((candidate) => semver.valid(candidate)))].sort(
      semver.rcompare,
    );
    return {
      availableVersions: available,
      majorVersions: [...new Set(available.map((candidate) => `${semver.major(candidate)}.x`))],
      minorVersions: [
        ...new Set(
          available.map((candidate) => `${semver.major(candidate)}.${semver.minor(candidate)}.x`),
        ),
      ],
    };
  }, [versions]);
  const selectedVersion = [
    ...availableVersions,
    ...majorVersions,
    ...minorVersions,
    ...(availableVersions.length ? ['*'] : []),
  ].includes(version)
    ? version
    : (availableVersions[0] ?? '');
  const comparison = operator === '=' ? selectedVersion : `${operator}${selectedVersion}`;
  const builderDisabled = isDisabled || !selectedVersion;
  const helperId = `${id}-semver-help`;

  return (
    <Stack hasGutter>
      <StackItem>
        <TextInput
          id={id}
          aria-label={ariaLabel}
          aria-describedby={helperId}
          value={value}
          onChange={(_event, nextValue) => onChange(nextValue)}
          isDisabled={isDisabled}
        />
        <FormHelperText>
          <HelperText id={helperId}>
            <HelperTextItem>
              {t('Enter a version or range. Leave empty to install the latest available version.')}
            </HelperTextItem>
            <HelperTextItem>
              {t(
                'Use commas or spaces for AND, and || for OR. Ranges are limited to 64 characters.',
              )}
            </HelperTextItem>
          </HelperText>
        </FormHelperText>
      </StackItem>
      <StackItem>
        <Flex>
          <FlexItem>
            <FormSelect
              id={`${id}-operator`}
              aria-label={t('Comparison operator for {{label}}', { label: ariaLabel })}
              value={operator}
              onChange={(_event, nextOperator) => setOperator(nextOperator)}
              isDisabled={builderDisabled}
            >
              <FormSelectOption value="=" label={t('Equal (=)')} />
              <FormSelectOption value="!=" label={t('Not equal (!=)')} />
              <FormSelectOption value=">=" label={t('At least (>=)')} />
              <FormSelectOption value=">" label={t('Greater than (>)')} />
              <FormSelectOption value="<=" label={t('At most (<=)')} />
              <FormSelectOption value="<" label={t('Less than (<)')} />
              <FormSelectOption value="~" label={`${t('Allow patch updates')} (~)`} />
              <FormSelectOption value="^" label={`${t('Allow compatible updates')} (^)`} />
            </FormSelect>
          </FlexItem>
          <FlexItem>
            <FormSelect
              id={`${id}-versions`}
              aria-label={t('Available version for {{label}}', { label: ariaLabel })}
              value={selectedVersion}
              onChange={(_event, nextVersion) => setVersion(nextVersion)}
              isDisabled={builderDisabled}
            >
              {!availableVersions.length && (
                <FormSelectOption value="" label={t('No available versions')} />
              )}
              <FormSelectOptionGroup label={t('Exact version')}>
                {availableVersions.map((candidate) => (
                  <FormSelectOption key={candidate} value={candidate} label={candidate} />
                ))}
              </FormSelectOptionGroup>
              <FormSelectOptionGroup label={t('Minor version wildcard')}>
                {minorVersions.map((candidate) => (
                  <FormSelectOption key={candidate} value={candidate} label={candidate} />
                ))}
              </FormSelectOptionGroup>
              <FormSelectOptionGroup label={t('Major version wildcard')}>
                {majorVersions.map((candidate) => (
                  <FormSelectOption key={candidate} value={candidate} label={candidate} />
                ))}
              </FormSelectOptionGroup>
              {availableVersions.length > 0 && (
                <FormSelectOption value="*" label={t('Any version (*)')} />
              )}
            </FormSelect>
          </FlexItem>
        </Flex>
        <Flex className="pf-v6-u-mt-sm">
          <FlexItem>
            <Button
              type="button"
              variant="secondary"
              isDisabled={builderDisabled}
              onClick={() => onChange(comparison)}
            >
              {t('Use comparison')}
            </Button>
          </FlexItem>
          <FlexItem>
            <Button
              type="button"
              variant="link"
              isDisabled={builderDisabled || !value.trim()}
              onClick={() => onChange(`${value}, ${comparison}`)}
            >
              {t('Add AND condition')}
            </Button>
          </FlexItem>
          <FlexItem>
            <Button
              type="button"
              variant="link"
              isDisabled={builderDisabled || !value.trim()}
              onClick={() => onChange(`${value} || ${comparison}`)}
            >
              {t('Add OR alternative')}
            </Button>
          </FlexItem>
        </Flex>
        <FormHelperText>
          <HelperText>
            <HelperTextItem>
              {t(
                'An exact version prevents automatic updates. A range allows updates within its constraints.',
              )}
            </HelperTextItem>
          </HelperText>
        </FormHelperText>
      </StackItem>
      <StackItem>
        {availableVersions.length ? (
          <ExpandableSection
            isExpanded={isExpanded}
            onToggle={(_event, expanded) => setIsExpanded(expanded)}
            toggleText={t('View available versions ({{count}})', {
              count: availableVersions.length,
            })}
          >
            <List isPlain>
              {availableVersions.map((candidate) => (
                <ListItem key={candidate}>{candidate}</ListItem>
              ))}
            </List>
          </ExpandableSection>
        ) : (
          <HelperText>
            <HelperTextItem>
              {t('No available versions to suggest. You can still enter a version range.')}
            </HelperTextItem>
          </HelperText>
        )}
      </StackItem>
    </Stack>
  );
};

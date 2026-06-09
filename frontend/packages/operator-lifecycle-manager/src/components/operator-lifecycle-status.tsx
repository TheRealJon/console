import type { FC } from 'react';
import {
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  Button,
  DescriptionListTerm,
  Label,
  Popover,
} from '@patternfly/react-core';
import { useTranslation } from 'react-i18next';
import * as semver from 'semver';
import {
  BlueInfoCircleIcon,
  GreenCheckCircleIcon,
} from '@console/dynamic-plugin-sdk/src/app/components/status/icons';
import { ExternalLink } from '@console/shared/src/components/links/ExternalLink';
import { RedExclamationCircleIcon } from '@console/shared/src/components/status/icons';
import { dateFormatter } from '@console/shared/src/utils/datetime';
import { getClusterVersion } from '../hooks/useOperatorLifecycle';

type LifecyclePhase = {
  name: string;
  startDate: string;
  endDate: string;
};

type PlatformCompatibility = {
  name: string;
  versions: string[];
};

type LifecycleVersion = {
  name: string;
  platformCompatibility?: PlatformCompatibility[];
  phases?: LifecyclePhase[];
};

export type LifecycleData = {
  package: string;
  schema: string;
  versions?: LifecycleVersion[];
};

const parseMinorVersion = (version: string): string | undefined => {
  const parsed = semver.coerce(version);
  return parsed ? `${parsed.major}.${parsed.minor}` : undefined;
};

const findVersionEntry = (
  versions: LifecycleVersion[],
  operatorVersion: string | undefined,
): LifecycleVersion | undefined => {
  if (!operatorVersion) {
    return versions[0];
  }
  return (
    versions.find((v) => v.name === operatorVersion) ??
    versions.find((v) => parseMinorVersion(v.name) === parseMinorVersion(operatorVersion))
  );
};

export type CompatibilityResult = 'compatible' | 'incompatible' | 'no-data';

export const getClusterCompatibility = (
  lifecycle: LifecycleData | undefined,
  operatorVersion: string | undefined,
  clusterVersion: string | undefined,
): CompatibilityResult => {
  if (!lifecycle?.versions || !clusterVersion) {
    return 'no-data';
  }

  const clusterMinor = parseMinorVersion(clusterVersion);
  if (clusterMinor === undefined) {
    return 'no-data';
  }

  const versionEntry = findVersionEntry(lifecycle.versions, operatorVersion);

  const openshiftCompat = versionEntry?.platformCompatibility?.find((p) => p.name === 'openshift');
  if (!openshiftCompat?.versions) {
    return 'no-data';
  }

  return openshiftCompat.versions.some((v) => parseMinorVersion(v) === clusterMinor)
    ? 'compatible'
    : 'incompatible';
};

const parseLocalStartOfDay = (dateStr: string): number => {
  const [y, m, d] = dateStr.split('-').map(Number);
  return new Date(y, m - 1, d).getTime();
};

const parseLocalEndOfDay = (dateStr: string): number => {
  const [y, m, d] = dateStr.split('-').map(Number);
  return new Date(y, m - 1, d, 23, 59, 59, 999).getTime();
};

type SupportPhaseInfo = {
  currentPhase: LifecyclePhase;
  allPhases: LifecyclePhase[];
};

type SelfSupportInfo = {
  selfSupport: true;
  allPhases: LifecyclePhase[];
};

export type SupportPhaseResult = SupportPhaseInfo | SelfSupportInfo | 'no-data';

export const getSupportPhase = (
  lifecycle: LifecycleData | undefined,
  operatorVersion: string | undefined,
  currentDate: Date = new Date(),
): SupportPhaseResult => {
  if (!lifecycle?.versions) {
    return 'no-data';
  }

  const versionEntry = findVersionEntry(lifecycle.versions, operatorVersion);

  if (!Array.isArray(versionEntry?.phases) || versionEntry.phases.length === 0) {
    return 'no-data';
  }

  const now = currentDate.getTime();
  const allPhases = [...versionEntry.phases].sort(
    (a, b) => parseLocalEndOfDay(a.endDate) - parseLocalEndOfDay(b.endDate),
  );

  for (const phase of allPhases) {
    const begin = parseLocalStartOfDay(phase.startDate);
    const end = parseLocalEndOfDay(phase.endDate);
    if (now >= begin && now <= end) {
      return { currentPhase: phase, allPhases };
    }
  }

  const lastPhase = allPhases[allPhases.length - 1];
  if (now > parseLocalEndOfDay(lastPhase.endDate)) {
    return { selfSupport: true, allPhases };
  }

  return { currentPhase: allPhases[0], allPhases };
};

export const ClusterCompatibilityStatus: FC<{ compatible: CompatibilityResult }> = ({
  compatible,
}) => {
  const { t } = useTranslation();

  if (compatible === 'compatible') {
    return (
      <span data-test="cluster-compatibility-compatible">
        <GreenCheckCircleIcon /> {t('olm~Compatible')}
      </span>
    );
  }
  if (compatible === 'incompatible') {
    return (
      <span data-test="cluster-compatibility-incompatible">
        <RedExclamationCircleIcon /> {t('olm~Incompatible')}
      </span>
    );
  }
  return (
    <span data-test="cluster-compatibility-no-data" aria-label={t('olm~No data available')}>
      -
    </span>
  );
};

const formatDate = (date: Date): string => dateFormatter.format(date);

const LifecycleDatesFooter: FC = () => {
  const { t } = useTranslation();
  const clusterVersion = getClusterVersion();
  const clusterMinor = clusterVersion ? parseMinorVersion(clusterVersion) : undefined;

  return (
    <>
      <hr className="pf-v6-u-mb-sm pf-v6-u-mt-0" />
      <span className="pf-v6-u-color-200">
        {t('olm~May not reflect your actual SKU. Check your actual SKU for extended support.')}
      </span>
      <div className="pf-v6-u-mt-sm">
        <ExternalLink href="https://access.redhat.com/support/policy/updates/openshift_operators/lifecycle">
          {t('olm~OpenShift Operator life cycle')}
        </ExternalLink>
      </div>
      {clusterMinor && (
        <div>
          <ExternalLink
            href={`https://access.redhat.com/support/policy/updates/openshift#ocp${clusterMinor.replace(
              '.',
              '',
            )}`}
          >
            {t('olm~OpenShift life cycle ({{version}})', { version: clusterMinor })}
          </ExternalLink>
        </div>
      )}
      <div>
        <ExternalLink href="https://access.redhat.com/product-life-cycles">
          {t('olm~Red Hat product life cycles')}
        </ExternalLink>
      </div>
    </>
  );
};

const isSelfSupport = (phase: SupportPhaseResult): phase is SelfSupportInfo =>
  typeof phase === 'object' && 'selfSupport' in phase;

const isSupportPhaseInfo = (phase: SupportPhaseResult): phase is SupportPhaseInfo =>
  typeof phase === 'object' && 'currentPhase' in phase;

const LifecycleDatesPopover: FC<{
  phases: LifecyclePhase[];
  children: React.ReactElement;
}> = ({ phases, children }) => {
  const { t } = useTranslation();
  const sorted = [...phases].sort(
    (a, b) => parseLocalEndOfDay(a.endDate) - parseLocalEndOfDay(b.endDate),
  );

  return (
    <Popover
      headerContent={t('olm~Lifecycle dates')}
      appendTo="inline"
      position="left"
      bodyContent={
        <DescriptionList isHorizontal isCompact>
          {sorted.map((p) => (
            <DescriptionListGroup key={p.name}>
              <DescriptionListTerm>{p.name}</DescriptionListTerm>
              <DescriptionListDescription>
                {formatDate(new Date(parseLocalEndOfDay(p.endDate)))}
              </DescriptionListDescription>
            </DescriptionListGroup>
          ))}
        </DescriptionList>
      }
      footerContent={<LifecycleDatesFooter />}
      data-test="lifecycle-dates-popover"
    >
      {children}
    </Popover>
  );
};

export const SupportPhaseBadge: FC<{ phase: SupportPhaseResult }> = ({ phase }) => {
  const { t } = useTranslation();

  if (isSelfSupport(phase)) {
    return (
      <LifecycleDatesPopover phases={phase.allPhases}>
        <Button
          variant="plain"
          type="button"
          data-test="support-phase-self-support"
          onClick={(e) => e.preventDefault()}
          aria-haspopup="dialog"
          isInline
        >
          <Label variant="outline" icon={<BlueInfoCircleIcon />} textMaxWidth="100ch">
            {t('olm~Self-support')}
          </Label>
        </Button>
      </LifecycleDatesPopover>
    );
  }

  if (!isSupportPhaseInfo(phase)) {
    return (
      <span data-test="support-phase-no-data" aria-label={t('olm~No data available')}>
        -
      </span>
    );
  }

  const endDate = formatDate(new Date(parseLocalEndOfDay(phase.currentPhase.endDate)));

  return (
    <LifecycleDatesPopover phases={phase.allPhases}>
      <Button
        variant="plain"
        type="button"
        data-test="support-phase-badge"
        onClick={(e) => e.preventDefault()}
        aria-haspopup="dialog"
        isInline
      >
        <Label variant="outline" icon={<BlueInfoCircleIcon />} textMaxWidth="100ch">
          {phase.currentPhase.name}
        </Label>{' '}
        {endDate}
      </Button>
    </LifecycleDatesPopover>
  );
};

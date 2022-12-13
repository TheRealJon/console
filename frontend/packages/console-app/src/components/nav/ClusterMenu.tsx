import * as React from 'react';
import {
  Button,
  Divider,
  EmptyState,
  EmptyStateBody,
  EmptyStateSecondaryActions,
  Menu,
  MenuContent,
  MenuGroup,
  MenuInput,
  MenuItem,
  MenuList,
  TextInput,
  Title,
} from '@patternfly/react-core';
import fuzzysearch from 'fuzzysearch';
import { useTranslation } from 'react-i18next';
// eslint-disable-next-line @typescript-eslint/ban-ts-ignore
// @ts-ignore
import { useDispatch } from 'react-redux';
import { useActivePerspective } from '@console/dynamic-plugin-sdk';
import { detectFeatures, clearSSARFlags } from '@console/internal/actions/features';
import { formatNamespaceRoute } from '@console/internal/actions/ui';
import { history } from '@console/internal/components/utils';
import { useActiveCluster, useActiveNamespace, usePerspectives } from '@console/shared';
import ClusterMenuToggle from './ClusterMenuToggle';

const ClusterCIcon: React.FC = () => <span className="co-m-resource-icon">C</span>;

const NoResults: React.FC<{
  onClear: (event: React.MouseEvent<HTMLButtonElement, MouseEvent>) => void;
}> = ({ onClear }) => {
  const { t } = useTranslation();
  return (
    <EmptyState>
      <Title size="md" headingLevel="h4">
        {t('console-app~No cluster found')}
      </Title>
      <EmptyStateBody>{t('console-app~No results match the filter criteria.')}</EmptyStateBody>
      <EmptyStateSecondaryActions>
        <Button variant="link" onClick={onClear}>
          {t('console-app~Clear filter')}
        </Button>
      </EmptyStateSecondaryActions>
    </EmptyState>
  );
};

const ClusterFilter: React.FC<{
  filterRef: React.Ref<any>;
  onFilterChange: (filterText: string) => void;
  filterText: string;
}> = ({ filterText, filterRef, onFilterChange }) => {
  const { t } = useTranslation();
  return (
    <MenuInput translate="no">
      <TextInput
        autoFocus
        placeholder={t('console-app~Find a cluster...')}
        aria-label={t('console-app~Find a cluster...')}
        iconVariant="search"
        type="search"
        value={filterText}
        onChange={onFilterChange}
        ref={filterRef}
      />
    </MenuInput>
  );
};

const ClusterGroup: React.FC<{
  clusters: ClusterMenuItem[];
}> = ({ clusters }) => {
  const [activeCluster] = useActiveCluster();

  return clusters.length === 0 ? null : (
    <MenuGroup translate="no" label="Clusters">
      <MenuList>
        {clusters.map((cluster) => (
          <MenuItem
            translate="no"
            key={cluster.key}
            itemId={cluster.key}
            isSelected={activeCluster === cluster.key}
            onClick={(e) => {
              e.preventDefault();
              cluster.onClick();
            }}
          >
            {cluster.showIcon && <ClusterCIcon />}
            {cluster.title}
          </MenuItem>
        ))}
      </MenuList>
    </MenuGroup>
  );
};

const ClusterMenu = () => {
  const { t } = useTranslation();
  const [filterText, setFilterText] = React.useState('');
  const filterRef = React.useRef(null);
  const dispatch = useDispatch();
  const menuRef = React.useRef(null);
  const [activePerspective, setActivePerspective] = useActivePerspective();
  const [activeNamespace] = useActiveNamespace();
  const [activeCluster, setActiveCluster] = useActiveCluster();
  const [dropdownOpen, setDropdownOpen] = React.useState(false);
  const perspectiveExtensions = usePerspectives();
  const acmPerspectiveExtension = React.useMemo(
    () => perspectiveExtensions.find((p) => p.properties.id === 'acm'),
    [perspectiveExtensions],
  );

  const onClusterClick = React.useCallback(
    (cluster: string): void => {
      if (cluster !== activeCluster) {
        setActiveCluster(cluster);
        // TODO: Move this logic into `setActiveCluster`?
        dispatch(clearSSARFlags());
        dispatch(detectFeatures());
      }
      if (activePerspective === 'acm') {
        setActivePerspective('admin');
      } else {
        const oldPath = window.location.pathname;
        const newPath = formatNamespaceRoute(activeNamespace, oldPath, window.location, true);
        if (newPath !== oldPath) {
          history.pushPath(newPath);
        }
      }
      setDropdownOpen(false);
    },
    [
      activeCluster,
      activeNamespace,
      activePerspective,
      dispatch,
      setActiveCluster,
      setActivePerspective,
    ],
  );

  const optionItems = React.useMemo<ClusterMenuItem[]>(
    () => [
      ...(acmPerspectiveExtension
        ? [
            {
              key: acmPerspectiveExtension.properties.id,
              title: 'All Clusters',
              onClick: () => setActivePerspective(acmPerspectiveExtension.properties.id),
            },
          ]
        : []),
      ...window.SERVER_FLAGS.clusters.map((cluster) => ({
        key: cluster,
        title: cluster,
        showIcon: true,
        onClick: () => onClusterClick(cluster),
      })),
    ],
    [acmPerspectiveExtension, onClusterClick, setActivePerspective],
  );

  const isOptionShown = React.useCallback(
    (option: ClusterMenuItem): boolean =>
      fuzzysearch(filterText.toLowerCase(), option.title.toLowerCase()),
    [filterText],
  );

  const filteredOptions = React.useMemo(() => optionItems.filter(isOptionShown), [
    isOptionShown,
    optionItems,
  ]);

  const emptyState: JSX.Element =
    filteredOptions.length === 0 ? (
      <NoResults
        onClear={(event) => {
          event.preventDefault();
          event.stopPropagation();
          setFilterText('');
          filterRef.current?.focus();
        }}
      />
    ) : null;

  const clusterMenu: JSX.Element = (
    <Menu ref={menuRef} isScrollable activeItemId={activeCluster} className="co-cluster-menu">
      <ClusterFilter filterText={filterText} filterRef={filterRef} onFilterChange={setFilterText} />
      <Divider />
      <MenuContent translate="no">
        {emptyState}
        <ClusterGroup clusters={filteredOptions} />
      </MenuContent>
    </Menu>
  );
  const onToggle = (isOpen: boolean) => setDropdownOpen(isOpen);

  return (
    <ClusterMenuToggle
      disabled={false}
      menu={clusterMenu}
      menuRef={menuRef}
      isOpen={dropdownOpen}
      onToggle={onToggle}
      title={
        `${activePerspective}` === 'acm' ? (
          t('console-app~All Clusters')
        ) : (
          <>
            <ClusterCIcon /> {activeCluster}
          </>
        )
      }
    />
  );
};

type ClusterMenuItem = {
  key: string;
  title: string;
  showIcon?: boolean;
  onClick: () => void;
};

export default ClusterMenu;

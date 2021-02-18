import * as React from 'react';
// eslint-disable-next-line @typescript-eslint/ban-ts-ignore
// @ts-ignore
import { useDispatch, useSelector } from 'react-redux';
import { Dropdown, DropdownItem, DropdownToggle, Title } from '@patternfly/react-core';
import { CaretDownIcon } from '@patternfly/react-icons';
import { Perspective, useExtensions, isPerspective } from '@console/plugin-sdk';
import { formatNamespaceRoute, setActiveCluster } from '@console/internal/actions/ui';
import { getActiveCluster } from '@console/internal/reducers/ui';
import { detectFeatures, clearSSARFlags } from '@console/internal/actions/features';
import { RootState } from '../../redux';
import { history } from '../utils';
import { useActiveNamespace, useActivePerspective } from '@console/shared';
import { STORAGE_PREFIX } from '@console/shared/src/constants/common';

export type NavHeaderProps = {
  onPerspectiveSelected: () => void;
};

const ClusterIcon: React.FC<{}> = () => <span className="co-m-resource-icon">C</span>;

const NavHeader: React.FC<NavHeaderProps> = ({ onPerspectiveSelected }) => {
  const dispatch = useDispatch();
  const activeCluster = useSelector((state: RootState) => getActiveCluster(state));
  const [activeNamespace] = useActiveNamespace();
  const [activePerspective, setActivePerspective] = useActivePerspective();
  const [isClusterDropdownOpen, setClusterDropdownOpen] = React.useState(false);
  const [isPerspectiveDropdownOpen, setPerspectiveDropdownOpen] = React.useState(false);
  const perspectiveExtensions = useExtensions<Perspective>(isPerspective);
  const togglePerspectiveOpen = React.useCallback(() => {
    setPerspectiveDropdownOpen(!isPerspectiveDropdownOpen);
  }, [isPerspectiveDropdownOpen]);

  const onClusterSelect = (event, cluster: string): void => {
    event.preventDefault();
    setClusterDropdownOpen(false);
    // TODO: Move this logic into `setActiveCluster`?
    dispatch(setActiveCluster(cluster));
    dispatch(clearSSARFlags());
    dispatch(detectFeatures());
    const oldPath = window.location.pathname;
    const newPath = formatNamespaceRoute(activeNamespace, oldPath, window.location, true);
    if (newPath !== oldPath) {
      history.pushPath(newPath);
    }
    window.localStorage.setItem(`${STORAGE_PREFIX}/last-cluster`, cluster);
  };

  const onPerspectiveSelect = React.useCallback(
    (event: React.MouseEvent<HTMLLinkElement>, perspective: Perspective): void => {
      event.preventDefault();
      if (perspective.properties.id !== activePerspective) {
        setActivePerspective(perspective.properties.id);
        // Navigate to root and let the default page determine where to go to next
        history.push('/');
      }

      setPerspectiveDropdownOpen(false);
      onPerspectiveSelected && onPerspectiveSelected();
    },
    [activePerspective, onPerspectiveSelected, setActivePerspective],
  );

  const renderToggle = React.useCallback(
    (icon: React.ReactNode, name: string) => (
      <DropdownToggle
        isOpen={isPerspectiveDropdownOpen}
        onToggle={togglePerspectiveOpen}
        toggleIndicator={CaretDownIcon}
        data-test-id="perspective-switcher-toggle"
      >
        <Title headingLevel="h2" size="md">
          <span className="oc-nav-header__icon">{icon}</span>
          {name}
        </Title>
      </DropdownToggle>
    ),
    [isPerspectiveDropdownOpen, togglePerspectiveOpen],
  );

  const clusterItems = [
    <DropdownItem key="hub" component="button" onClick={(e) => onClusterSelect(e, 'hub')}>
      <ClusterIcon />
      Hub Cluster
    </DropdownItem>,
    <DropdownItem key="managed" component="button" onClick={(e) => onClusterSelect(e, 'managed')}>
      <ClusterIcon />
      Managed Cluster
    </DropdownItem>,
  ];

  const perspectiveItems = React.useMemo(
    () =>
      perspectiveExtensions.map((nextPerspective: Perspective) => (
        <DropdownItem
          key={nextPerspective.properties.id}
          onClick={(event: React.MouseEvent<HTMLLinkElement>) =>
            onPerspectiveSelect(event, nextPerspective)
          }
          isHovered={nextPerspective.properties.id === activePerspective}
          component="button"
        >
          <Title headingLevel="h2" size="md" data-test-id="perspective-switcher-menu-option">
            <span className="oc-nav-header__icon">{nextPerspective.properties.icon}</span>
            {nextPerspective.properties.name}
          </Title>
        </DropdownItem>
      )),
    [activePerspective, onPerspectiveSelect, perspectiveExtensions],
  );

  const { icon, name } = React.useMemo(
    () => perspectiveExtensions.find((p) => p.properties.id === activePerspective).properties,
    [activePerspective, perspectiveExtensions],
  );

  return (
    <>
      <div className="oc-nav-header">
        <Dropdown
          isOpen={isClusterDropdownOpen}
          toggle={
            <DropdownToggle onToggle={() => setClusterDropdownOpen(!isClusterDropdownOpen)}>
              <Title headingLevel="h2" size="md">
                <ClusterIcon />
                {activeCluster === 'hub' ? 'Hub Cluster' : 'Managed Cluster'}
              </Title>
            </DropdownToggle>
          }
          dropdownItems={clusterItems}
        />
      </div>
      <div
        className="oc-nav-header"
        data-tour-id="tour-perspective-dropdown"
        data-quickstart-id="qs-perspective-switcher"
      >
        <Dropdown
          isOpen={isPerspectiveDropdownOpen}
          toggle={renderToggle(icon, name)}
          dropdownItems={perspectiveItems}
          data-test-id="perspective-switcher-menu"
        />
      </div>
    </>
  );
};

export default NavHeader;

import { Breadcrumb, BreadcrumbItem } from '@patternfly/react-core';
import classNames from 'classnames';
import * as React from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Routes, Route } from 'react-router-dom-v5-compat';

import PrimaryHeading from '@console/shared/src/components/heading/PrimaryHeading';
import { breadcrumbsForGlobalConfig } from '../../cluster-settings/global-config';
import { AlertmanagerConfig } from './alertmanager-config';
import AlertmanagerYAML from './alertmanager-yaml-editor';

const AlertmanagerPage: React.FC<{ match: { url: string } }> = ({ match }) => {
  const { t } = useTranslation();

  const configPath = '/monitoring/alertmanagerconfig';
  const YAMLPath = '/monitoring/alertmanageryaml';

  const { url } = match;

  const breadcrumbs = breadcrumbsForGlobalConfig('Alertmanager', configPath);

  return (
    <>
      <div className="pf-v6-c-page__main-breadcrumb">
        <Breadcrumb className="monitoring-breadcrumbs">
          <BreadcrumbItem>
            <Link className="pf-v6-c-breadcrumb__link" to={breadcrumbs[0].path}>
              {breadcrumbs[0].name}
            </Link>
          </BreadcrumbItem>
          <BreadcrumbItem isActive>{breadcrumbs[1].name}</BreadcrumbItem>
        </Breadcrumb>
      </div>
      <div className="co-m-nav-title co-m-nav-title--detail co-m-nav-title--breadcrumbs">
        <PrimaryHeading>
          <div className="co-m-pane__name co-resource-item">
            <span className="co-resource-item__resource-name" data-test-id="resource-title">
              {t('public~Alertmanager')}
            </span>
          </div>
        </PrimaryHeading>
      </div>
      <ul className="co-m-horizontal-nav__menu">
        <li
          className={classNames('co-m-horizontal-nav__menu-item', {
            'co-m-horizontal-nav-item--active': url === configPath,
          })}
        >
          <Link to={configPath} data-test="horizontal-link-details">
            {t('public~Details')}
          </Link>
        </li>
        <li
          className={classNames('co-m-horizontal-nav__menu-item', {
            'co-m-horizontal-nav-item--active': url === YAMLPath,
          })}
        >
          <Link to={YAMLPath} data-test-id="horizontal-link-yaml">
            {t('public~Details')}
          </Link>
        </li>
      </ul>
      <Routes>
        <Route path={configPath} element={<AlertmanagerConfig />} />
        <Route path={YAMLPath} element={<AlertmanagerYAML />} />
      </Routes>
    </>
  );
};

export default AlertmanagerPage;

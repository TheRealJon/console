/* eslint-disable no-unused-vars, no-undef */
import * as React from 'react';

import { StatefulSetModel } from '../../models';
import { menuActions } from '../stateful-set';
import { ResourceSummary } from '../utils';

import { ProjectStatusItem } from '.';
import { ProjectStatusItemDetailsDefaultResourcesTab, ProjectStatusItemDetails } from './project-status-item-details';

const OverviewTab: React.SFC<OverviewTabProps> = ({item}) =>
  <div className="project-status__sidebar-pane-body project-status-item-details__overview">
    <ResourceSummary resource={item.obj} showPodSelector showNodeSelector />
  </div>;

const tabs = [
  {
    name: 'Overview',
    component: OverviewTab,
  },
  {
    name: 'Resources',
    component: ProjectStatusItemDetailsDefaultResourcesTab,
  },
];

export const ProjectStatusStatefulSetDetails: React.SFC<ProjectStatusStatefulSetDetailsProps> = ({item}) =>
  <ProjectStatusItemDetails
    item={item}
    kindObj={StatefulSetModel}
    menuActions={menuActions}
    tabs={tabs}
  />;

type OverviewTabProps = {
  item: ProjectStatusItem;
};

type ProjectStatusStatefulSetDetailsProps = {
  item: ProjectStatusItem;
};

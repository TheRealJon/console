/* eslint-disable no-unused-vars, no-undef */
import * as React from 'react';

import { DaemonSetModel } from '../../models';
import { ResourceSummary } from '../utils';
import {
  menuActions,
  DaemonSetDetailsList,
} from '../daemon-set';

import { ProjectStatusItem } from '.';
import { ProjectStatusItemDetails, ProjectStatusItemDetailsDefaultResourcesTab } from './project-status-item-details';

const OverviewTab: React.SFC<OverviewTabProps> = ({item}) =>
  <div className="co-m-pane__body project-status__item-details-body">
    <div className="project-status__item-base-details">
      <ResourceSummary resource={item.obj} showPodSelector showNodeSelector />
    </div>
    <div className="project-status__item-distinct-details">
      <DaemonSetDetailsList ds={item.obj} />
    </div>
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

export const ProjectStatusDaemonSetDetails: React.SFC<ProjectStatusDaemonSetDetailsProps> = ({item}) =>
  <ProjectStatusItemDetails
    item={item}
    kindObj={DaemonSetModel}
    menuActions={menuActions}
    tabs={tabs}
  />;

type OverviewTabProps = {
  item: ProjectStatusItem;
};

type ProjectStatusDaemonSetDetailsProps = {
  item: ProjectStatusItem;
};

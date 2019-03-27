/* eslint-disable no-unused-vars, no-undef */
import * as React from 'react';
import { ProjectStatusItem } from '.';
import { PodResourceSummary, PodDetailsList, menuActions } from '../pod';
import { PodModel } from '../../models';
import { ProjectStatusItemDetails } from './project-status-item-details';
import { ProjectStatusRouteDetails } from './project-status-route-details';
import { ProjectStatusServiceDetails } from './project-status-service-details';

const OverviewTab: React.SFC<OverviewTabProps> = ({item:{obj: pod}}) => {
  return <div className="project-status__sidebar-pane-body project-status-item-details__overview">
    <div className="project-status-item-details__common">
      <PodResourceSummary pod={pod} />
    </div>
    <div className="project-status-item-details__distinctive">
      <PodDetailsList pod={pod} />
    </div>
  </div>;
};

const ResourcesTab: React.SFC<ResourcesTabProps> = ({item}) => <div className="project-status__sidebar-pane-body">
  <ProjectStatusServiceDetails item={item} />
  <ProjectStatusRouteDetails item={item} />
</div>;

const tabs = [
  {
    name: 'Overview',
    component: OverviewTab,
  },
  {
    name: 'Resources',
    component: ResourcesTab,
  },
];

export const ProjectStatusPodDetails: React.SFC<ProjectStatusPodDetailsProps> = ({item}) =>
  <ProjectStatusItemDetails
    item={item}
    kindObj={PodModel}
    menuActions={menuActions}
    tabs={tabs}
  />;

type OverviewTabProps = {
  item: ProjectStatusItem;
};

type ResourcesTabProps = {
  item: ProjectStatusItem;
};

type ProjectStatusPodDetailsProps = {
  item: ProjectStatusItem;
};

/* eslint-disable no-unused-vars, no-undef */
import * as React from 'react';

import { DeploymentConfigModel } from '../../models';
import {
  DeploymentConfigDetailsList,
  menuActions,
} from '../deployment-config';
import {
  DeploymentPodCounts,
  LoadingInline,
  ResourceSummary,
  WorkloadPausedAlert,
} from '../utils';

import { ProjectStatusItem } from '.';
import { ProjectStatusItemDetails, ProjectStatusItemDetailsDefaultResourcesTab } from './project-status-item-details';

const OverviewTab: React.SFC<OverviewTabProps> = ({item: {obj: dc}}) => {
  return <div className="project-status__sidebar-pane-body project-status-item-details__overview">
    {dc.spec.paused && <WorkloadPausedAlert obj={dc} model={DeploymentConfigModel} />}
    <div className="project-status-item-details__pod-counts">
      <DeploymentPodCounts resource={dc} resourceKind={DeploymentConfigModel} />
    </div>
    <div className="project-status-item-details__common">
      <ResourceSummary resource={dc} showPodSelector showNodeSelector>
        <dt>Status</dt>
        <dd>
          {
            dc.status.availableReplicas === dc.status.updatedReplicas
              ? 'Active'
              : <div>
                <span className="co-icon-space-r"><LoadingInline /></span> Updating
              </div>
          }
        </dd>
      </ResourceSummary>
    </div>
    <div className="project-status-item-details__distinctive">
      <DeploymentConfigDetailsList dc={dc} />
    </div>
  </div>;
};

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

export const ProjectStatusDeploymentConfigDetails: React.SFC<ProjectStatusDeploymentConfigDetailsProps> = ({item}) =>
  <ProjectStatusItemDetails
    item={item}
    kindObj={DeploymentConfigModel}
    menuActions={menuActions}
    tabs={tabs}
  />;

type OverviewTabProps = {
  item: ProjectStatusItem;
};

type ProjectStatusDeploymentConfigDetailsProps = {
  item: ProjectStatusItem;
};

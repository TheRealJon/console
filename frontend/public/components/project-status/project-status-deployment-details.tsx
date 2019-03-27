/* eslint-disable no-unused-vars, no-undef */
import * as React from 'react';

import { DeploymentModel } from '../../models';
import {
  DeploymentDetailsList,
  menuActions,
} from '../deployment';
import {
  DeploymentPodCounts,
  LoadingInline,
  ResourceSummary,
  WorkloadPausedAlert,
} from '../utils';

import { ProjectStatusItem } from '.';
import { ProjectStatusItemDetailsDefaultResourcesTab, ProjectStatusItemDetails } from './project-status-item-details';

const OverviewTab: React.SFC<OverviewTabProps> = ({item}) => {
  return <div className="project-status__sidebar-pane-body project-status-item-details__overview">
    {item.obj.spec.paused && <WorkloadPausedAlert obj={item.obj} model={DeploymentModel} />}
    <div className="project-status-item-details__pod-counts">
      <DeploymentPodCounts resource={item.obj} resourceKind={DeploymentModel} />
    </div>
    <div className="project-status-item-details__common">
      <ResourceSummary resource={item.obj} showPodSelector showNodeSelector>
        <dt>Status</dt>
        <dd>
          {
            item.obj.status.availableReplicas === item.obj.status.updatedReplicas
              ? 'Active'
              : <div>
                <span className="co-icon-space-r"><LoadingInline /></span> Updating
              </div>
          }
        </dd>
      </ResourceSummary>
    </div>
    <div className="project-status-item-details__distinctive">
      <DeploymentDetailsList deployment={item.obj} />
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

export const ProjectStatusDeploymentDetails: React.SFC<ProjectStatusDeploymentDetailsProps> = ({item}) =>
  <ProjectStatusItemDetails
    item={item}
    kindObj={DeploymentModel}
    menuActions={menuActions}
    tabs={tabs}
  />;

type OverviewTabProps = {
  item: ProjectStatusItem;
};

type ProjectStatusDeploymentDetailsProps = {
  item: ProjectStatusItem;
};

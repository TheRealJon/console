/* eslint-disable no-unused-vars, no-undef */
import * as React from 'react';
import { Map as ImmutableMap } from 'immutable';
import { CSSTransition } from 'react-transition-group';


import { connectToModel } from '../../kinds';
import { DaemonSetModel, DeploymentModel, DeploymentConfigModel, PodModel, StatefulSetModel } from '../../models';
import { GroupVersionKind, referenceForModel } from '../../module/k8s';
import { AsyncComponent, CloseButton } from '../utils';
import { ProjectStatusDefaultItemDetails } from './project-status-item-details';



const projectStatusSidebarByResource = ImmutableMap<GroupVersionKind | string, () => Promise<React.ComponentType<any>>>()
  .set(referenceForModel(DaemonSetModel), () => import('./project-status-daemonset-details' /* webpackChunkNmae: "daemon-set"*/).then(m => m.ProjectStatusDaemonSetDetails))
  .set(referenceForModel(DeploymentModel), () => import('./project-status-deployment-details' /* webpackChunkNmae: "deployment"*/).then(m => m.ProjectStatusDeploymentDetails))
  .set(referenceForModel(DeploymentConfigModel), () => import('./project-status-deployment-config-details' /* webpackChunkNmae: "deployment-config"*/).then(m => m.ProjectStatusDeploymentConfigDetails))
  .set(referenceForModel(PodModel), () => import('./project-status-pod-details' /* webpackChunkNmae: "pod"*/).then(m => m.ProjectStatusPodDetails))
  .set(referenceForModel(StatefulSetModel), () => import('./project-status-stateful-set-details' /* webpackChunkNmae: "stateful-set"*/).then(m => m.ProjectStatusStatefulSetDetails));


export const ProjectStatusSidebar = connectToModel(({kindObj, item, onClickClose}) => {
  const ref = referenceForModel(kindObj);
  const loader = projectStatusSidebarByResource.get(ref, () => Promise.resolve(ProjectStatusDefaultItemDetails));
  return <CSSTransition appear={true} in timeout={225} classNames="project-status__sidebar">
    <div className="project-status__sidebar" data-test-selector="project-status-sidebar">
      <div className="project-status__sidebar-dismiss clearfix">
        <CloseButton onClick={onClickClose} />
      </div>
      <AsyncComponent loader={loader} kindObj={kindObj} item={item} />
    </div>
  </CSSTransition>;

});

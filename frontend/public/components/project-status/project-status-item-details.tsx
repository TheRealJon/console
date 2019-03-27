/* eslint-disable no-unused-vars, no-undef */
import * as React from 'react';
import { connect } from 'react-redux';
import { Link } from 'react-router-dom';

import { connectToModel } from '../../kinds';
import { UIActions } from '../../ui/ui-actions';
import { K8sKind, K8sResourceKind } from '../../module/k8s';
import {
  KebabAction,
  SimpleTabNav,
  ResourceIcon,
  resourcePath,
  ActionsMenu,
  Kebab,
  ResourceSummary,
} from '../utils';

import { ProjectStatusItem } from '.';
import { ProjectStatusBuildDetails } from './project-status-build-details';
import { ProjectStatusServiceDetails } from './project-status-service-details';
import { ProjectStatusRouteDetails } from './project-status-route-details';

const { common } = Kebab.factory;
const defaultMenuActions = [...common];

export const ProjectStatusItemDetailsHeading: React.SFC<ProjectStatusItemDetailsHeadingProps> = ({kindObj, actions, resource}) =>
<div className="project-status__sidebar-pane-head" data-test-selector="project-status-sidebar-heading">
  <h1 className="co-m-pane__heading">
    <div className="co-m-pane__name">
      <ResourceIcon className="co-m-resource-icon--lg" kind={kindObj.kind} />
      <Link to={resourcePath(resource.kind, resource.metadata.name, resource.metadata.namespace)} className="co-resource-link__resource-name">
        {resource.metadata.name}
      </Link>
    </div>
    <div className="co-actions">
      <ActionsMenu actions={actions.map(a => a(kindObj, resource))} />
    </div>
  </h1>
</div>;

export const ProjectStatusItemDetailsDefaultResourcesTab: React.SFC<ProjectStatusItemDetailsDefaultResourcesTabProps>= ({item}) => (
  <div className="project-status__sidebar-pane-body">
    <ProjectStatusBuildDetails item={item} />
    <ProjectStatusServiceDetails item={item} />
    <ProjectStatusRouteDetails item={item} />
  </div>
);

export const ProjectStatusDefaultItemDetails = connectToModel( ({kindObj: kindObject, item}) =>
  <div className="project-status__sidebar-pane project-status-item-details">
    <ProjectStatusItemDetailsHeading
      actions={defaultMenuActions}
      kindObj={kindObject}
      resource={item.obj}
    />
    <div className="project-status__sidebar-pane-body project-status-item-details__body">
      <div className="project-status-item-details__common-details">
        <ResourceSummary resource={item.obj} />
      </div>
    </div>
  </div>
);


const stateToProps = ({UI}): PropsFromState => ({
  selectedTab: UI.getIn(['projectStatus', 'selectedSidebarTab']),
});

const dispatchToProps = (dispatch): PropsFromDispatch => ({
  onClickTab: (name) => dispatch(UIActions.selectProjectStatusSidebarTab(name)),
});

export const ProjectStatusItemDetails = connect<PropsFromState, PropsFromDispatch, OwnProps>(stateToProps, dispatchToProps)(
  ({kindObj, item, menuActions, onClickTab, selectedTab, tabs}: ProjectStatusSidebarProps) =>
    <div className="project-status__sidebar-pane project-status-item-details">
      <ProjectStatusItemDetailsHeading
        actions={menuActions}
        kindObj={kindObj}
        resource={item.obj}
      />
      <SimpleTabNav
        onClickTab={onClickTab}
        selectedTab={selectedTab}
        tabProps={{item}}
        tabs={tabs}
      />
    </div>
);

type ProjectStatusItemDetailsHeadingProps = {
  actions: KebabAction[];
  kindObj: K8sKind;
  resource: K8sResourceKind;
};

type ProjectStatusItemDetailsDefaultResourcesTabProps = {
  item: ProjectStatusItem;
};

type PropsFromState = {
  selectedTab: any
};

type PropsFromDispatch = {
  onClickTab: (name: string) => void;
};

type OwnProps = {
  item: ProjectStatusItem;
  kindObj: K8sKind;
  menuActions: KebabAction[];
  tabs: {
    name: string;
    component: any;
  }[];
};

type ProjectStatusSidebarProps = PropsFromState & PropsFromDispatch & OwnProps;

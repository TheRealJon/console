/* eslint-disable no-unused-vars, no-undef */
import * as React from 'react';
import * as _ from 'lodash-es';
import { ListGroup } from 'patternfly-react';

import { K8sResourceKind } from '../../module/k8s';
import { RouteLocation } from '../routes';
import { ResourceLink, SidebarSectionHeading } from '../utils';
import { ProjectStatusItem } from '.';

const RouteListItem: React.SFC<RouteListItemProps> = ({route}) => {
  const {name, namespace} = route.metadata;
  return <li className="list-group-item">
    <ResourceLink kind="Route" name={name} namespace={namespace} />
    <span className="text-muted">{'Location: '}</span><RouteLocation obj={route} />
  </li>;
};

const RouteList: React.SFC<RouteListProps> = ({routes}) => <ListGroup componentClass="ul">
  {_.map(routes, route => <RouteListItem key={route.metadata.uid} route={route} />)}
</ListGroup>;

export const ProjectStatusRouteDetails: React.SFC<ProjectStatusRouteDetailsProps> = ({item}) => {
  return <React.Fragment>
    <SidebarSectionHeading text="Routes" />
    {
      _.isEmpty(item.routes)
        ? <span className="text-muted">No Routes found for this resource.</span>
        : <RouteList routes={item.routes} />
    }
  </React.Fragment>;
};

type RouteListProps = {
  routes: K8sResourceKind[];
};

type RouteListItemProps = {
  route: K8sResourceKind;
};

type ProjectStatusRouteDetailsProps = {
  item: ProjectStatusItem;
};

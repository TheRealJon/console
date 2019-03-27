/* eslint-disable no-unused-vars, no-undef */
import * as React from 'react';
import * as _ from 'lodash-es';
import { Icon, ListGroup } from 'patternfly-react';

import { K8sResourceKind } from '../../module/k8s';
import { ResourceLink, SidebarSectionHeading } from '../utils';
import { ProjectStatusItem } from '.';

const ServicePortList: React.SFC<ServicePortListProps> = ({service}) => {
  const ports = _.get(service, 'spec.ports', []);
  return <ul className="port-list">
    {
      _.map(ports, ({name, port, protocol, targetPort}) =>
        <li key={name || `${protocol}/${port}`}>
          <span className="text-muted">Service port:</span> {name || `${protocol}/${port}`}
          &nbsp;<Icon type="fa" name="long-arrow-right" />&nbsp;
          <span className="text-muted">Pod Port:</span> {targetPort}
        </li>
      )
    }
  </ul>;
};

const ServiceListItem: React.SFC<ServiceListItemProps> = ({service}) => {
  const {name, namespace} = service.metadata;
  return <li className="list-group-item">
    <ResourceLink kind="Service" name={name} namespace={namespace} />
    <ServicePortList service={service} />
  </li>;
};

const ServiceList: React.SFC<ServiceListProps> = ({services}) => (
  <ListGroup componentClass="ul">
    {_.map(services, (service) => <ServiceListItem key={service.metadata.uid} service={service} />)}
  </ListGroup>
);

export const ProjectStatusServiceDetails: React.SFC<ProjectStatusServiceDetailsProps> = ({item}) => {
  return <React.Fragment>
    <SidebarSectionHeading text="Services" />
    {
      _.isEmpty(item.services)
        ? <span className="text-muted">No Services found for this resource.</span>
        : <ServiceList services={item.services} />
    }
  </React.Fragment>;
};

type ServicePortListProps = {
  service: K8sResourceKind;
};

type ServiceListProps = {
  services: K8sResourceKind[];
};

type ServiceListItemProps = {
  service: K8sResourceKind;
};

type ProjectStatusServiceDetailsProps = {
  item: ProjectStatusItem;
};

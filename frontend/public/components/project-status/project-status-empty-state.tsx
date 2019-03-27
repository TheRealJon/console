/* eslint-disable no-unused-vars, no-undef */
import * as _ from 'lodash-es';
import * as React from 'react';
import { connect } from 'react-redux';
import { EmptyState } from 'patternfly-react';
import { Link } from 'react-router-dom';
import { Map } from 'immutable';

import { formatNamespacedRouteForResource } from '../../ui/ui-actions';
import { EmptyBox } from '../utils';

// Namespace prefixes that are reserved and should not have calls to action on empty state
export const RESERVED_NS_PREFIXES = ['openshift-', 'kube-', 'kubernetes-'];

const isReservedNamespace = (ns: string): boolean => ns === 'default' || ns === 'openshift' || RESERVED_NS_PREFIXES.some(prefix => _.startsWith(ns, prefix));

const stateToProps = ({UI}): PropsFromState => ({
  activeNamespace: UI.get('activeNamespace'),
  items: UI.getIn(['projectStatus', 'items']),
});

export const ProjectStatusEmptyState = connect<PropsFromState>(stateToProps)(({activeNamespace, items}) => {
  // Don't encourage users to add content to system namespaces.
  if (items.isEmpty() && !isReservedNamespace(activeNamespace)) {
    return <EmptyState>
      <EmptyState.Title>
        Get started with your project.
      </EmptyState.Title>
      <EmptyState.Info>
        Add content to your project from the catalog of web frameworks, databases, and other components. You may also deploy an existing image or create resources using YAML definitions.
      </EmptyState.Info>
      <EmptyState.Action>
        <Link to="/catalog" className="btn btn-primary">
          Browse Catalog
        </Link>
      </EmptyState.Action>
      <EmptyState.Action secondary>
        <Link className="btn btn-default" to={`/deploy-image?preselected-ns=${activeNamespace}`}>
          Deploy Image
        </Link>
        <Link className="btn btn-default" to={formatNamespacedRouteForResource('import', activeNamespace)}>
          Import YAML
        </Link>
      </EmptyState.Action>
    </EmptyState>;
  }
  return <EmptyBox label="Resources" />;
});

type PropsFromState = {
  activeNamespace: string,
  items: Map<any, any>;
};

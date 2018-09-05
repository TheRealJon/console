import * as React from 'react';
import * as _ from 'lodash-es';
import * as fuzzy from 'fuzzysearch';
import * as PropTypes from 'prop-types';
import * as classnames from 'classnames';

import { Toolbar } from 'patternfly-react';
import { Helmet } from 'react-helmet';

import { StartGuide } from './start-guide';
import { Dropdown, Firehose, NavTitle, StatusBox, ResourceSummary } from './utils';
import { TextFilter } from './factory';
import { ProjectOverview } from './project-overview';

const getOwnedResources = (resources, uid) => {
  return _.filter(resources, ({metadata:{ownerReferences}}) => {
    return _.some(ownerReferences, {
      uid,
      controller: true
    });
  });
};

const OverviewToolbar = ({groupOptions, handleFilterChange, handleGroupChange, selectedGroup}) =>
  <Toolbar className="overview-toolbar">
    <Toolbar.RightContent>
      {
        !_.isEmpty(groupOptions) &&
        <div className="form-group overview-toolbar__form-group">
          <label className="overview-toolbar__label">
            Group by label
          </label>
          <Dropdown
            className="overview-toolbar__dropdown"
            disabled={_.isEmpty(groupOptions)}
            items={groupOptions}
            onChange={handleGroupChange}
            style={{display: 'inline-block'}}
            title={selectedGroup}
          />
        </div>
      }
      <div className="form-group overview-toolbar__form-group">
        <TextFilter
          label="Resources by name"
          onChange={handleFilterChange}
        />
      </div>
    </Toolbar.RightContent>
  </Toolbar>;

OverviewToolbar.displayName = 'OverviewToolbar';

OverviewToolbar.propTypes = {
  groupOptions: PropTypes.object,
  handleFilterChange: PropTypes.func.isRequired,
  handleGroupChange: PropTypes.func.isRequired,
  selectedGroup: PropTypes.string
};

class OverviewDetails extends React.Component {
  constructor(props) {
    super(props);
    this.handleFilterChange = this.handleFilterChange.bind(this);
    this.handleGroupChange = this.handleGroupChange.bind(this);
    this.clearFilter = this.clearFilter.bind(this);

    this.state = {
      filterValue: '',
      items: [],
      filteredItems: [],
      groupedItems: [],
      groupOptions: {},
      selectedGroupLabel: ''
    };
  }

  componentDidUpdate(prevProps, prevState) {
    const {deployments, deploymentConfigs, namespace, pods, replicaSets, replicationControllers} = this.props;
    const {filterValue, selectedGroupLabel} = this.state;

    if (namespace !== prevProps.namespace
      || replicationControllers !== prevProps.replicationControllers
      || replicaSets !== prevProps.replicaSets
      || pods !== prevProps.pods
      || deploymentConfigs !== prevProps.deploymentConfigs
      || deployments !== prevProps.deployments) {
      this.createOverviewData();
    } else if (filterValue !== prevState.filterValue) {
      const filteredItems = this.filterItems(this.state.items);
      this.setState({
        filteredItems,
        groupedItems: this.groupItems(filteredItems, selectedGroupLabel)
      });
    } else if (selectedGroupLabel !== prevState.selectedGroupLabel) {
      this.setState({
        groupedItems: this.groupItems(this.state.filteredItems, selectedGroupLabel)
      });
    }
  }

  sortByRevision(replicators, descending, annotation) {
    const compare = (left, right) => {
      const leftVersion = parseInt(_.get(left, ['metadata', 'annotations', annotation]), 10);
      const rightVersion = parseInt(_.get(right, ['metadata', 'annotations', annotation]), 10);
      if (!_.isFinite(leftVersion) && !_.isFinite(rightVersion)) {
        const leftName = _.get(left, 'metadata.name', '');
        const rightName = _.get(right, 'metadata.name', '');
        if (descending) {
          return rightName.localeCompare(leftName);
        }
        return leftName.localeCompare(rightName);
      }

      if (!leftVersion) {
        return descending ? 1 : -1;
      }

      if (!rightVersion) {
        return descending ? -1 : 1;
      }

      if (descending) {
        return rightVersion - leftVersion;
      }

      return leftVersion - rightVersion;
    };

    return _.toArray(replicators).sort(compare);
  }

  sortRSByRevison(replicaSets, descending) {
    return this.sortByRevision(replicaSets, descending, 'deployment.kubernetes.io/revision');
  }

  sortRCByRevision(replicationControllers, descending) {
    return this.sortByRevision(replicationControllers, descending, 'openshift.io/deployment-config.latest-version');
  }

  filterItems(items) {
    const {filterValue} = this.state;
    const {currentSelection} = this.props;

    if (!filterValue) {
      return items;
    }

    const filterString = filterValue.toLowerCase();
    return _.filter(items, item => {
      return fuzzy(filterString, _.get(item, 'metadata.name', '')) || _.get(item, 'metadata.uid') === _.get(currentSelection, 'metadata.uid');
    });
  }

  groupItems(items, label) {
    const compareGroups = (a, b) => {
      if (a.name === 'other') {
        return 1;
      }
      if (b.name === 'other') {
        return -1;
      }
      return a.name.localeCompare(b.name);
    };

    if (!label) {
      return [{items}];
    }

    const groups = _.groupBy(items, item => _.get(item, ['metadata', 'labels', label], 'other'));
    return _.map(groups, (group, name) => {
      return {
        name,
        items: group
      };
    }).sort(compareGroups);
  }

  getGroupOptionsFromLabels(items) {
    const {groupOptions} = this.state;
    const labelKeys = _.flatMap(items, item => _.keys(item.metadata.labels));
    return _.reduce(labelKeys, (accumulator, key) => {
      if (_.has(key, accumulator)) {
        return accumulator;
      }
      return {
        ...accumulator,
        [key]: key
      };
    }, groupOptions);
  }

  buildGraphForReplicators(replicators, kind) {
    const {pods} = this.props;
    return _.map(replicators, replicator => {
      const {uid: replicatorUid} = replicator.metadata;
      const ownedPods = getOwnedResources(pods.data, replicatorUid);
      return {
        ...replicator,
        kind,
        pods: ownedPods
      };
    });
  }

  buildGraphForRootResources(rootResources, kind) {
    const {replicationControllers, replicaSets} = this.props;

    return _.map(rootResources, rootResource => {
      const {uid: rootResourceUid} = rootResource.metadata;
      // Determine the replication controllers/replica sets associated with these resources
      const ownedReplicationControllers = this.buildGraphForReplicators(getOwnedResources(replicationControllers.data, rootResourceUid), 'ReplicationController');
      const ownedReplicaSets = this.buildGraphForReplicators(getOwnedResources(replicaSets.data, rootResourceUid), 'ReplicaSet');
      const orderedReplicationControllers = this.sortRCByRevision(ownedReplicationControllers, 'ReplicationController', true);
      const orderedReplicaSets = this.sortRSByRevison(ownedReplicaSets, 'ReplicaSet', true);
      const currentController = _.head(orderedReplicationControllers) || _.head(orderedReplicaSets);

      return {
        ...rootResource,
        currentController,
        kind,
        replicaSets: orderedReplicaSets,
        replicationControllers: orderedReplicationControllers,
      };
    });
  }

  createOverviewData() {
    const {deploymentConfigs, deployments, loaded, statefulSets} = this.props;

    if (!loaded) {
      return;
    }

    const deploymentConfigItems = this.buildGraphForRootResources(deploymentConfigs.data, 'DeploymentConfig');
    const deploymentItems = this.buildGraphForRootResources(deployments.data, 'Deployment');
    const statefulSetItems = this.buildGraphForReplicators(statefulSets.data, 'StatefulSet');

    const items = [
      ...deploymentConfigItems,
      ...deploymentItems,
      ...statefulSetItems
    ];

    const filteredItems = this.filterItems(items);
    const groupOptions = this.getGroupOptionsFromLabels(filteredItems);
    const selectedGroupLabel = _.has(groupOptions, 'app') ? 'app' : _.head(_.keys(groupOptions));
    const groupedItems = this.groupItems(filteredItems, selectedGroupLabel);
    this.setState({items, filteredItems, groupedItems, groupOptions, selectedGroupLabel});
  }

  handleFilterChange(event) {
    this.setState({filterValue: event.target.value});
  }

  handleGroupChange(selectedGroupLabel) {
    this.setState({selectedGroupLabel});
  }

  clearFilter() {
    this.setState({filterValue: ''});
  }

  render() {
    const {currentSelection, loaded, loadError, title} = this.props;
    const {filteredItems, filterValue, groupedItems, groupOptions, selectedGroupLabel} = this.state;
    return <React.Fragment>
      {title && <NavTitle title={title} />}
      <div className="co-m-pane">
        <div className="co-m-pane__body">
          <OverviewToolbar
            filterValue={filterValue}
            groupOptions={groupOptions}
            handleFilterChange={this.handleFilterChange}
            handleGroupChange={this.handleGroupChange}
            selectedGroup={selectedGroupLabel}
            title={title}
          />
          <StatusBox
            data={filteredItems}
            loaded={loaded}
            loadError={loadError}
            label="Resources"
          >
            <ProjectOverview
              currentSelection={currentSelection}
              groups={groupedItems}
              onClickItem={this.props.selectItem}
            />
          </StatusBox>
        </div>
      </div>
    </React.Fragment>;
  }
}

OverviewDetails.displayName = 'OverviewDetails';

OverviewDetails.propTypes = {
  deploymentConfigs: PropTypes.object,
  deployments: PropTypes.object,
  loaded: PropTypes.bool,
  loadError: PropTypes.object,
  pods: PropTypes.object,
  replicationControllers: PropTypes.object,
  replicaSets: PropTypes.object,
  statefulSets: PropTypes.object,
};

export class Overview extends React.Component {
  constructor(props){
    super(props);
    this.selectItem = this.selectItem.bind(this);
    this.state = {
      currentSelection: {}
    };
  }

  selectItem(currentSelection){
    this.setState({currentSelection});
  }

  render() {
    const {namespace, title} = this.props;
    const {currentSelection} = this.state;
    const className = classnames('overview', {'overview--sidebar-shown': !_.isEmpty(currentSelection)});
    const resources = [
      {
        isList: true,
        kind: 'Pod',
        namespace,
        prop: 'pods'
      },
      {
        isList: true,
        kind: 'ReplicationController',
        namespace,
        prop: 'replicationControllers'
      },
      {
        isList: true,
        kind: 'DeploymentConfig',
        namespace,
        prop: 'deploymentConfigs'
      },
      {
        isList: true,
        kind: 'Deployment',
        namespace,
        prop: 'deployments'
      },
      {
        isList: true,
        kind: 'ReplicaSet',
        namespace,
        prop: 'replicaSets'
      },
      {
        isList: true,
        kind: 'StatefulSet',
        namespace,
        prop: 'statefulSets'
      }
    ];

    return <div className={className}>
      <div className="overview__body">
        <Firehose resources={resources} forceUpdate={true}>
          <OverviewDetails
            title={title}
            currentSelection={currentSelection}
            selectItem={this.selectItem}
          />
        </Firehose>
      </div>
      { !_.isEmpty(currentSelection) &&
        <div className="overview__sidebar">
          <NavTitle
            title={_.get(currentSelection, 'metadata.name')}
            kind={currentSelection.kind}
          />
          <div className="co-m-pane">
            <div className="co-m-pane__body">
              <ResourceSummary resource={currentSelection} />
            </div>
          </div>
        </div>
      }
    </div>;
  }
}

Overview.displayName = 'Overview';

Overview.propTypes = {
  namespace: PropTypes.string.isRequired,
  title: PropTypes.string
};


export const OverviewPage = ({match}) => {
  const namespace = _.get(match, 'params.ns');
  return <React.Fragment>
    <Helmet>
      <title>Project Overview</title>
    </Helmet>
    <StartGuide dismissible={true} style={{margin: 15}} />
    <Overview title="Project Overview" namespace={namespace} />
  </React.Fragment>;
};

OverviewPage.displayName = 'OverviewPage';

OverviewPage.propTypes = {
  match: PropTypes.object.isRequired
};

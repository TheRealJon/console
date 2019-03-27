/* eslint-disable no-unused-vars, no-undef */
import * as _ from 'lodash-es';
import * as classnames from 'classnames';
import * as fuzzy from 'fuzzysearch';
import * as React from 'react';
import { connect } from 'react-redux';
import { Helmet } from 'react-helmet';
import { Link } from 'react-router-dom';

import { coFetchJSON } from '../../co-fetch';
import { getBuildNumber } from '../../module/k8s/builds';
import { prometheusTenancyBasePath } from '../graphs';
import { UIActions } from '../../ui/ui-actions';
import {
  apiVersionForModel,
  K8sResourceKind,
  LabelSelector,
} from '../../module/k8s';
import {
  withStartGuide,
  WithStartGuideProps,
} from '../start-guide';
import {
  DaemonSetModel,
  DeploymentModel,
  DeploymentConfigModel,
  PodModel,
  ReplicationControllerModel,
  ReplicaSetModel,
  StatefulSetModel,
} from '../../models';
import {
  Firehose,
  StatusBox,
  resourceObjPath,
} from '../utils';

import { ProjectStatusDashboard } from './project-status-dashboard';
import { ProjectStatusList } from './project-status-list';
import { ProjectStatusSidebar } from './project-status-sidebar';
import { PodStatus } from '../pod';
import { ProjectStatusHeading } from './project-status-heading';
import { ProjectStatusEmptyState } from './project-status-empty-state';
import { ProjectStatusSpecialGroup, ProjectStatusViewOption } from './constants';

// List of container status waiting reason values that we should call out as errors in project status rows.
const CONTAINER_WAITING_STATE_ERROR_REASONS = ['CrashLoopBackOff', 'ErrImagePull', 'ImagePullBackOff'];

// Annotation key for deployment config latest version
const DEPLOYMENT_CONFIG_LATEST_VERSION_ANNOTATION = 'openshift.io/deployment-config.latest-version';

// Annotation key for deployment phase
const DEPLOYMENT_PHASE_ANNOTATION = 'openshift.io/deployment.phase';

// Annotaton key for deployment revision
const DEPLOYMENT_REVISION_ANNOTATION = 'deployment.kubernetes.io/revision';

// Name for project status groups that don't have a value for the selected group by option.
// Should not be a valid label key to avoid conflicts. https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-setexport
const EMPTY_GROUP_NAME = 'other resources';

// Interval at which metrics are retrieved and updated
const METRICS_POLL_INTERVAL = 30 * 1000;

// Annotation key for image triggers
const TRIGGERS_ANNOTATION = 'image.openshift.io/triggers';

const asProjectStatusGroups = (keyedItems: { [name: string]: ProjectStatusItem[] }): ProjectStatusGroup[] => {
  const compareGroups = (a: ProjectStatusGroup, b: ProjectStatusGroup) => {
    if (a.name === EMPTY_GROUP_NAME) {
      return 1;
    }
    if (b.name === EMPTY_GROUP_NAME) {
      return -1;
    }
    return a.name.localeCompare(b.name);
  };

  return _.map(keyedItems, (group: ProjectStatusItem[], name: string): ProjectStatusGroup => {
    return {
      name,
      items: group,
    };
  }).sort(compareGroups);
};

const getApplication = (item: ProjectStatusItem): string => {
  const labels = _.get(item, 'obj.metadata.labels') || {};
  return labels['app.kubernetes.io/part-of'] || labels['app.kubernetes.io/name'] || labels.app || EMPTY_GROUP_NAME;
};

const groupByApplication = (items: ProjectStatusItem[]): ProjectStatusGroup[] => {
  const byApplication = _.groupBy(items, getApplication);
  return asProjectStatusGroups(byApplication);
};

const groupByResource = (items: ProjectStatusItem[]): ProjectStatusGroup[] => {
  const byResource = _.groupBy(items, item => _.startCase(item.obj.kind));
  return asProjectStatusGroups(byResource);
};

const groupByLabel = (items: ProjectStatusItem[], label: string): ProjectStatusGroup[] => {
  const byLabel = _.groupBy(items, (item): string => _.get(item, ['obj', 'metadata', 'labels', label]) || EMPTY_GROUP_NAME);
  return asProjectStatusGroups(byLabel);
};

const groupItems = (items: ProjectStatusItem[], selectedGroup: string): ProjectStatusGroup[] => {
  switch (selectedGroup) {
    case ProjectStatusSpecialGroup.GROUP_BY_APPLICATION:
      return groupByApplication(items);
    case ProjectStatusSpecialGroup.GROUP_BY_RESOURCE:
      return groupByResource(items);
    default:
      return groupByLabel(items, selectedGroup);
  }
};

const getAnnotation = (obj: K8sResourceKind, annotation: string): string => {
  return _.get(obj, ['metadata', 'annotations', annotation]);
};

const getDeploymentRevision = (obj: K8sResourceKind): number => {
  const revision = getAnnotation(obj, DEPLOYMENT_REVISION_ANNOTATION);
  return revision && parseInt(revision, 10);
};

const getDeploymentConfigVersion = (obj: K8sResourceKind): number => {
  const version = getAnnotation(obj, DEPLOYMENT_CONFIG_LATEST_VERSION_ANNOTATION);
  return version && parseInt(version, 10);
};

const getAnnotatedTriggers = (obj: K8sResourceKind) => {
  const triggersJSON = getAnnotation(obj, TRIGGERS_ANNOTATION) || '[]';
  try {
    return JSON.parse(triggersJSON);
  } catch (e) {
    /* eslint-disable-next-line no-console */
    console.warn('Error parsing triggers annotation', e);
    return [];
  }
};

const getDeploymentPhase = (rc: K8sResourceKind): string => _.get(rc, ['metadata', 'annotations', DEPLOYMENT_PHASE_ANNOTATION]);

// Only show an alert once if multiple pods have the same error for the same owner.
const podAlertKey = (alert: any, pod: K8sResourceKind, containerName: string = 'all'): string => {
  const id = _.get(pod, 'metadata.ownerReferences[0].uid', pod.metadata.uid);
  return `${alert}--${id}--${containerName}`;
};

const getPodAlerts = (pod: K8sResourceKind): ProjectStatusItemAlerts => {
  const alerts = {};
  const statuses = [
    ..._.get(pod, 'status.initContainerStatuses', []),
    ..._.get(pod, 'status.containerStatuses', []),
  ];
  statuses.forEach(status => {
    const { name, state } = status;
    const waitingReason = _.get(state, 'waiting.reason');
    if (CONTAINER_WAITING_STATE_ERROR_REASONS.includes(waitingReason)) {
      const key = podAlertKey(waitingReason, pod, name);
      const message = state.waiting.message || waitingReason;
      alerts[key] = { severity: 'error', message };
    }
  });

  _.get(pod, 'status.conditions', []).forEach(condition => {
    const { type, status, reason, message } = condition;
    if (type === 'PodScheduled' && status === 'False' && reason === 'Unschedulable') {
      const key = podAlertKey(reason, pod, name);
      alerts[key] = {
        severity: 'error',
        message: `${reason}: ${message}`,
      };
    }
  });

  return alerts;
};

const combinePodAlerts = (pods: K8sResourceKind[]): ProjectStatusItemAlerts => _.reduce(pods, (acc, pod) => ({
  ...acc,
  ...getPodAlerts(pod),
}), {});

const getReplicationControllerAlerts = (rc: K8sResourceKind): ProjectStatusItemAlerts => {
  const phase = getDeploymentPhase(rc);
  const version = getDeploymentConfigVersion(rc);
  const label = _.isFinite(version) ? `#${version}` : rc.metadata.name;
  const key = `${rc.metadata.uid}--Rollout${phase}`;
  switch (phase) {
    case 'Cancelled':
      return {
        [key]: {
          severity: 'info',
          message: `Rollout ${label} was cancelled.`,
        },
      };
    case 'Failed':
      return {
        [key]: {
          severity: 'error',
          message: `Rollout ${label} failed.`,
        },
      };
    default:
      return {};
  }
};

const getResourcePausedAlert = (resource): ProjectStatusItemAlerts => {
  if (!resource.spec.paused) {
    return {};
  }
  return {
    [`${resource.metadata.uid}--Paused`]: {
      severity: 'info',
      message: `${resource.metadata.name} is paused.`,
    },
  };
};

const getOwnedResources = ({metadata:{uid}}: K8sResourceKind, resources: K8sResourceKind[]): K8sResourceKind[] => {
  return _.filter(resources, ({metadata:{ownerReferences}}) => {
    return _.some(ownerReferences, {
      uid,
      controller: true,
    });
  });
};

const sortByRevision = (replicators: K8sResourceKind[], getRevision: Function, descending: boolean = true): K8sResourceKind[] => {
  const compare = (a, b) => {
    const left = descending ? b : a;
    const right = descending ? a : b;
    const leftVersion = getRevision(left);
    const rightVersion = getRevision(right);
    if (!_.isFinite(leftVersion) && !_.isFinite(rightVersion)) {
      const leftName = _.get(left, 'metadata.name', '');
      const rightName = _.get(right, 'metadata.name', '');
      return leftName.localeCompare(rightName);
    }
    if (!leftVersion) {
      return -1;
    }
    if (!rightVersion) {
      return 1;
    }
    return leftVersion - rightVersion;
  };

  return _.toArray(replicators).sort(compare);
};

const sortReplicaSetsByRevision = (replicaSets: K8sResourceKind[]): K8sResourceKind[] => {
  return sortByRevision(replicaSets, getDeploymentRevision);
};

const sortReplicationControllersByRevision = (replicationControllers: K8sResourceKind[]): K8sResourceKind[] => {
  return sortByRevision(replicationControllers, getDeploymentConfigVersion);
};

const sortBuilds = (builds: K8sResourceKind[]): K8sResourceKind[] => {

  const byCreationTime = (left, right) => {
    const leftCreationTime = new Date(_.get(left, 'metadata.creationTimestamp', Date.now()));
    const rightCreationTime = new Date(_.get(right, 'metadata.creationTimestamp', Date.now()));
    return rightCreationTime.getMilliseconds() - leftCreationTime.getMilliseconds();
  };

  const byBuildNumber = (left, right) => {
    const leftBuildNumber = getBuildNumber(left);
    const rightBuildNumber = getBuildNumber(right);
    if (!_.isFinite(leftBuildNumber) || !_.isFinite(rightBuildNumber)) {
      return byCreationTime(left, right);
    }
    return rightBuildNumber - leftBuildNumber;
  };

  return builds.sort(byBuildNumber);
};

const ProjectStatusItemReadiness: React.SFC<ProjectStatusItemReadinessProps> = ({desired = 0, ready = 0, resource}) => {
  const href = `${resourceObjPath(resource, resource.kind)}/pods`;
  return <Link to={href}>
    {ready} of {desired} pods
  </Link>;
};

const mainContentStateToProps = ({UI}): ProjectStatusMainContentPropsFromState => {
  const metrics = UI.getIn(['projectStatus', 'metrics']);
  const selectedView = UI.getIn(['projectStatus', 'selectedView']);
  return { metrics, selectedView };
};

const mainContentDispatchToProps = (dispatch): ProjectStatusMainContentPropsFromDispatch => ({
  updateMetrics: (metrics: ProjectStatusMetrics) => dispatch(UIActions.updateProjectStatusMetrics(metrics)),
  updateItems: (items: ProjectStatusItem[]) => dispatch(UIActions.updateProjectStatusItems(items)),
});

const ProjectStatusMainContent = connect<ProjectStatusMainContentPropsFromState, ProjectStatusMainContentPropsFromDispatch, ProjectStatusMainContentOwnProps>(mainContentStateToProps, mainContentDispatchToProps)(
  class extends React.Component<ProjectStatusMainContentProps, ProjectStatusMainContentState> {
    private metricsInterval: any = null;

    readonly state: ProjectStatusMainContentState = {
      filterValue: '',
      items: [],
      filteredItems: [],
      groupedItems: [],
      firstLabel: '',
      groupOptions: {},
      selectedGroup: '',
    };

    componentDidMount(): void {
      this.fetchMetrics();
    }

    componentWillUnmount(): void {
      clearInterval(this.metricsInterval);
    }

    componentDidUpdate(prevProps: ProjectStatusMainContentProps, prevState: ProjectStatusMainContentState): void {
      const {
        builds,
        buildConfigs,
        daemonSets,
        deployments,
        deploymentConfigs,
        loaded,
        namespace,
        pods,
        replicaSets,
        replicationControllers,
        routes,
        services,
        statefulSets,
        selectedView,
      } = this.props;
      const {filterValue, selectedGroup} = this.state;

      if (namespace !== prevProps.namespace
        || loaded !== prevProps.loaded
        || !_.isEqual(buildConfigs, prevProps.buildConfigs)
        || !_.isEqual(builds, prevProps.builds)
        || !_.isEqual(daemonSets, prevProps.daemonSets)
        || !_.isEqual(deploymentConfigs, prevProps.deploymentConfigs)
        || !_.isEqual(deployments, prevProps.deployments)
        || !_.isEqual(pods, prevProps.pods)
        || !_.isEqual(replicaSets, prevProps.replicaSets)
        || !_.isEqual(replicationControllers, prevProps.replicationControllers)
        || !_.isEqual(routes, prevProps.routes)
        || !_.isEqual(services, prevProps.services)
        || !_.isEqual(statefulSets, prevProps.statefulSets)) {
        this.createProjectStatusData();
      } else if (filterValue !== prevState.filterValue) {
        const filteredItems = this.filterItems(this.state.items);
        this.setState({
          filteredItems,
          groupedItems: groupItems(filteredItems, selectedGroup),
        });
      } else if (selectedGroup !== prevState.selectedGroup) {
        this.setState({
          groupedItems: groupItems(this.state.filteredItems, selectedGroup),
        });
      } else if (selectedView !== prevProps.selectedView && selectedView === ProjectStatusViewOption.DASHBOARD) {
        // TODO: Preserve filter when switching to dashboard view and back.
        // ProjectStatusHeading doesn't keep the value in state.
        this.setState({ filterValue: '' });
      }

      // Fetch new metrics when the namespace changes.
      if (namespace !== prevProps.namespace) {
        clearInterval(this.metricsInterval);
        this.fetchMetrics();
      }
    }

    fetchMetrics = (): void => {
      if (!prometheusTenancyBasePath) {
        return;
      }

      const { metrics: previousMetrics, namespace } = this.props;
      const queries = {
        memory: `pod_name:container_memory_usage_bytes:sum{namespace="${namespace}"}`,
        cpu: `pod_name:container_cpu_usage:sum{namespace="${namespace}"}`,
      };

      const promises = _.map(queries, (query, name) => {
        const url = `${prometheusTenancyBasePath}/api/v1/query?namespace=${namespace}&query=${encodeURIComponent(query)}`;
        return coFetchJSON(url).then(({ data: {result} }) => {
          const byPod: MetricValuesByPod = result.reduce((acc, { metric, value }) => {
            acc[metric.pod_name] = Number(value[1]);
            return acc;
          }, {});
          return { [name]: byPod };
        });
      });

      Promise.all(promises).then((data) => {
        const metrics = data.reduce((acc: ProjectStatusMetrics, metric): ProjectStatusMetrics => _.assign(acc, metric), {});
        this.props.updateMetrics(metrics);
      }).catch(res => {
        const status = _.get(res, 'response.status');
        // eslint-disable-next-line no-console
        console.error('Could not fetch metrics, status:', status);
        // Don't retry on some status codes unless a previous request succeeded.
        if (_.includes([401, 403, 502, 503], status) && _.isEmpty(previousMetrics)) {
          throw new Error(`Could not fetch metrics, status: ${status}`);
        }
      }).then(() => {
        this.metricsInterval = setTimeout(this.fetchMetrics, METRICS_POLL_INTERVAL);
      });
    }

    filterItems(items: ProjectStatusItem[]): ProjectStatusItem[] {
      const {selectedItem} = this.props;
      const {filterValue} = this.state;

      if (!filterValue) {
        return items;
      }

      const filterString = filterValue.toLowerCase();
      return _.filter(items, item => {
        return fuzzy(filterString, _.get(item, 'obj.metadata.name', ''))
          || _.get(item, 'obj.metadata.uid') === _.get(selectedItem, 'obj.metadata.uid');
      });
    }

    getGroupOptionsFromLabels(items: ProjectStatusItem[]): any {
      const specialGroups = {
        [ProjectStatusSpecialGroup.GROUP_BY_APPLICATION]: 'Application',
        [ProjectStatusSpecialGroup.GROUP_BY_RESOURCE]: 'Resource',
      };

      const labelKeys = _.flatMap(items, item => _.keys(_.get(item, 'obj.metadata.labels'))).sort();
      if (_.isEmpty(labelKeys)) {
        return { firstLabel: '', groupOptions: specialGroups };
      }

      const firstLabel = _.first(labelKeys);
      const groupOptions = _.reduce(labelKeys, (accumulator, key) => ({
        ...accumulator,
        [key]: key,
      }), specialGroups);
      return { firstLabel, groupOptions };
    }

    getPodsForResource(resource: K8sResourceKind): K8sResourceKind[] {
      const {pods} = this.props;
      return getOwnedResources(resource, pods.data);
    }

    getRoutesForServices(services: K8sResourceKind[]): K8sResourceKind[] {
      const {routes} = this.props;
      return _.filter(routes.data, route => {
        const name = _.get(route, 'spec.to.name');
        return _.some(services, {metadata: {name}});
      });
    }

    getServicesForResource(resource: K8sResourceKind): K8sResourceKind[] {
      const {services} = this.props;
      const template = resource.kind === 'Pod' ? resource : _.get(resource, 'spec.template');
      return _.filter(services.data, service => {
        const selector = new LabelSelector(_.get(service, 'spec.selector', {}));
        return selector.matches(template);
      });
    }

    toReplicationControllerItem(rc: K8sResourceKind): ProjectStatusPodControllerItem {
      const pods = this.getPodsForResource(rc);
      const alerts = {
        ...combinePodAlerts(pods),
        ...getReplicationControllerAlerts(rc),
      };
      const phase = getDeploymentPhase(rc);
      const revision = getDeploymentConfigVersion(rc);
      const obj = {
        ...rc,
        apiVersion: apiVersionForModel(ReplicationControllerModel),
        kind: ReplicationControllerModel.kind,
      };
      return {
        alerts,
        obj,
        phase,
        pods,
        revision,
      };
    }

    getActiveReplicationControllers(resource: K8sResourceKind): K8sResourceKind[] {
      const {replicationControllers} = this.props;
      const currentVersion = _.get(resource, 'status.latestVersion');
      const ownedRC = getOwnedResources(resource, replicationControllers.data);
      return _.filter(ownedRC, rc => _.get(rc, 'status.replicas') || getDeploymentConfigVersion(rc) === currentVersion);
    }

    getReplicationControllersForResource(resource: K8sResourceKind): ProjectStatusPodControllerItem[] {
      const replicationControllers = this.getActiveReplicationControllers(resource);
      return sortReplicationControllersByRevision(replicationControllers).map(rc => this.toReplicationControllerItem(rc));
    }

    toReplicaSetItem(rs: K8sResourceKind): ProjectStatusPodControllerItem {
      const obj = {
        ...rs,
        apiVersion: apiVersionForModel(ReplicaSetModel),
        kind: ReplicaSetModel.kind,
      };
      const pods = this.getPodsForResource(rs);
      const alerts = combinePodAlerts(pods);
      return {
        alerts,
        obj,
        pods,
        revision: getDeploymentRevision(rs),
      };
    }

    getActiveReplicaSets(deployment: K8sResourceKind): K8sResourceKind[] {
      const {replicaSets} = this.props;
      const currentRevision = getDeploymentRevision(deployment);
      const ownedRS = getOwnedResources(deployment, replicaSets.data);
      return _.filter(ownedRS, rs => _.get(rs, 'status.replicas') || getDeploymentRevision(rs) === currentRevision);
    }

    getReplicaSetsForResource(deployment: K8sResourceKind): ProjectStatusPodControllerItem[] {
      const replicaSets = this.getActiveReplicaSets(deployment);
      return sortReplicaSetsByRevision(replicaSets).map(rs => this.toReplicaSetItem(rs));
    }

    getBuildsForResource(buildConfig: K8sResourceKind): K8sResourceKind[] {
      const {builds} = this.props;
      return getOwnedResources(buildConfig, builds.data);
    }

    getBuildConfigsForResource(resource: K8sResourceKind): ProjectStatusBuildConfigItem[] {
      const {buildConfigs} = this.props;
      const currentNamespace = resource.metadata.namespace;
      const nativeTriggers = _.get(resource, 'spec.triggers');
      const annotatedTriggers = getAnnotatedTriggers(resource);
      const triggers = _.unionWith(nativeTriggers, annotatedTriggers, _.isEqual);
      return _.flatMap(triggers, (trigger) => {
        const triggerFrom = trigger.from || _.get(trigger, 'imageChangeParams.from', {});
        if ( triggerFrom.kind !== 'ImageStreamTag') {
          return [];
        }
        return _.reduce(buildConfigs.data, (acc, buildConfig) => {
          const triggerImageNamespace = triggerFrom.namespace || currentNamespace;
          const triggerImageName = triggerFrom.name;
          const targetImageNamespace = _.get(buildConfig, 'spec.output.to.namespace', currentNamespace);
          const targetImageName = _.get(buildConfig, 'spec.output.to.name');
          if (triggerImageNamespace === targetImageNamespace && triggerImageName === targetImageName) {
            const builds = this.getBuildsForResource(buildConfig);
            return [
              ...acc,
              {
                ...buildConfig,
                builds: sortBuilds(builds),
              },
            ];
          }
          return acc;
        }, []);
      });
    }

    createDaemonSetItems(): ProjectStatusItem[] {
      const {daemonSets} = this.props;
      return _.map(daemonSets.data, ds => {
        const buildConfigs = this.getBuildConfigsForResource(ds);
        const services = this.getServicesForResource(ds);
        const routes = this.getRoutesForServices(services);
        const pods = this.getPodsForResource(ds);
        const alerts = combinePodAlerts(pods);
        const obj = {
          ...ds,
          apiVersion: apiVersionForModel(DaemonSetModel),
          kind: DaemonSetModel.kind,
        };
        const status = <ProjectStatusItemReadiness
          desired={ds.status.desiredNumberScheduled}
          ready={ds.status.currentNumberScheduled}
          resource={obj}
        />;
        return {
          alerts,
          buildConfigs,
          obj,
          pods,
          routes,
          services,
          status,
        };
      });
    }

    createDeploymentItems(): ProjectStatusItem[] {
      const {deployments} = this.props;
      return _.map(deployments.data, d => {
        const alerts = getResourcePausedAlert(d);
        const replicaSets = this.getReplicaSetsForResource(d);
        const current = _.head(replicaSets);
        const previous = _.nth(replicaSets, 1);
        const isRollingOut = !!current && !!previous;
        const buildConfigs = this.getBuildConfigsForResource(d);
        const services = this.getServicesForResource(d);
        const routes = this.getRoutesForServices(services);
        const obj = {
          ...d,
          apiVersion: apiVersionForModel(DeploymentModel),
          kind: DeploymentModel.kind,
        };
        // TODO: Show pod status for previous and next revisions.
        const status = isRollingOut
          ? <span className="text-muted">Rollout in progress...</span>
          : <ProjectStatusItemReadiness
            desired={d.spec.replicas}
            ready={d.status.replicas}
            resource={current ? current.obj : obj}
          />;

        return {
          alerts,
          buildConfigs,
          current,
          isRollingOut,
          obj,
          previous,
          routes,
          services,
          status,
        };
      });
    }

    createDeploymentConfigItems(): ProjectStatusItem[] {
      const {deploymentConfigs} = this.props;
      return _.map(deploymentConfigs.data, dc => {
        const alerts = getResourcePausedAlert(dc);
        const replicationControllers = this.getReplicationControllersForResource(dc);
        const current = _.head(replicationControllers);
        const previous = _.nth(replicationControllers, 1);
        const isRollingOut = current && previous && current.phase !== 'Cancelled' && current.phase !== 'Failed';
        const buildConfigs = this.getBuildConfigsForResource(dc);
        const services = this.getServicesForResource(dc);
        const routes = this.getRoutesForServices(services);
        const obj = {
          ...dc,
          apiVersion: apiVersionForModel(DeploymentConfigModel),
          kind: DeploymentConfigModel.kind,
        };

        // TODO: Show pod status for previous and next revisions.
        const status = isRollingOut
          ? <span className="text-muted">Rollout in progress...</span>
          : <ProjectStatusItemReadiness
            desired={dc.spec.replicas}
            ready={dc.status.replicas}
            resource={current ? current.obj : obj}
          />;
        return {
          alerts,
          buildConfigs,
          current,
          isRollingOut,
          obj,
          previous,
          routes,
          services,
          status,
        };
      });
    }

    createStatefulSetItems(): ProjectStatusItem[] {
      const {statefulSets} = this.props;
      return _.map(statefulSets.data, (ss) => {
        const buildConfigs = this.getBuildConfigsForResource(ss);
        const pods = this.getPodsForResource(ss);
        const alerts = combinePodAlerts(pods);
        const services = this.getServicesForResource(ss);
        const routes = this.getRoutesForServices(services);
        const obj = {
          ...ss,
          apiVersion: apiVersionForModel(StatefulSetModel),
          kind: StatefulSetModel.kind,
        };
        const status = <ProjectStatusItemReadiness
          desired={ss.spec.replicas}
          ready={ss.status.replicas}
          resource={obj}
        />;

        return {
          alerts,
          buildConfigs,
          obj,
          pods,
          routes,
          services,
          status,
        };
      });
    }

    createPodItems(): ProjectStatusItem[] {
      const {pods} = this.props;
      return _.reduce(pods.data, (acc, pod) => {
        const owners = _.get(pod, 'metadata.ownerReferences');
        const phase = _.get(pod, 'status.phase');
        if (!_.isEmpty(owners) || ['Succeeded', 'Failed'].includes(phase)) {
          return acc;
        }

        const obj = {
          ...pod,
          apiVersion: apiVersionForModel(PodModel),
          kind: PodModel.kind,
        };
        const alerts = getPodAlerts(pod);
        const services = this.getServicesForResource(obj);
        const routes = this.getRoutesForServices(services);
        const status = <PodStatus pod={pod} />;
        return [
          ...acc,
          {
            alerts,
            obj,
            routes,
            services,
            status,
          },
        ];
      }, []);
    }

    createProjectStatusData(): void {
      const {loaded, mock, updateItems} = this.props;

      if (!loaded) {
        return;
      }
      // keeps deleted bookmarked projects from attempting to generate data
      if (mock) {
        return;
      }

      const items = [
        ...this.createDaemonSetItems(),
        ...this.createDeploymentItems(),
        ...this.createDeploymentConfigItems(),
        ...this.createStatefulSetItems(),
        ...this.createPodItems(),
      ];

      updateItems(items);

      const filteredItems = this.filterItems(items);
      const { firstLabel, groupOptions } = this.getGroupOptionsFromLabels(filteredItems);
      const selectedGroup = ProjectStatusSpecialGroup.GROUP_BY_APPLICATION;
      const groupedItems = groupItems(filteredItems, selectedGroup);
      this.setState({
        filteredItems,
        groupedItems,
        firstLabel,
        groupOptions,
        items,
        selectedGroup,
      });
    }

    handleFilterChange = (event: any): void => {
      this.setState({filterValue: event.target.value});
    };

    handleGroupChange = (selectedGroup: string): void => {
      this.setState({selectedGroup});
    };

    clearFilter = (): void => {
      this.setState({filterValue: ''});
    };

    render() {
      const {loaded, loadError, mock, title, project = {}, selectedView} = this.props;
      const {filteredItems, groupedItems, firstLabel, groupOptions, selectedGroup} = this.state;
      return <div className="co-m-pane">
        <ProjectStatusHeading
          disabled={mock}
          firstLabel={firstLabel}
          groupOptions={groupOptions}
          handleFilterChange={this.handleFilterChange}
          handleGroupChange={this.handleGroupChange}
          selectedGroup={selectedGroup}
          selectedView={selectedView}
          title={title}
          project={project.data}
        />
        <div className="co-m-pane__body co-m-pane__body--no-top-margin">
          <StatusBox
            data={selectedView === ProjectStatusViewOption.RESOURCES ? filteredItems : project}
            label="Resources"
            loaded={loaded}
            loadError={loadError}
            EmptyMsg={ProjectStatusEmptyState}
          >
            {selectedView === ProjectStatusViewOption.RESOURCES && <ProjectStatusList groups={groupedItems} />}
            {selectedView === ProjectStatusViewOption.DASHBOARD && <ProjectStatusDashboard obj={project.data} />}
          </StatusBox>
        </div>
      </div>;
    }
  }
);

const projectStatusStateToProps = ({UI}): ProjectStatusPropsFromState => {
  const selectedUID = UI.getIn(['projectStatus', 'selectedUID']);
  const items = UI.getIn(['projectStatus', 'items']);
  const selectedItem = !!items && items.get(selectedUID);
  const selectedView = UI.getIn(['projectStatus', 'selectedView'], ProjectStatusViewOption.RESOURCES);
  return { selectedItem, selectedView };
};

const projectStatusDispatchToProps = (dispatch) => {
  return {
    dismissSidebar: () => dispatch(UIActions.dismissProjectStatusSidebar()),
  };
};

const ProjectStatus = connect<ProjectStatusPropsFromState, ProjectStatusPropsFromDispatch, ProjectStatusOwnProps>(projectStatusStateToProps, projectStatusDispatchToProps)(
  ({mock, namespace, selectedItem, selectedView, title, dismissSidebar}: ProjectStatusProps) => {
    const sidebarOpen = !_.isEmpty(selectedItem) && selectedView !== ProjectStatusViewOption.DASHBOARD;
    const className = classnames('project-status', {'project-status--sidebar-shown': sidebarOpen});
    // TODO: Update resources for native Kubernetes clusters.
    const resources = [
      {
        isList: true,
        kind: 'Build',
        namespace,
        prop: 'builds',
      },
      {
        isList: true,
        kind: 'BuildConfig',
        namespace,
        prop: 'buildConfigs',
      },
      {
        isList: true,
        kind: 'DaemonSet',
        namespace,
        prop: 'daemonSets',
      },
      {
        isList: true,
        kind: 'Deployment',
        namespace,
        prop: 'deployments',
      },
      {
        isList: true,
        kind: 'DeploymentConfig',
        namespace,
        prop: 'deploymentConfigs',
      },
      {
        isList: true,
        kind: 'Pod',
        namespace,
        prop: 'pods',
      },
      {
        isList: false,
        kind: 'Project',
        name: namespace,
        prop: 'project',
      },
      {
        isList: true,
        kind: 'ReplicaSet',
        namespace,
        prop: 'replicaSets',
      },
      {
        isList: true,
        kind: 'ReplicationController',
        namespace,
        prop: 'replicationControllers',
      },
      {
        isList: true,
        kind: 'Route',
        namespace,
        prop: 'routes',
      },
      {
        isList: true,
        kind: 'Service',
        namespace,
        prop: 'services',
      },
      {
        isList: true,
        kind: 'StatefulSet',
        namespace,
        prop: 'statefulSets',
      },
    ];

    return <div className={className}>
      <div className="project-status__main-column">
        <div className="project-status__main-column-section">
          <Firehose resources={mock ? [] : resources} forceUpdate>
            <ProjectStatusMainContent
              mock={mock}
              namespace={namespace}
              selectedItem={selectedItem}
              title={title}
            />
          </Firehose>
        </div>
      </div>
      {
        sidebarOpen &&
        <ProjectStatusSidebar
          onClickClose={dismissSidebar}
          item={selectedItem}
          kind={selectedItem.obj.kind}
        />
      }
    </div>;
  }
);

export const ProjectStatusPage = withStartGuide(
  ({match, noProjectsAvailable}: ProjectStatusPageProps & WithStartGuideProps) => {
    const namespace = _.get(match, 'params.ns');
    const title = 'Project Status';
    return <React.Fragment>
      <Helmet>
        <title>{title}</title>
      </Helmet>
      <ProjectStatus
        mock={noProjectsAvailable}
        namespace={namespace}
        title={title}
      />
    </React.Fragment>;
  }
);

type FirehoseItem = {
  data?: K8sResourceKind;
  [key: string]: any;
};

type FirehoseList = {
  data?: K8sResourceKind[];
  [key: string]: any;
};

type ProjectStatusItemAlerts = {
  [key: string]: {
    message: string;
    severity: string;
  }
};

export type ProjectStatusPodControllerItem = {
  alerts: ProjectStatusItemAlerts;
  revision: number;
  obj: K8sResourceKind;
  phase?: string;
  pods: K8sResourceKind[];
};

export type ProjectStatusBuildConfigItem = K8sResourceKind & {
  builds: K8sResourceKind[];
};

export type ProjectStatusItem = {
  alerts?: ProjectStatusItemAlerts;
  buildConfigs: ProjectStatusBuildConfigItem[];
  current?: ProjectStatusPodControllerItem;
  isRollingOut?: boolean;
  obj: K8sResourceKind;
  pods?: K8sResourceKind[];
  previous?: ProjectStatusPodControllerItem;
  routes: K8sResourceKind[];
  services: K8sResourceKind[];
  status?: React.ReactNode;
};

export type ProjectStatusGroup = {
  name: string;
  items: ProjectStatusItem[];
};

type MetricValuesByPod = {
  [podName: string]: number,
};

export type ProjectStatusMetrics = {
  cpu?: MetricValuesByPod;
  memory?: MetricValuesByPod;
};

type ProjectStatusItemReadinessProps = {
  desired: number;
  resource: K8sResourceKind;
  ready: number;
};

type ProjectStatusMainContentPropsFromState = {
  metrics: ProjectStatusMetrics;
  selectedView: ProjectStatusViewOption;
};

type ProjectStatusMainContentPropsFromDispatch = {
  updateMetrics: (metrics: ProjectStatusMetrics) => void;
  updateItems: (items: ProjectStatusItem[]) => void;
};

type ProjectStatusMainContentOwnProps = {
  builds?: FirehoseList;
  buildConfigs?: FirehoseList;
  daemonSets?: FirehoseList;
  deploymentConfigs?: FirehoseList;
  deployments?: FirehoseList;
  mock: boolean;
  loaded?: boolean;
  loadError?: any;
  namespace: string;
  pods?: FirehoseList;
  project?: FirehoseItem;
  replicationControllers?: FirehoseList;
  replicaSets?: FirehoseList;
  routes?: FirehoseList;
  services?: FirehoseList;
  selectedItem: ProjectStatusItem;
  statefulSets?: FirehoseList;
  title?: string;
};

type ProjectStatusMainContentProps = ProjectStatusMainContentPropsFromState & ProjectStatusMainContentPropsFromDispatch & ProjectStatusMainContentOwnProps;

type ProjectStatusMainContentState = {
  readonly filterValue: string;
  readonly items: any[];
  readonly filteredItems: any[];
  readonly groupedItems: any[];
  readonly firstLabel: string;
  readonly groupOptions: any;
  readonly selectedGroup: string;
};

type ProjectStatusPropsFromState = {
  selectedItem: any;
  selectedView: ProjectStatusViewOption;
};

type ProjectStatusPropsFromDispatch = {
  dismissSidebar: () => void;
};

type ProjectStatusOwnProps = {
  mock: boolean;
  namespace: string;
  title: string;
};

type ProjectStatusProps = ProjectStatusPropsFromState & ProjectStatusPropsFromDispatch & ProjectStatusOwnProps;

type ProjectStatusPageProps = {
  match: any;
};

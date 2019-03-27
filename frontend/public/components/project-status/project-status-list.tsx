/* eslint-disable no-unused-vars, no-undef */
import * as _ from 'lodash-es';
import * as classnames from 'classnames';
import * as React from 'react';
import { connect } from 'react-redux';
import { Link } from 'react-router-dom';
import { ListView } from 'patternfly-react';

import { Tooltip } from '../utils/tooltip';
import { K8sResourceKind } from '../../module/k8s';
import { UIActions } from '../../ui/ui-actions';
import {
  pluralize,
  ResourceIcon,
  resourceObjPath,
  resourcePath,
} from '../utils';

import {
  ProjectStatusGroup,
  ProjectStatusItem,
  ProjectStatusMetrics,
  ProjectStatusPodControllerItem,
} from '.';

const formatToFractionalDigits = (value: number, digits: number): string => Intl.NumberFormat(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(value);

const formatBytesAsMiB = (bytes: number): string => {
  const mib = bytes / 1024 / 1024;
  return formatToFractionalDigits(mib, 1);
};

const formatCores = (cores: number): string => formatToFractionalDigits(cores, 3);

const projectStatusTooltipStyles = Object.freeze({
  content: {
    maxWidth: '225px',
  },
  tooltip: {
    minWidth: '225px',
  },
});

const truncateMiddle = (text: string = ''): React.ReactNode => {
  const length = text.length;
  if (length < 20) {
    return text;
  }

  const begin = text.substr(0, 7);
  const end = text.substr(length - 10, length);
  return <span className="text-nowrap">{begin}&hellip;{end}</span>;
};

const ControllerLink: React.SFC<ControllerLinkProps> = ({controller}) => {
  const { obj, revision } = controller;
  const { name } = obj.metadata;
  const label = _.isFinite(revision) ? `#${revision}` : name;
  return <Link to={resourceObjPath(obj, obj.kind)} title={name}>{label}</Link>;
};

export const ComponentLabel: React.SFC<ComponentLabelProps> = ({text}) => <div className="co-component-label">{text}</div>;

const MetricsTooltip: React.SFC<MetricsTooltipProps> = ({metricLabel, byPod, children}) => {
  const sortedMetrics = _.orderBy(byPod, ['value', 'name'], ['desc', 'asc']);
  const content: any[] = _.isEmpty(sortedMetrics)
    ? [<React.Fragment key="no-metrics">No {metricLabel} metrics available.</React.Fragment>]
    : _.concat(<div key="#title">{metricLabel} Usage by Pod</div>, sortedMetrics.map(({name, formattedValue}) => (
      <div key={name} className="project-status-list__metric-tooltip">
        <div className="project-status-list__metric-tooltip-name">{truncateMiddle(name)}</div>
        <div className="project-status-list__metric-tooltip-value">{formattedValue}</div>
      </div>
    )));

  const keepLines = 6;
  // Don't remove a single line to show a "1 other" message since there's space to show the last pod in that case.
  // Make sure we always remove at least 2 lines if we truncate.
  if (content.length > (keepLines + 1)) {
    const numRemoved = content.length - keepLines;
    content.splice(keepLines, numRemoved, <div key="#removed-pods">and {numRemoved} other pods</div>);
  }

  // Disable the tooltip on mobile since a touch also opens the sidebar, which
  // immediately covers the tooltip content.
  return <Tooltip content={content} styles={projectStatusTooltipStyles} disableOnMobile>{children}</Tooltip>;
};


const Metrics: React.SFC<MetricsProps> = ({metrics, item}) => {
  const getPods = () => {
    if (item.obj.kind === 'Pod') {
      return [item.obj];
    }
    return item.current ? item.current.pods : item.pods;
  };

  if (_.isEmpty(metrics)) {
    return null;
  }

  let totalBytes = 0;
  let totalCores = 0;
  const memoryByPod = [];
  const cpuByPod = [];
  _.each(getPods(), ({ metadata: { name } }: K8sResourceKind) => {
    const bytes = _.get(metrics, ['memory', name]);
    if (_.isFinite(bytes)) {
      totalBytes += bytes;
      const formattedValue = `${formatBytesAsMiB(bytes)} MiB`;
      memoryByPod.push({ name, value: bytes, formattedValue });
    }

    const cores = _.get(metrics, ['cpu', name]);
    if (_.isFinite(cores)) {
      totalCores += cores;
      cpuByPod[name] = `${formatCores(cores)} cores`;
      const formattedValue = `${formatCores(cores)} cores`;
      cpuByPod.push({ name, value: cores, formattedValue });
    }
  });

  if (!totalBytes && !totalCores) {
    return null;
  }

  const formattedMiB = formatBytesAsMiB(totalBytes);
  const formattedCores = formatCores(totalCores);
  return <React.Fragment>
    <div className="project-status-list__detail project-status-list__detail--memory">
      <MetricsTooltip metricLabel="Memory" byPod={memoryByPod}>
        <span className="project-status-list__metric-value">{formattedMiB}</span>
        &nbsp;
        <span className="project-status-list__metric-unit">MiB</span>
      </MetricsTooltip>
    </div>
    <div className="project-status-list__detail project-status-list__detail--cpu">
      <MetricsTooltip metricLabel="CPU" byPod={cpuByPod}>
        <span className="project-status-list__metric-value">{formattedCores}</span>
        &nbsp;
        <span className="project-status-list__metric-unit">cores</span>
      </MetricsTooltip>
    </div>
  </React.Fragment>;
};

const Status: React.SFC<StatusProps> = ({item}) => {
  const {status} = item;
  return status ? <div className="project-status-list__detail project-status-list__detail--status">
    {status}
  </div> : null;
};

const iconClassBySeverity = Object.freeze({
  error: 'pficon pficon-error-circle-o text-danger',
  info: 'pficon pficon-info',
  warning: 'pficon pficon-warning-triangle-o text-warning',
});

const alertLabelBySeverity = Object.freeze({
  error: 'Error',
  info: 'Message',
  warning: 'Warning',
});

const AlertTooltip = ({alerts, severity}) => {
  const iconClass = iconClassBySeverity[severity];
  const label = alertLabelBySeverity[severity];
  const count = _.size(alerts);
  const message = _.map(alerts, 'message').join('\n');
  const content = [<span key="message" className="co-pre-wrap">{message}</span>];

  // Disable the tooltip on mobile since a touch also opens the sidebar, which
  // immediately covers the tooltip content.
  return <Tooltip content={content} styles={projectStatusTooltipStyles} disableOnMobile>
    <i className={iconClass} aria-hidden="true" /> {pluralize(count, label)}
  </Tooltip>;
};

const Alerts: React.SFC<AlertsProps> = ({item}) => {
  const currentAlerts = _.get(item, 'current.alerts', {});
  const previousAlerts = _.get(item, 'previous.alerts', {});
  const itemAlerts = _.get(item, 'alerts', {});
  const alerts ={
    ...itemAlerts,
    ...currentAlerts,
    ...previousAlerts,
  };
  if (_.isEmpty(alerts)) {
    return null;
  }

  const { error, warning, info } = _.groupBy(alerts, 'severity');
  return <div className="project-status-list__detail project-status-list__detail--alert">
    {error && <AlertTooltip severity="error" alerts={error} />}
    {warning && <AlertTooltip severity="warning" alerts={warning} />}
    {info && <AlertTooltip severity="info" alerts={info} />}
  </div>;
};

const itemStateToProps = ({UI}): ItemPropsFromState => ({
  metrics: UI.getIn(['ProjectStatus', 'metrics']),
  selectedUID: UI.getIn(['ProjectStatus', 'selectedUID']),
});

const itemDispatchToProps = (dispatch): ItemPropsFromDispatch => ({
  selectItem: (uid) => dispatch(UIActions.selectProjectStatusItem(uid)),
  dismissDetails: () => dispatch(UIActions.dismissProjectStatusDetails()),
});

const Item = connect<ItemPropsFromState, ItemPropsFromDispatch, ItemOwnProps>(itemStateToProps, itemDispatchToProps)(
  ({dismissDetails, item, metrics, selectItem, selectedUID}: ItemProps) => {
    const {current, obj} = item;
    const {namespace, name, uid} = obj.metadata;
    const {kind} = obj;
    // Hide metrics when a selection is active.
    const hasSelection = !!selectedUID;
    const isSelected = uid === selectedUID;
    const className = classnames(`project-status-list__item project-status-list__item--${kind}`, {'project-status-list__item--selected': isSelected});
    const heading = <h3 className="project-status-list__item-heading">
      <span className="co-resource-link co-resource-link-truncate">
        <ResourceIcon kind={kind} />
        <Link to={resourcePath(kind, name, namespace)} className="co-resource-link__resource-name">
          {name}
        </Link>
        {current && <React.Fragment>,&nbsp;<ControllerLink controller={current} /></React.Fragment>}
      </span>
    </h3>;

    const additionalInfo = <div key={uid} className="project-status-list__additional-info">
      <Alerts item={item} />
      {!hasSelection && <Metrics item={item} metrics={metrics} />}
      <Status item={item} />
    </div>;

    const onClick = (e: Event) => {
      // Don't toggle details if clicking on a link inside the row.
      const target = e.target as HTMLElement;
      if (target.tagName.toLowerCase() === 'a') {
        return;
      }

      if (isSelected) {
        dismissDetails();
      } else {
        selectItem(uid);
      }
    };

    return <ListView.Item
      onClick={onClick}
      className={className}
      heading={heading}
      additionalInfo={[additionalInfo]}
      data-name={name}
      data-kind={kind}
      data-test-selector="project-status-list-item"
    />;
  }
);

const List: React.SFC<ListProps> = ({items}) => {
  const listItems = _.map(items, (item) =>
    <Item
      item={item}
      key={item.obj.metadata.uid}
    />
  );
  return <ListView className="project-status-list__grouped-list">
    {listItems}
  </ListView>;
};

const Group: React.SFC<GroupProps> = ({heading, items}) =>
  <div className="project-status-list__group">
    <h2 className="project-status-list__group-heading">{heading}</h2>
    <List
      items={items}
    />
  </div>;

export const ProjectStatusList: React.SFC<ProjectStatusListProps> = ({groups}) =>
  <div className="project-status-list" data-test-selector="project-status-list">
    {_.map(groups, ({name, items}, index) =>
      <Group
        key={name || `_${index}`}
        heading={name}
        items={items}
      />
    )}
  </div>;

type ControllerLinkProps = {
  controller: ProjectStatusPodControllerItem;
};

type ComponentLabelProps = {
  text: string;
};

type MetricsTooltipProps = {
  metricLabel: string;
  byPod: {
    formattedValue: string
    name: string;
    value: number;
  }[];
};

type MetricsProps = {
  metrics: any;
  item: ProjectStatusItem;
};

type StatusProps = {
  item: ProjectStatusItem;
};

type AlertsProps = {
  item: ProjectStatusItem;
};

type ItemPropsFromState = {
  metrics: ProjectStatusMetrics;
  selectedUID: string;
};

type ItemPropsFromDispatch = {
  selectItem: (uid: string) => void;
  dismissDetails: () => void;
};

type ItemOwnProps= {
  item: ProjectStatusItem;
};

type ItemProps = ItemOwnProps & ItemPropsFromDispatch & ItemPropsFromState;

type ListProps = {
  items: ProjectStatusItem[];
};

type GroupProps = {
  heading: string;
  items: ProjectStatusItem[];
};

type ProjectStatusListProps = {
  groups: ProjectStatusGroup[];
};

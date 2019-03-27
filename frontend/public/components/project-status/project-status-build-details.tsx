/* eslint-disable no-unused-vars, no-undef */
import * as _ from 'lodash-es';
import * as React from 'react';
import { Button, ListGroup } from 'patternfly-react';

import { BuildPhaseIcon, BuildNumberLink, BuildLogLink } from '../build';
import { errorModal } from '../modals/error-modal';
import { fromNow } from '../utils/datetime';
import { K8sResourceKind } from '../../module/k8s';
import {
  BuildPhase,
  startBuild,
} from '../../module/k8s/builds';
import {
  ResourceLink,
  SidebarSectionHeading,
} from '../utils';

import { ProjectStatusBuildConfigItem, ProjectStatusItem } from '.';

const conjugateBuildPhase = (phase: BuildPhase): string => {
  switch (phase) {
    case BuildPhase.Cancelled:
      return 'was cancelled';
    case BuildPhase.Error:
      return 'encountered an error';
    case BuildPhase.Failed:
      return 'failed';
    default:
      return `is ${_.toLower(phase)}`;
  }
};

const BuildStatus = ({build}) => {
  const {status:{logSnippet, message, phase}} = build;
  const unsuccessful = [BuildPhase.Error, BuildPhase.Failed].includes(phase);
  return unsuccessful
    ? <div className="project-status-build-details__item-reason">
      <p className="project-status-build-details__status-message">{message}</p>
      {
        logSnippet && <pre className="project-status-build-details__log-snippet">{logSnippet}</pre>
      }
    </div>
    : null;
};

const BuildListItem: React.SFC<BuildListItemProps> = ({build}) => {
  const {metadata: {creationTimestamp}, status: {completionTimestamp, startTimestamp, phase}} = build;
  const lastUpdated = completionTimestamp
    || startTimestamp
    || creationTimestamp;

  return <li className="list-group-item project-status-build-details__item">
    <div className="project-status-build-details__item-title">
      <div>
        <BuildPhaseIcon build={build} />
        &nbsp;
        Build
        &nbsp;
        <BuildNumberLink build={build} />
        &nbsp;
        {conjugateBuildPhase(phase)}
        {lastUpdated && <span className="text-muted">&nbsp;({fromNow(lastUpdated)})</span>}
      </div>
      <div>
        <BuildLogLink build={build} />
      </div>
    </div>
    <BuildStatus build={build} />
  </li>;
};

const BuildList: React.SFC<BuildListProps> = ({buildConfig}) => {
  const {metadata: {name, namespace}, builds} = buildConfig;
  const onClick = () => {
    startBuild(buildConfig).catch(err => {
      const error = err.message;
      errorModal({error});
    });
  };
  return <ListGroup className="project-status-build-details__list" componentClass="ul">
    <li className="list-group-item project-status-build-details__item">
      <div className="project-status-build-details__item-title">
        <div>
          <ResourceLink
            inline
            kind="BuildConfig"
            name={name}
            namespace={namespace}
          />
        </div>
        <div>
          <Button bsStyle="default" bsSize="xs" onClick={onClick}>Start Build</Button>
        </div>
      </div>
    </li>
    {
      _.isEmpty(builds)
        ? <li className="list-group-item"><span className="text-muted">No Builds found for this Build Config.</span></li>
        : _.map(builds, build => <BuildListItem key={build.metadata.uid} build={build} />)
    }
  </ListGroup>;
};

export const ProjectStatusBuildDetails: React.SFC<ProjectStatusBuildDetailsProps> = ({item}) => <div className="project-status-build-details">
  <SidebarSectionHeading text="Builds" />
  {
    _.isEmpty(item.buildConfigs)
      ? <span className="text-muted">No Build Configs found for this resource.</span>
      : _.map(item.buildConfigs, buildConfig => <BuildList key={buildConfig.metadata.uid} buildConfig={buildConfig} />)
  }
</div>;

type BuildListItemProps = {
  build: K8sResourceKind;
};

type BuildListProps = {
  buildConfig: ProjectStatusBuildConfigItem;
};

type ProjectStatusBuildDetailsProps = {
  item: ProjectStatusItem;
};

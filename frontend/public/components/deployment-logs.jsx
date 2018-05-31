import * as _ from 'lodash-es';
import * as React from 'react';

import { ResourceLog } from './utils';

export class DeploymentLogs extends React.Component {
  constructor(props) {
    super(props);
  }

  // TODO figure out eof conditions for a DeploymentConfig, if they exist

  render() {
    const namespace = _.get(this.props.obj, 'metadata.namespace');
    const deploymentConfigName = _.get(this.props.obj, 'metadata.name');
    return <div className="co-m-pane__body">
      <ResourceLog
        eof={false}
        kind="DeploymentConfig"
        namespace={namespace}
        resourceName={deploymentConfigName} />
    </div>;
  }
}

import * as React from 'react';
import { Form, ContentVariants } from '@patternfly/react-core';
import { useParams } from 'react-router-dom-v5-compat';
import { resourcePathFromModel } from '@console/internal/components/utils';
import { useK8sWatchResource } from '@console/internal/components/utils/k8s-watch-hook';
import { history } from '@console/internal/components/utils/router';
import { k8sCreate, NodeKind, referenceForModel } from '@console/internal/module/k8s';
import { ClusterServiceVersionModel } from '@console/operator-lifecycle-manager';
import { usePromiseHandler } from '@console/shared/src/hooks/promise-handler';
import { LocalVolumeSetModel } from '../../models';
import { nodeResource } from '../../resources';
import { hasNoTaints, getNodesByHostNameLabel } from '../../utils';
import { FormFooter } from '../common/form-footer';
import { LocalVolumeSetBody } from './body';
import { LocalVolumeSetHeader } from './header';
import { getLocalVolumeSetRequestData } from './request';
import { reducer, initialState } from './state';
import './create-local-volume-set.scss';

const CreateLocalVolumeSet: React.FC = () => {
  const { appName, ns } = useParams();
  const resourcePath = resourcePathFromModel(ClusterServiceVersionModel, appName, ns);

  const [state, dispatch] = React.useReducer(reducer, initialState);
  const [nodesData, nodesLoaded, nodesLoadError] = useK8sWatchResource<NodeKind[]>(nodeResource);
  const [handlePromise, inProgress, errorMessage] = usePromiseHandler();

  React.useEffect(() => {
    if (nodesLoaded && !nodesLoadError && nodesData?.length !== 0) {
      const filteredNodes: NodeKind[] = nodesData.filter(hasNoTaints);
      dispatch({ type: 'setLvsAllNodes', value: filteredNodes });
    }
  }, [nodesData, nodesLoadError, nodesLoaded]);

  const onSubmit = async (event: React.FormEvent<EventTarget>) => {
    event.preventDefault();

    const lvsNodes = state.lvsIsSelectNodes ? state.lvsSelectNodes : state.lvsAllNodes;
    const nodesByHostNameLabel = getNodesByHostNameLabel(lvsNodes);
    const requestData = getLocalVolumeSetRequestData(state, nodesByHostNameLabel, ns);

    handlePromise(k8sCreate(LocalVolumeSetModel, requestData))
      .then(() => {
        history.push(
          `/k8s/ns/${ns}/clusterserviceversions/${appName}/${referenceForModel(
            LocalVolumeSetModel,
          )}/${state.volumeSetName}`,
        );
      })
      .catch(() => {});
  };

  const getDisabledCondition = () => {
    const nodes = state.lvsIsSelectNodes ? state.lvsSelectNodes : state.lvsAllNodes;
    if (!state.volumeSetName.trim().length) return true;
    if (nodes.length < 1) return true;
    if (!state.isValidDiskSize) return true;
    return false;
  };

  return (
    <>
      <div className="co-create-operand__header">
        <LocalVolumeSetHeader
          variant={ContentVariants.h1}
          className="co-create-operand__header-text"
        />
      </div>
      <Form
        noValidate={false}
        className="co-m-pane__body lso-form-body__node-list pf-v6-u-w-75"
        onSubmit={onSubmit}
      >
        <LocalVolumeSetBody dispatch={dispatch} state={state} />
        <FormFooter
          errorMessage={errorMessage}
          inProgress={inProgress}
          cancelUrl={resourcePath}
          disableNext={getDisabledCondition()}
        />
      </Form>
    </>
  );
};

export default CreateLocalVolumeSet;

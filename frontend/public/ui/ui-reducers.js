import * as _ from 'lodash-es';
import { Map as ImmutableMap } from 'immutable';

import { types } from './ui-actions';
import { ALL_NAMESPACES_KEY, LAST_NAMESPACE_NAME_LOCAL_STORAGE_KEY, NAMESPACE_LOCAL_STORAGE_KEY } from '../const';
import { AlertStates, isSilenced, SilenceStates } from '../monitoring';
import { legalNamePattern, getNamespace } from '../components/utils/link';

export default (state, action) => {
  if (!state) {
    const { pathname } = window.location;

    let activeNamespace = getNamespace(pathname);
    if (!activeNamespace) {
      const parsedFavorite = localStorage.getItem(NAMESPACE_LOCAL_STORAGE_KEY);
      if (_.isString(parsedFavorite) && (parsedFavorite.match(legalNamePattern) || parsedFavorite === ALL_NAMESPACES_KEY)) {
        activeNamespace = parsedFavorite;
      } else {
        activeNamespace = localStorage.getItem(LAST_NAMESPACE_NAME_LOCAL_STORAGE_KEY);
      }
    }

    return ImmutableMap({
      activeNavSectionId: 'workloads',
      location: pathname,
      activeNamespace: activeNamespace || 'default',
      createProjectMessage: '',
      projectStatus: new ImmutableMap({
        metrics: {},
        items: new ImmutableMap({}),
        selectedSidebarTab: '',
        selectedUID: '',
        selectedView: 'resources',
      }),
      user: {},
      clusterID: '',
    });
  }

  switch (action.type) {
    case types.setActiveNamespace:
      if (!action.value) {
        // eslint-disable-next-line no-console
        console.warn('setActiveNamespace: Not setting to falsy!');
        return state;
      }
      return state.set('activeNamespace', action.value);

    case types.setCurrentLocation: {
      state = state.set('location', action.location);
      const ns = getNamespace(action.location);
      if (_.isUndefined(ns)) {
        return state;
      }
      return state.set('activeNamespace', ns);
    }
    case types.startImpersonate:
      return state.set('impersonate', {kind: action.kind, name: action.name, subprotocols: action.subprotocols});

    case types.stopImpersonate:
      return state.delete('impersonate');

    case types.sortList:
      return state.mergeIn(['listSorts', action.listId], _.pick(action, ['field', 'func', 'orderBy']));

    case types.setCreateProjectMessage:
      return state.set('createProjectMessage', action.message);

    case types.setUser:
      return state.set('user', action.user);

    case types.setClusterID:
      return state.set('clusterID', action.clusterID);

    case types.setMonitoringData: {
      const alerts = action.key === 'alerts' ? action.data : state.getIn(['monitoring', 'alerts']);
      const firingAlerts = _.filter(_.get(alerts, 'data'), a => [AlertStates.Firing, AlertStates.Silenced].includes(a.state));
      const silences = action.key === 'silences' ? action.data : state.getIn(['monitoring', 'silences']);

      // For each Alert, store a list of the Silences that are silencing it and set its state to show it is silenced
      _.each(firingAlerts, a => {
        a.silencedBy = _.filter(_.get(silences, 'data'), s => _.get(s, 'status.state') === SilenceStates.Active && isSilenced(a, s));
        if (a.silencedBy.length) {
          a.state = AlertStates.Silenced;
          // Also set the state of Alerts in `rule.alerts`
          _.each(a.rule.alerts, ruleAlert => {
            if (_.some(a.silencedBy, s => isSilenced(ruleAlert, s))) {
              ruleAlert.state = AlertStates.Silenced;
            }
          });
        }
      });
      state = state.setIn(['monitoring', 'alerts'], alerts);

      // For each Silence, store a list of the Alerts it is silencing
      _.each(_.get(silences, 'data'), s => {
        s.firingAlerts = _.filter(firingAlerts, a => isSilenced(a, s));
      });
      return state.setIn(['monitoring', 'silences'], silences);
    }
    case types.selectProjectStatusView:
      return state.setIn(['projectStatus', 'selectedView'], action.view);

    case types.selectProjectStatusItem:
      return state.setIn(['projectStatus', 'selectedUID'], action.uid);

    case types.selectProjectStatusSidebarTab:
      return state.setIn(['projectStatus', 'selectedSidebarTab'], action.tab);

    case types.dismissProjectStatusSidebar:
      return state.mergeIn(['projectStatus'], {selectedUID: '', selectedDetailsTab: ''});

    case types.updateProjectStatusMetrics:
      return state.setIn(['projectStatus', 'metrics'], action.metrics);

    case types.updateProjectStatusItems: {
      const newItems = new ImmutableMap(_.keyBy(action.items, 'obj.metadata.uid'));
      return state.setIn(['projectStatus', 'items'], newItems);
    }

    default:
      break;
  }
  return state;
};

export const clusterIDStateToProps = ({UI}) => {
  return {clusterID: UI.get('clusterID')};
};

export const createProjectMessageStateToProps = ({UI}) => {
  return {createProjectMessage: UI.get('createProjectMessage')};
};

export const userStateToProps = ({UI}) => {
  return {user: UI.get('user')};
};

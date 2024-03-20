import { action, ActionType as Action } from 'typesafe-actions';
import { UserInfo } from '../../../extensions';

export enum ActionType {
  SetUser = 'setUser',
  BeginImpersonate = 'beginImpersonate',
  EndImpersonate = 'endImpersonate',
  SetActiveCluster = 'setActiveCluster',
  SetAdmissionWebhookWarning = 'setAdmissionWebhookWarning',
  ClearAdmissionWebhookWarning = 'clearAdmissionWebhookWarning',
}

export const setUser = (userInfo: UserInfo) => action(ActionType.SetUser, { userInfo });
export const beginImpersonate = (kind: string, name: string, subprotocols: string[]) =>
  action(ActionType.BeginImpersonate, { kind, name, subprotocols });
export const endImpersonate = () => action(ActionType.EndImpersonate);
export const setAdmissionWebhookWarning = (warning: string, kind: string, name: string) =>
  action(ActionType.SetAdmissionWebhookWarning, { warning, kind, name });
export const clearAdmissionWebhookWarning = () =>
  action(ActionType.ClearAdmissionWebhookWarning, null);
const coreActions = {
  setUser,
  beginImpersonate,
  endImpersonate,
  setAdmissionWebhookWarning,
  clearAdmissionWebhookWarning,
};

export type CoreAction = Action<typeof coreActions>;

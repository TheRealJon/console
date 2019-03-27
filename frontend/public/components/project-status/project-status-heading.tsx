/* eslint-disable no-unused-vars, no-undef */
import * as _ from 'lodash-es';
import * as classnames from 'classnames';
import * as React from 'react';
import { connect } from 'react-redux';
import { Toolbar } from 'patternfly-react';

import { UIActions } from '../../ui/ui-actions';
import { ProjectModel } from '../../models';
import { K8sResourceKind } from '../../module/k8s';
import { TextFilter } from '../factory';
import { Dropdown, ActionsMenu, KebabAction } from '../utils';
import { ProjectStatusViewOption } from './constants';
import { projectStatusMenuActions } from './project-status-dashboard';

const stateToProps = ({UI}): PropsFromState => {
  const selectedView = UI.getIn(['projectStatus', 'selectedView']);
  return { selectedView };
};

const dispatchToProps = (dispatch): PropsFromDispatch => ({
  selectView: (view: ProjectStatusViewOption) => dispatch(UIActions.selectProjectStatusView(view)),
});

export const ProjectStatusHeading = connect<PropsFromState, PropsFromDispatch, OwnProps>(stateToProps, dispatchToProps)(
  ({disabled, firstLabel = '', groupOptions, handleFilterChange = _.noop, handleGroupChange = _.noop, selectedGroup = '', selectView, selectedView, title, project}: ProjectStatusHeadingProps) => (
    <div className={classnames('co-m-nav-title co-m-nav-title--project-status', { 'project-status-filter-group': selectedView === ProjectStatusViewOption.RESOURCES })}>
      {
        title &&
        <h1 className="co-m-pane__heading co-m-pane__heading--project-status">
          <div className="co-m-pane__name co-m-pane__name--project-status">{title}</div>
        </h1>
      }
      {!_.isEmpty(project) && <div className={classnames('project-status-view-selector', {'selected-view__resources': selectedView === ProjectStatusViewOption.RESOURCES })}>
        <div className="form-group btn-group">
          <button
            type="button"
            className={classnames('btn btn-default', { 'btn-primary': selectedView === ProjectStatusViewOption.RESOURCES })}
            aria-label="Resources"
            title="Resources"
            disabled={disabled}
            onClick={() => selectView(ProjectStatusViewOption.RESOURCES)}
          >
            <i className="fa fa-list-ul" aria-hidden="true" />
            Resources
          </button>
          <button
            type="button"
            className={classnames('btn btn-default', { 'btn-primary': selectedView === ProjectStatusViewOption.DASHBOARD })}
            aria-label="Dashboard"
            title="Dashboard"
            disabled={disabled}
            onClick={() => selectView(ProjectStatusViewOption.DASHBOARD)}
          >
            <i className="fa fa-dashboard" aria-hidden="true" />
            Dashboard
          </button>
        </div>
        <Toolbar className="project-status-toolbar" preventSubmit>
          <Toolbar.RightContent>
            {selectedView === ProjectStatusViewOption.RESOURCES && <React.Fragment>
              <div className="form-group project-status-toolbar__form-group">
                <Dropdown
                  className="project-status-toolbar__dropdown"
                  menuClassName="dropdown-menu--text-wrap"
                  items={groupOptions}
                  onChange={handleGroupChange}
                  titlePrefix="Group by"
                  title={groupOptions[selectedGroup]}
                  spacerBefore={new Set([firstLabel])}
                  headerBefore={{[firstLabel]: 'Label'}}
                />
              </div>
              <div className="form-group project-status-toolbar__form-group">
                <div className="project-status-toolbar__text-filter">
                  <TextFilter
                    autoFocus={!disabled}
                    defaultValue={''}
                    label="by name"
                    onChange={handleFilterChange}
                  />
                </div>
              </div>
            </React.Fragment>}
            {selectedView === ProjectStatusViewOption.DASHBOARD && !_.isEmpty(project) && <div className="form-group">
              <ActionsMenu actions={projectStatusMenuActions.map((a: KebabAction) => a(ProjectModel, project))} />
            </div>}
          </Toolbar.RightContent>
        </Toolbar>
      </div>}
    </div>
  )
);

type PropsFromState = {
  selectedView: ProjectStatusViewOption;
};

type PropsFromDispatch = {
  selectView: (view: ProjectStatusViewOption) => void;
};

type OwnProps = {
  disabled?: boolean;
  firstLabel?: string;
  groupOptions?: any;
  handleFilterChange?: (event: any) => void;
  handleGroupChange?: (selectedLabel: string) => void;
  selectedGroup?: string;
  selectedView?: string;
  title: string;
  project: K8sResourceKind;
};

type ProjectStatusHeadingProps = PropsFromState & PropsFromDispatch & OwnProps;

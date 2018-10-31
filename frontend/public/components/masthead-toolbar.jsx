import * as React from 'react';
import * as _ from 'lodash-es';

import { FLAGS, connectToFlags, flagPending } from '../features';
import { authSvc } from '../module/auth';
import { coFetchJSON } from '../co-fetch';
import { history } from './utils';
import { openshiftHelpBase } from './utils/documentation';

import { Button, Dropdown, DropdownToggle, DropdownItem, KebabToggle, Toolbar, ToolbarGroup, ToolbarItem } from '@patternfly/react-core';
import { ArrowCircleUpIcon, QuestionCircleIcon } from '@patternfly/react-icons';
import { AboutModal } from './about-modal';

class MastheadToolbar_ extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      isUserDropdownOpen: false,
      isKebabDropdownOpen: false,
      username: null,
      showAboutModal: false,
    };

    this._updateUser = this._updateUser.bind(this);
    this._onUserDropdownToggle = this._onUserDropdownToggle.bind(this);
    this._onUserDropdownSelect = this._onUserDropdownSelect.bind(this);
    this._onKebabDropdownToggle = this._onKebabDropdownToggle.bind(this);
    this._onKebabDropdownSelect = this._onKebabDropdownSelect.bind(this);
    this._renderMenu = this._renderMenu.bind(this);
    this._onClusterUpdatesAvailable = this._onClusterUpdatesAvailable.bind(this);
    this._onHelpDropdownSelect = this._onHelpDropdownSelect.bind(this);
    this._onHelpDropdownToggle = this._onHelpDropdownToggle.bind(this);
    this._onAboutModal = this._onAboutModal.bind(this);
    this._closeAboutModal = this._closeAboutModal.bind(this);
  }

  componentDidMount() {
    this._updateUser();
  }

  componentDidUpdate(prevProps) {
    if (this.props.flags !== prevProps.flags) {
      this._updateUser();
    }
  }

  _updateUser() {
    const { flags } = this.props;

    if (flags[FLAGS.OPENSHIFT]) {
      coFetchJSON('api/kubernetes/apis/user.openshift.io/v1/users/~')
        .then(user => {
          this.setState({ username: _.get(user, 'fullName') || user.metadata.name });
        })
        .catch(() => {
          this.setState({ username: null });
        });
    } else {
      this.setState({ username: authSvc.userID() ? authSvc.name() : null });
    }
  }

  _onUserDropdownToggle(isUserDropdownOpen) {
    this.setState({
      isUserDropdownOpen,
    });
  }

  _onUserDropdownSelect() {
    this.setState({
      isUserDropdownOpen: !this.state.isUserDropdownOpen,
    });
  }

  _onKebabDropdownToggle(isKebabDropdownOpen) {
    this.setState({
      isKebabDropdownOpen,
    });
  }

  _onKebabDropdownSelect() {
    this.setState({
      isKebabDropdownOpen: !this.state.isKebabDropdownOpen,
    });
  }

  _onClusterUpdatesAvailable() {
    history.push('/settings/cluster');
  }

  _onHelpDropdownSelect() {
    this.setState({
      isHelpDropdownOpen: !this.state.isHelpDropdownOpen,
    });
  }

  _onHelpDropdownToggle(isHelpDropdownOpen) {
    this.setState({
      isHelpDropdownOpen,
    });
  }

  _onAboutModal(e) {
    e.preventDefault();
    this.setState({ showAboutModal: true });
  }

  _closeAboutModal() {
    this.setState({ showAboutModal: false });
  }

  _onDocumentation(e) {
    e.preventDefault();
    window.open(openshiftHelpBase, '_blank').opener = null;
  }

  _renderMenu(mobile) {
    const { flags } = this.props;

    if (flagPending(flags[FLAGS.OPENSHIFT]) || flagPending(flags[FLAGS.AUTH_ENABLED])) {
      return null;
    }

    const actions = [];
    if (flags[FLAGS.AUTH_ENABLED]) {
      const logout = e => {
        e.preventDefault();
        if (flags[FLAGS.OPENSHIFT]) {
          authSvc.deleteOpenShiftToken().then(() => authSvc.logout());
        } else {
          authSvc.logout();
        }
      };
      actions.push({
        label: 'Logout',
        callback: logout,
      });
    }

    if (mobile) {
      actions.push({
        label: 'Documentation',
        callback: this._onDocumentation,
      });
      actions.push({
        label: 'About',
        callback: this._onAboutModal,
      });
    }

    const { isUserDropdownOpen, isKebabDropdownOpen, username } = this.state;

    if (!username) {
      return null;
    }

    if (mobile) {
      if (_.isEmpty(actions)) {
        return null; //do not render kebab if we have no actions
      }
      return (
        <Dropdown
          isPlain
          position="right"
          onSelect={this._onKebabDropdownSelect}
          toggle={<KebabToggle onToggle={this._onKebabDropdownToggle} />}
          isOpen={isKebabDropdownOpen}
          dropdownItems={actions.map((action, i) => {
            return (
              <DropdownItem key={i} onClick={action.callback}>
                {action.label}
              </DropdownItem>
            );
          })}
        />
      );
    }
    if (_.isEmpty(actions)) {
      return <div className="co-username">{username}</div>;
    }
    return (
      <Dropdown
        isPlain
        position="right"
        onSelect={this._onUserDropdownSelect}
        isOpen={isUserDropdownOpen}
        toggle={<DropdownToggle onToggle={this._onUserDropdownToggle}>{username}</DropdownToggle>}
        dropdownItems={actions.map((action, i) => {
          return (
            <DropdownItem key={i} onClick={action.callback}>
              {action.label}
            </DropdownItem>
          );
        })}
      />
    );
  }

  render() {
    const { isHelpDropdownOpen, showAboutModal } = this.state;
    const { flags } = this.props;
    return (
      <React.Fragment>
        <Toolbar>
          <ToolbarGroup className="pf-u-sr-only pf-u-visible-on-md">
            {/* desktop -- updates button */}
            {flags[FLAGS.CLUSTER_UPDATES_AVAILABLE] && <ToolbarItem>
              <Button variant="plain" aria-label="Cluster Updates Available" onClick={this._onClusterUpdatesAvailable}>
                <ArrowCircleUpIcon />
              </Button>
            </ToolbarItem>}
            {/* desktop -- help dropdown [documentation, about] */}
            <ToolbarItem>
              <Dropdown
                isPlain
                onSelect={this._onHelpDropdownSelect}
                toggle={
                  <DropdownToggle aria-label="Help" iconComponent={null} onToggle={this._onHelpDropdownToggle}>
                    <QuestionCircleIcon />
                  </DropdownToggle>
                }
                isOpen={isHelpDropdownOpen}
                dropdownItems={[
                  <DropdownItem key="documentation" onClick={this._onDocumentation}>
                    Documentation
                  </DropdownItem>,
                  <DropdownItem key="about" onClick={this._onAboutModal}>
                    About
                  </DropdownItem>,
                ]}
              />
            </ToolbarItem>
          </ToolbarGroup>
          <ToolbarGroup >
            {/* mobile -- kebab dropdown [documentation, about, (logout)] */}
            <ToolbarItem className="pf-u-hidden-on-md pf-u-mr-0">{this._renderMenu(true)}</ToolbarItem>
            {/* desktop -- (user dropdown [logout]) */}
            <ToolbarItem className="pf-u-sr-only pf-u-visible-on-md">{this._renderMenu(false)}</ToolbarItem>
          </ToolbarGroup>
        </Toolbar>
        {showAboutModal && <AboutModal isOpen={showAboutModal} closeAboutModal={this._closeAboutModal} />}
      </React.Fragment>
    );
  }
}

export const MastheadToolbar = connectToFlags(FLAGS.AUTH_ENABLED, FLAGS.OPENSHIFT, FLAGS.CLUSTER_UPDATES_AVAILABLE)(MastheadToolbar_);

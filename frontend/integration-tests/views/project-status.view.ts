import { $, $$, browser, ExpectedConditions as until } from 'protractor';

export const projectStatusList = $('[data-test-selector="project-status-list"]');
const projectStatusListItemSelector = '[data-test-selector="project-status-list-item"]';
export const projectStatusListItems = $$(projectStatusListItemSelector);
export const detailsSidebar = $('[data-test-selector="project-status-sidebar"]');
export const detailsSidebarHeading = $('[data-test-selector="project-status-sidebar-heading"]');

export const itemsArePresent = () => {
  return browser.wait(until.presenceOf($(projectStatusListItemSelector)));
};

export const getProjectStatusListItemsOfKind = (kindModel) => {
  return $$(`[data-test-selector="project-status-list-item"][data-kind="${kindModel.kind}"]`);
};

export const getProjectStatusListItem = (kindModel, name) => {
  return $(`[data-test-selector="project-status-list-item"][data-kind="${kindModel.kind}"][data-name="${name}"]`);
};

export const sidebarIsVisible = () => {
  return browser.wait(until.visibilityOf(detailsSidebar));
};

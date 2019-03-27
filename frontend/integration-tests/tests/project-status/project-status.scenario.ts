import { browser, ExpectedConditions as until } from 'protractor';
import { Set as ImmutableSet } from 'immutable';

import { appHost, testName, checkErrors, checkLogs } from '../../protractor.conf';
import * as projectStatusView from '../../views/project-status.view';
import * as crudView from '../../views/crud.view';
import { DeploymentModel, StatefulSetModel, DeploymentConfigModel, DaemonSetModel } from '../../../public/models';

const projectStatusResources = ImmutableSet([
  DaemonSetModel,
  DeploymentModel,
  DeploymentConfigModel,
  StatefulSetModel,
]);

describe('Visiting Status page', () => {
  afterEach(() => {
    checkErrors();
    checkLogs();
  });

  beforeAll(async() => {
    await browser.get(`${appHost}/status/ns/${testName}`);
    await crudView.isLoaded();
  });

  projectStatusResources.forEach((kindModel) => {
    describe(kindModel.labelPlural, () => {
      const resourceName = `${testName}-${kindModel.kind.toLowerCase()}`;
      beforeAll(async()=>{
        await crudView.createNamespacedTestResource(kindModel, resourceName);
      });

      it(`displays a ${kindModel.id} in the project status list`, async() => {
        await browser.wait(until.presenceOf(projectStatusView.projectStatusList));
        await projectStatusView.itemsArePresent();
        expect(projectStatusView.getProjectStatusListItem(kindModel, resourceName).isPresent()).toBeTruthy();
      });

      // Disabling for now due to flake https://jira.coreos.com/browse/CONSOLE-1298
      it(`CONSOLE-1298 - shows ${kindModel.id} details sidebar when item is clicked`, async() => {
        const projectStatusListItem = projectStatusView.getProjectStatusListItem(kindModel, resourceName);
        expect(projectStatusView.detailsSidebar.isPresent()).toBeFalsy();
        await browser.wait(until.elementToBeClickable(projectStatusListItem));
        await projectStatusListItem.click();
        await projectStatusView.sidebarIsVisible();
        expect(projectStatusView.detailsSidebar.isDisplayed()).toBeTruthy();
        expect(projectStatusView.detailsSidebarHeading.getText()).toContain(resourceName);
      });
    });
  });
});

import { testName } from '../support';

describe('Project creation', () => {
  it('Visits the Console', () => {
    cy.visit('http://0.0.0.0:9000/');
  });

  it('Creates a new test project', () => {
    cy.getTestElement('yaml-create').click();
    cy.getTestElement('input-name').type(testName);
    cy.getTestElement('confirm-action').click().should('be', 'disabled');
    cy.getTestElement('page-heading').should('have.text', 'Project Status');
  });

  it('Deletes the test project', () => {
    cy.getTestElement('dashboard-button').click();
    cy.getTestElement('actions-menu-button Actions').click();
    cy.getTestElement('Delete Project').click();
    cy.getTestElement('project-name-input').type(testName);
    cy.getTestElement('confirm-action').click();
  });
});

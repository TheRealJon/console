/* eslint-disable no-undef */

// Keys for special 'group by' options
// Should not be valid label keys to avoid conflicts. https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
export enum ProjectStatusSpecialGroup {
  GROUP_BY_APPLICATION = '#GROUP_BY_APPLICATION#',
  GROUP_BY_RESOURCE = '#GROUP_BY_RESOURCE#',
}

// View options for project status page
export enum ProjectStatusViewOption {
  RESOURCES = 'resources',
  DASHBOARD = 'dashboard',
}

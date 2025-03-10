import * as React from 'react';
import { TextInputTypes, Title } from '@patternfly/react-core';
import { useTranslation } from 'react-i18next';
import { InputField } from '@console/shared';
import { PipelineWorkspaces } from '../detail-page-tabs';
import PipelineParameters from '../PipelineParameters';
import PipelineBuilderVisualization from './PipelineBuilderVisualization';
import {
  PipelineBuilderTaskResources,
  PipelineBuilderTaskGroup,
  SelectTaskCallback,
  UpdateTasksCallback,
  TaskSearchCallback,
} from './types';

import './PipelineBuilderForm.scss';

type PipelineBuilderFormEditorProps = {
  hasExistingPipeline: boolean;
  taskGroup: PipelineBuilderTaskGroup;
  taskResources: PipelineBuilderTaskResources;
  onTaskSelection: SelectTaskCallback;
  onTaskSearch: TaskSearchCallback;
  onUpdateTasks: UpdateTasksCallback;
};

const PipelineBuilderFormEditor: React.FC<PipelineBuilderFormEditorProps> = (props) => {
  const { t } = useTranslation();
  const {
    hasExistingPipeline,
    taskGroup,
    taskResources,
    onTaskSelection,
    onUpdateTasks,
    onTaskSearch,
  } = props;

  return (
    <>
      <div className="opp-pipeline-builder-form__short-section">
        <InputField
          label={t('pipelines-plugin~Name')}
          name="formData.name"
          type={TextInputTypes.text}
          isDisabled={hasExistingPipeline}
          required
        />
      </div>

      <div>
        <Title headingLevel="h2" className="pf-v6-u-mb-sm">
          {t('pipelines-plugin~Tasks')}
          <span className="pf-v6-c-form__label-required">*</span>
        </Title>
        <PipelineBuilderVisualization
          onTaskSelection={onTaskSelection}
          onUpdateTasks={onUpdateTasks}
          onTaskSearch={onTaskSearch}
          taskGroup={taskGroup}
          taskResources={taskResources}
        />
      </div>

      <div>
        <Title headingLevel="h2" className="pf-v6-u-mb-sm">
          {t('pipelines-plugin~Parameters')}
        </Title>
        <PipelineParameters
          fieldName="formData.params"
          addLabel={t('pipelines-plugin~Add parameter')}
          nameLabel={t('pipelines-plugin~Name')}
          nameFieldName="name"
          descriptionLabel={t('pipelines-plugin~Description')}
          descriptionFieldName="description"
          valueLabel={t('pipelines-plugin~Default value')}
          valueFieldName="default"
          emptyMessage={t('pipelines-plugin~No parameters are associated with this Pipeline.')}
          emptyValues={{ name: '', description: '', default: '' }}
        />
      </div>

      <div>
        <Title headingLevel="h2" className="pf-v6-u-mb-sm">
          {t('pipelines-plugin~Workspaces')}
        </Title>
        <PipelineWorkspaces
          addLabel={t('pipelines-plugin~Add workspace')}
          fieldName="formData.workspaces"
        />
      </div>
    </>
  );
};

export default PipelineBuilderFormEditor;

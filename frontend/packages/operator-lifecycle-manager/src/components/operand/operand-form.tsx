import {
  Alert,
  ActionGroup,
  Button,
  Popover,
  Accordion,
  AccordionItem,
  AccordionToggle,
  AccordionContent,
} from '@patternfly/react-core';
import { MinusCircleIcon, PlusCircleIcon } from '@patternfly/react-icons';
import { JSONSchema6, JSONSchema6TypeName } from 'json-schema';
import {
  k8sCreate,
  K8sKind,
  K8sResourceKind,
  referenceForModel,
} from '@console/internal/module/k8s';
import {
  BreadCrumbs,
  history,
  resourcePathFromModel,
  useScrollToTopOnMount,
  LinkifyExternal,
} from '@console/internal/components/utils';
import * as _ from 'lodash';
import * as React from 'react';
import * as classnames from 'classnames';
import { ClusterServiceVersionModel } from '../../models';
import { ClusterServiceVersionKind, CRDDescription, APIServiceDefinition } from '../../types';
import { ClusterServiceVersionLogo } from '../index';
import Form, {
  FieldTemplateProps,
  FormProps,
  ObjectFieldTemplateProps,
  ArrayFieldTemplateProps,
  UiSchema,
} from 'react-jsonschema-form';

const groupTypes: JSONSchema6TypeName[] = ['object', 'array'];

const DescriptionField: FormProps<any>['fields']['DescriptionField'] = ({ id, description }) =>
  description ? (
    <span id={id} className="help-block">
      <LinkifyExternal>
        <div className="co-pre-line">{description}</div>
      </LinkifyExternal>
    </span>
  ) : null;

const ErrorListTemplate = ({ errors }) => {
  return (
    <Alert
      isInline
      className="co-alert co-break-word co-alert--scrollable"
      variant="danger"
      title="Error"
    >
      <ul>
        {_.map(errors, (error) => (
          <li key={error.stack}>{error.stack}</li>
        ))}
      </ul>
    </Alert>
  );
};

const FieldLabel = ({ id, label, required }) => (
  <label className={classnames('form-label', { 'co-required': required })} htmlFor={id}>
    {label}
  </label>
);

const AtomicFieldTemplate: React.FC<FieldTemplateProps> = ({
  children,
  id,
  displayLabel,
  label,
  rawErrors,
  description,
  required,
}) => (
  <div id={id} className="form-group co-create-operand__form-group" data-test-selector={id}>
    {displayLabel && <FieldLabel label={_.startCase(label)} required={required} id={id} />}
    {children}
    {description}
    {!_.isEmpty(rawErrors) &&
      _.map(rawErrors, (error) => <span className="co-error">{error}</span>)}
  </div>
);

const FieldTemplate: React.FC<FieldTemplateProps> = (props) => {
  if (props?.uiSchema?.['ui:omit']) {
    return null;
  }
  const isGroup =
    groupTypes.includes(props?.schema?.type as JSONSchema6TypeName) ||
    props.schema.properties ||
    props.schema.items;
  return isGroup ? props.children : <AtomicFieldTemplate {...props} />;
};

const FieldSet: React.FC<FieldSetProps> = ({ children, uiSchema, id, title }) => {
  const [expanded, setExpanded] = React.useState(false);
  const showTitle = _.isNil(uiSchema['ui:showTitle']) ? true : uiSchema['ui:showTitle'];
  const onToggle = (e) => setExpanded((current) => !current);
  return showTitle && title ? (
    <div className="co-field-group">
      <AccordionItem>
        <AccordionToggle id={id} onClick={onToggle} isExpanded={expanded}>
          {_.startCase(title)}
        </AccordionToggle>
        <AccordionContent isHidden={!expanded}>{children}</AccordionContent>
      </AccordionItem>
    </div>
  ) : (
    <>{children}</>
  );
};

const ObjectFieldTemplate: React.FC<ObjectFieldTemplateProps> = ({
  idSchema,
  properties,
  title,
  uiSchema,
}) => {
  return properties.length ? (
    <div
      id={idSchema.$id}
      key={idSchema.$id}
      className="form-group co-create-operand__form-group"
      data-test-selector={idSchema.$id}
    >
      <FieldSet title={title} uiSchema={uiSchema} id={idSchema.$id}>
        {_.map(properties, (p) => p.content)}
      </FieldSet>
    </div>
  ) : null;
};

const ArrayFieldTemplate: React.FC<ArrayFieldTemplateProps> = ({
  idSchema,
  items,
  onAddClick,
  title,
  uiSchema,
}) => {
  const singularTitle = _.startCase((title || 'Item').replace(/s$/, ''));
  return (
    <FieldSet id={idSchema.$id} title={title} uiSchema={uiSchema}>
      {_.map(items, (item) => {
        return (
          <React.Fragment key={item.key}>
            {item.index > 0 && <hr />}
            {item.hasRemove && (
              <div className="row co-array-field-group__remove">
                <Button
                  type="button"
                  className="co-array-field-group__remove-btn"
                  onClick={item.onDropIndexClick(item.index)}
                  variant="link"
                >
                  <MinusCircleIcon className="co-icon-space-r" />
                  Remove {singularTitle}
                </Button>
              </div>
            )}
            {item.children}
          </React.Fragment>
        );
      })}
      <div className="row">
        <Button type="button" onClick={onAddClick} variant="link">
          <PlusCircleIcon className="co-icon-space-r" />
          Add {singularTitle}
        </Button>
      </div>
    </FieldSet>
  );
};

const buildUISchema = (apiSchema: JSONSchema6, providedAPI: ProvidedAPI): UiSchema => {
  const allDescrpitorRootNames = _.uniq(
    _.map(providedAPI?.specDescriptors || [], (descriptor) => descriptor?.path?.split('.')?.[0]),
  );
  const allSchemaRootNames = _.keys(apiSchema.properties.spec.properties);
  return {
    apiVersion: {
      'ui:omit': true,
    },
    kind: {
      'ui:omit': true,
    },
    spec: {
      'ui:showTitle': false,
      'ui:order': [
        ..._.intersection(allDescrpitorRootNames, allSchemaRootNames), // schema properties that have a matching descriptor
        '*', // Rest of schema spec properties
      ],
      // TODO Add ui schema properties that are interpreted from descriptors
      // ...specUISchemaFromDescriptors(providedAPI, apiSchema),
    },
    status: {
      'ui:omit': true,
    },
  };
};

export const OperandForm: React.FC<OperandFormProps> = ({
  activePerspective,
  clusterServiceVersion,
  data,
  namespace,
  onChange,
  onChangeEditMethod,
  openAPI,
  operandModel,
  providedAPI,
}) => {
  const submit = ({ formData }) => {
    k8sCreate(operandModel, _.set(formData, ['metadata', 'namespace'], namespace))
      .then(() =>
        history.push(
          activePerspective === 'dev'
            ? '/topology'
            : `${resourcePathFromModel(
                ClusterServiceVersionModel,
                clusterServiceVersion.metadata.name,
                namespace,
              )}/${referenceForModel(operandModel)}`,
        ),
      )
      .catch((e) => console.dir(e));
  };

  const uiSchema = React.useMemo(() => buildUISchema(openAPI, providedAPI), [openAPI, providedAPI]);
  useScrollToTopOnMount();

  return (
    <>
      <div className="co-create-operand__header">
        <div className="co-create-operand__header-buttons">
          <BreadCrumbs
            breadcrumbs={[
              {
                name: clusterServiceVersion.spec.displayName,
                path: resourcePathFromModel(
                  ClusterServiceVersionModel,
                  clusterServiceVersion.metadata.name,
                  clusterServiceVersion.metadata.namespace,
                ),
              },
              { name: `Create ${operandModel.label}`, path: window.location.pathname },
            ]}
          />
          <div style={{ marginLeft: 'auto' }}>
            <Button variant="link" onClick={() => onChangeEditMethod('yaml')}>
              Edit YAML
            </Button>
          </div>
        </div>
        <h1 className="co-create-operand__header-text">{`Create ${operandModel.label}`}</h1>
        <p className="help-block">
          Create by completing the form. Default values may be provided by the Operator authors.
        </p>
      </div>
      <div className="co-m-pane__body">
        <div className="row">
          <div className="col-md-8 col-lg-7">
            <Accordion asDefinitionList={false} className="co-create-operand__accordion">
              <Form
                onSubmit={submit}
                schema={_.omit(openAPI, ['properties.status'])}
                formData={data || {}}
                FieldTemplate={FieldTemplate}
                ErrorList={ErrorListTemplate}
                ObjectFieldTemplate={ObjectFieldTemplate}
                ArrayFieldTemplate={ArrayFieldTemplate}
                fields={{ DescriptionField }}
                onChange={({ formData }) => onChange(formData)}
                uiSchema={uiSchema}
              >
                <div style={{ paddingBottom: '30px' }}>
                  <ActionGroup className="pf-c-form">
                    <Button type="submit" variant="primary">
                      Create
                    </Button>
                    <Button onClick={history.goBack} variant="secondary">
                      Cancel
                    </Button>
                  </ActionGroup>
                </div>
              </Form>
            </Accordion>
          </div>
          <div className="col-md-4 col-lg-5">
            {clusterServiceVersion && providedAPI && (
              <div style={{ marginBottom: '30px' }}>
                <ClusterServiceVersionLogo
                  displayName={providedAPI.displayName}
                  icon={_.get(clusterServiceVersion, 'spec.icon[0]')}
                  provider={_.get(clusterServiceVersion, 'spec.provider')}
                />
                {providedAPI.description}
              </div>
            )}
            <Alert
              isInline
              className="co-alert co-break-word"
              variant="info"
              title={
                'Note: Some fields may not be represented in this form. Please select "Edit YAML" for full control of object creation.'
              }
            />
          </div>
        </div>
      </div>
    </>
  );
};

type ProvidedAPI = CRDDescription | APIServiceDefinition;
type FieldSetProps = {
  id: string;
  title?: string;
  uiSchema?: UiSchema;
};

export type OperandFormProps = {
  onChangeEditMethod?: (method: 'yaml' | 'form') => void;
  onChange?: (formData?: any) => void;
  operandModel: K8sKind;
  providedAPI: ProvidedAPI;
  openAPI?: JSONSchema6;
  clusterServiceVersion: ClusterServiceVersionKind;
  data?: K8sResourceKind;
  namespace: string;
  activePerspective: string;
};

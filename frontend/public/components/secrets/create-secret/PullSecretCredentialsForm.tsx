import * as _ from 'lodash-es';
import * as React from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@patternfly/react-core';
import { MinusCircleIcon } from '@patternfly/react-icons/dist/esm/icons/minus-circle-icon';
import { PlusCircleIcon } from '@patternfly/react-icons/dist/esm/icons/plus-circle-icon';
import {
  PullSecretCredentialEntry,
  arrayifyPullSecret,
  getPullSecretFileName,
  stringifyPullSecret,
  SecretChangeData,
  SecretStringData,
  SecretType,
} from '.';

const newImageSecretEntry = (): PullSecretCredential => ({
  address: '',
  username: '',
  password: '',
  email: '',
  auth: '',
  uid: _.uniqueId(),
});

export const PullSecretCredentialsForm: React.FC<PullSecretCredentialsFormProps> = ({
  onChange,
  stringData,
  onError,
  secretType,
}) => {
  const { t } = useTranslation();
  const pullSecretFileName = getPullSecretFileName(secretType);
  const pullSecretJSON = stringData[pullSecretFileName];
  const entries = React.useMemo(() => arrayifyPullSecret(pullSecretJSON, onError), [
    pullSecretJSON,
    onError,
  ]);

  const onEntriesChanged = React.useCallback(
    (newEntries) => {
      const newPullSecretJSON = stringifyPullSecret(newEntries, secretType);
      if (newPullSecretJSON !== pullSecretJSON) {
        onChange({ stringData: { [pullSecretFileName]: newPullSecretJSON } });
      }
    },
    [onChange, pullSecretFileName, pullSecretJSON, secretType],
  );

  const updateEntry = (updatedEntry, entryIndex: number) => {
    const updatedEntries = entries.map((entry, index) =>
      index === entryIndex ? { uid: entry.uid, ...updatedEntry } : entry,
    );
    onEntriesChanged(updatedEntries);
  };

  const removeEntry = (entryIndex: number) => {
    const updatedEntries = entries.filter((_value, index) => index !== entryIndex);
    onEntriesChanged(updatedEntries);
  };

  const addEntry = () => {
    const updatedEntries = [...entries, newImageSecretEntry()];
    onEntriesChanged(updatedEntries);
  };

  return (
    <>
      {entries.map(({ uid, address, email, username, password }, index) => (
        <div className="co-add-remove-form__entry" key={uid}>
          {entries.length > 1 && (
            <div className="co-add-remove-form__link--remove-entry">
              <Button
                onClick={() => removeEntry(index)}
                type="button"
                variant="link"
                data-test="remove-entry-button"
              >
                <MinusCircleIcon className="co-icon-space-r" />
                {t('public~Remove credentials')}
              </Button>
            </div>
          )}
          <PullSecretCredentialEntry
            id={index}
            address={address}
            email={email}
            password={password}
            username={username}
            onChange={updateEntry}
          />
        </div>
      ))}
      <Button
        className="co-create-secret-form__link--add-entry pf-m-link--align-left"
        onClick={addEntry}
        type="button"
        variant="link"
        data-test="add-credentials-button"
      >
        <PlusCircleIcon className="co-icon-space-r" />
        {t('public~Add credentials')}
      </Button>
    </>
  );
};

export type PullSecretCredential = {
  address: string;
  username: string;
  password: string;
  email: string;
  auth?: string;
  uid: string;
};

type PullSecretCredentialsFormProps = {
  onChange: (stringData: SecretChangeData) => void;
  stringData: SecretStringData;
  onError: (error: any) => void;
  secretType: SecretType;
  onFormDisable?: (disable: boolean) => void;
};
import { useState } from 'react';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { verifyInputField } from '../../../test-utils/unit-test-utils';
import type { SemverRangeInputProps } from '../SemverRangeInput';
import { SemverRangeInput } from '../SemverRangeInput';

const versions = ['2.0.0', '1.3.0', '1.2.4', '1.2.3', '0.2.4', '0.2.3', '0.3.0'];
const label = 'Version range';
const versionLabel = 'Available version for Version range';
const operatorLabel = 'Comparison operator for Version range';

const ControlledInput = ({
  value: initialValue = '',
  onChange,
  ...props
}: Partial<SemverRangeInputProps>) => {
  const [value, setValue] = useState(initialValue);
  return (
    <SemverRangeInput
      id="version"
      ariaLabel={label}
      versions={versions}
      {...props}
      value={value}
      onChange={(nextValue) => {
        setValue(nextValue);
        onChange?.(nextValue);
      }}
    />
  );
};

describe('SemverRangeInput', () => {
  it('passes arbitrary constraint text unchanged without frontend validation or truncation', async () => {
    const onChange = jest.fn();
    render(<ControlledInput onChange={onChange} />);
    const range = '>=1.2.3, !=1.3.x <2.0 || ^3 || ~4.2 || =5.0.0';
    await verifyInputField({ inputLabel: label, testValue: range });
    expect(onChange).toHaveBeenLastCalledWith(range);

    const invalidRange = '!'.repeat(65);
    await verifyInputField({ inputLabel: label, testValue: invalidRange });
    expect(onChange).toHaveBeenLastCalledWith(invalidRange);
    expect(screen.getByRole('textbox', { name: label })).not.toBeInvalid();
  });

  it('builds comparisons using every documented operator', async () => {
    const user = userEvent.setup();
    const onChange = jest.fn();
    render(<ControlledInput onChange={onChange} />);
    await user.selectOptions(screen.getByRole('combobox', { name: versionLabel }), '1.2.3');
    expect(onChange).not.toHaveBeenCalled();

    const chooseOperator = async (operator: string) => {
      await user.selectOptions(screen.getByRole('combobox', { name: operatorLabel }), operator);
      await user.click(screen.getByRole('button', { name: 'Use comparison' }));
      const expected = operator === '=' ? '1.2.3' : `${operator}1.2.3`;
      expect(onChange).toHaveBeenLastCalledWith(expected);
      expect(screen.getByRole('textbox', { name: label })).toHaveValue(expected);
    };
    await chooseOperator('=');
    await chooseOperator('!=');
    await chooseOperator('>=');
    await chooseOperator('>');
    await chooseOperator('<=');
    await chooseOperator('<');
    await chooseOperator('~');
    await chooseOperator('^');
  });

  it('composes bounded ranges, exclusions, and OR alternatives', async () => {
    const user = userEvent.setup();
    render(<ControlledInput />);
    expect(screen.getByRole('button', { name: 'Add AND condition' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Add OR alternative' })).toBeDisabled();

    const addComparison = async (operator: string, version: string, action: string) => {
      await user.selectOptions(screen.getByRole('combobox', { name: operatorLabel }), operator);
      await user.selectOptions(screen.getByRole('combobox', { name: versionLabel }), version);
      await user.click(screen.getByRole('button', { name: action }));
    };
    await addComparison('>=', '1.2.3', 'Use comparison');
    await addComparison('<', '2.0.0', 'Add AND condition');
    await addComparison('!=', '1.3.0', 'Add AND condition');
    await addComparison('^', '0.2.3', 'Add OR alternative');

    expect(screen.getByRole('textbox', { name: label })).toHaveValue(
      '>=1.2.3, <2.0.0, !=1.3.0 || ^0.2.3',
    );
  });

  it('offers major and minor wildcards derived from available versions', async () => {
    const user = userEvent.setup();
    render(<ControlledInput />);
    const select = screen.getByRole('combobox', { name: versionLabel });
    await user.selectOptions(select, '1.2.x');
    await user.click(screen.getByRole('button', { name: 'Use comparison' }));
    expect(screen.getByRole('textbox', { name: label })).toHaveValue('1.2.x');

    await user.selectOptions(select, '1.x');
    await user.selectOptions(screen.getByRole('combobox', { name: operatorLabel }), '^');
    await user.click(screen.getByRole('button', { name: 'Use comparison' }));
    expect(screen.getByRole('textbox', { name: label })).toHaveValue('^1.x');

    await user.selectOptions(select, '*');
    await user.selectOptions(screen.getByRole('combobox', { name: operatorLabel }), '=');
    await user.click(screen.getByRole('button', { name: 'Use comparison' }));
    expect(screen.getByRole('textbox', { name: label })).toHaveValue('*');
  });

  it('sorts and deduplicates available versions without changing their identifiers or source data', async () => {
    const user = userEvent.setup();
    const availableVersions = Object.freeze([
      '1.2.3+build',
      'invalid',
      '1.10.0',
      '1.2.3+build',
      '1.3.0-beta.1',
    ]);
    render(<ControlledInput versions={availableVersions} />);
    const expectedVersions = ['1.10.0', '1.3.0-beta.1', '1.2.3+build'];
    expect(
      within(screen.getByRole('group', { name: 'Exact version' }))
        .getAllByRole('option')
        .map((option) => option.textContent),
    ).toEqual(expectedVersions);

    await user.click(screen.getByRole('button', { name: 'View available versions (3)' }));
    expect(screen.getAllByRole('listitem').map((item) => item.textContent)).toEqual(
      expectedVersions,
    );
    expect(availableVersions).toEqual([
      '1.2.3+build',
      'invalid',
      '1.10.0',
      '1.2.3+build',
      '1.3.0-beta.1',
    ]);
  });

  it('allows manual entry when no versions are available', async () => {
    render(<ControlledInput versions={[]} />);
    expect(screen.getByRole('combobox', { name: versionLabel })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Use comparison' })).toBeDisabled();
    expect(
      screen.getByText('No available versions to suggest. You can still enter a version range.'),
    ).toBeVisible();
    await verifyInputField({ inputLabel: label, testValue: '>=3.0, <3.6 || !=5.X' });
  });

  it('reflects external range and version changes without emitting changes', () => {
    const onChange = jest.fn();
    const props = { id: 'version', ariaLabel: label, versions, onChange };
    const { rerender } = render(<SemverRangeInput {...props} value="^1.2.3" />);
    rerender(<SemverRangeInput {...props} versions={['3.0.0']} value="3.x" />);
    expect(screen.getByRole('textbox', { name: label })).toHaveValue('3.x');
    expect(screen.getByRole('combobox', { name: versionLabel })).toHaveValue('3.0.0');
    expect(screen.queryByRole('option', { name: '1.2.3' })).not.toBeInTheDocument();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('disables range input and comparison builder', () => {
    render(<ControlledInput isDisabled />);
    expect(screen.getByRole('textbox', { name: label })).toBeDisabled();
    expect(screen.getByRole('combobox', { name: versionLabel })).toBeDisabled();
    expect(screen.getByRole('combobox', { name: operatorLabel })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Use comparison' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Add AND condition' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Add OR alternative' })).toBeDisabled();
  });

  it('clears constraints to allow the API to choose the latest version', async () => {
    const user = userEvent.setup();
    const onChange = jest.fn();
    render(<ControlledInput value="1.2.3" onChange={onChange} />);
    await user.clear(screen.getByRole('textbox', { name: label }));
    expect(onChange).toHaveBeenLastCalledWith('');
    expect(screen.getByRole('button', { name: 'Add AND condition' })).toBeDisabled();
  });
});

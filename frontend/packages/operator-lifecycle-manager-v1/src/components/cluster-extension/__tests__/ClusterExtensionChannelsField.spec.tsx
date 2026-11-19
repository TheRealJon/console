import type { ComponentProps } from 'react';
import { useState } from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ClusterExtensionChannelsField } from '../ClusterExtensionChannelsField';

jest.mock('@console/shared/src/components/markdown/MarkdownView', () => ({
  MarkdownView: ({ content }) => content,
}));

const ControlledChannels = ({
  values: initialValues = [],
  onChange,
  ...props
}: Partial<ComponentProps<typeof ClusterExtensionChannelsField>>) => {
  const [values, setValues] = useState(initialValues);
  return (
    <ClusterExtensionChannelsField
      fieldId="channels"
      availableChannels={['stable', 'beta']}
      {...props}
      values={values}
      onChange={(nextValues) => {
        setValues(nextValues);
        onChange?.(nextValues);
      }}
    />
  );
};

const openChannels = async () => {
  const user = userEvent.setup();
  await user.click(screen.getByRole('button', { name: 'Channels' }));
  return user;
};

describe('ClusterExtensionChannelsField', () => {
  it('renders one labeled multi-select and field-specific helper text', () => {
    render(<ControlledChannels />);
    expect(screen.getByRole('button', { name: 'Channels' })).toHaveTextContent('All channels');
    expect(screen.getByText('For example: stable, beta')).toBeVisible();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  });

  it('selects multiple channels while keeping the menu open', async () => {
    const onChange = jest.fn();
    render(<ControlledChannels onChange={onChange} />);
    const user = await openChannels();
    await user.click(screen.getByRole('checkbox', { name: 'beta' }));
    await user.click(screen.getByRole('checkbox', { name: 'stable' }));
    expect(screen.getByRole('checkbox', { name: 'beta' })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'stable' })).toBeChecked();
    const toggle = within(screen.getByRole('button', { name: 'Channels' }));
    expect(toggle.getByText('beta')).toBeVisible();
    expect(toggle.getByText('stable')).toBeVisible();
    expect(onChange).toHaveBeenLastCalledWith(['beta', 'stable']);
  });

  it('deduplicates choices and toggles only the selected channel without mutating values', async () => {
    const values = ['stable', 'stable', 'custom'];
    const onChange = jest.fn();
    render(
      <ControlledChannels
        values={values}
        availableChannels={['stable', 'stable', 'beta']}
        onChange={onChange}
      />,
    );
    const user = await openChannels();
    expect(screen.getAllByRole('checkbox')).toHaveLength(3);
    expect(screen.getByRole('checkbox', { name: 'stable' })).toBeChecked();
    await user.click(screen.getByRole('checkbox', { name: 'stable' }));
    expect(onChange).toHaveBeenLastCalledWith(['custom']);
    expect(screen.getByRole('button', { name: 'Channels' })).toHaveTextContent('custom');
    expect(values).toEqual(['stable', 'stable', 'custom']);
  });

  it('keeps existing selections removable when catalog suggestions are unavailable', async () => {
    const onChange = jest.fn();
    render(<ControlledChannels values={['stable']} availableChannels={[]} onChange={onChange} />);
    const user = await openChannels();
    await user.click(screen.getByRole('checkbox', { name: 'stable' }));
    expect(onChange).toHaveBeenLastCalledWith([]);
    expect(screen.getByRole('button', { name: 'Channels' })).toHaveTextContent('All channels');
  });

  it('updates choices without dropping existing selections absent from the new catalog', async () => {
    const onChange = jest.fn();
    const props = { fieldId: 'channels', values: ['stable', 'custom'], onChange };
    const { rerender } = render(
      <ClusterExtensionChannelsField {...props} availableChannels={['stable']} />,
    );
    rerender(<ClusterExtensionChannelsField {...props} availableChannels={['preview']} />);
    await openChannels();
    expect(screen.getByRole('checkbox', { name: 'preview' })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'stable' })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'custom' })).toBeChecked();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('disables the picker when no channels or selections exist', () => {
    render(<ControlledChannels availableChannels={[]} />);
    expect(screen.getByRole('button', { name: 'Channels' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Channels' })).toHaveTextContent('All channels');
  });

  it('supports keyboard selection and closes the menu on Escape', async () => {
    render(<ControlledChannels />);
    const user = await openChannels();
    await user.keyboard('{ArrowDown}');
    await user.keyboard(' ');
    expect(screen.getByRole('checkbox', { name: 'beta' })).toBeChecked();
    await user.keyboard('{Escape}');
    expect(screen.getByRole('button', { name: 'Channels' })).toHaveAttribute(
      'aria-expanded',
      'false',
    );
    await waitFor(() => expect(screen.queryAllByRole('checkbox')).toHaveLength(0));
  });

  it('focuses the multi-select when clicking its visible label', async () => {
    render(<ControlledChannels />);
    const user = userEvent.setup();
    await user.click(screen.getByText('Channels'));
    expect(screen.getByRole('button', { name: 'Channels' })).toHaveFocus();
  });

  it('shows field-specific schema help fallback', async () => {
    render(<ControlledChannels />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Channels help' }));
    expect(
      await screen.findByText(
        'Channels that constrain available versions and automatic update paths. If you leave this empty, Operator Lifecycle Manager considers all channels.',
      ),
    ).toBeVisible();
  });
});

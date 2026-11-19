import { renderHook } from '@testing-library/react';
import type { CatalogSource } from '../../components/cluster-extension/cluster-extension-catalog-selector';
import { CATALOG_LABEL_KEY } from '../../const';
import type { OLMCatalogItem } from '../../types';
import { useOLMCatalogItems } from '../useCatalogItems';
import { useClusterExtensionPackageOptions } from '../useClusterExtensionPackageOptions';

jest.mock('../useCatalogItems', () => ({ useOLMCatalogItems: jest.fn() }));

const items = [
  {
    name: 'operator',
    catalog: 'redhat',
    versions: ['1.2.3', '1.3.0'],
    channels: [
      { name: 'stable', versions: ['1.2.3'] },
      { name: 'beta', versions: ['1.3.0'] },
    ],
  },
  {
    name: 'operator',
    catalog: 'community',
    versions: ['2.0.0'],
    channels: [
      { name: 'stable', versions: ['2.0.0'] },
      { name: 'preview', versions: ['2.0.0'] },
    ],
  },
  {
    name: 'other',
    catalog: 'redhat',
    versions: ['9.0.0'],
    channels: [{ name: 'other', versions: ['9.0.0'] }],
  },
] as OLMCatalogItem[];

const emptyOptions = { channels: [], versions: [] };

describe('useClusterExtensionPackageOptions', () => {
  beforeEach(() => {
    jest.mocked(useOLMCatalogItems).mockReturnValue([items, true, '']);
  });

  it('returns sorted unique channels and versions of the selected package', () => {
    const { result } = renderHook(() =>
      useClusterExtensionPackageOptions({ packageName: 'operator' }),
    );
    expect(result.current).toEqual({
      channels: ['beta', 'preview', 'stable'],
      versions: ['1.2.3', '1.3.0', '2.0.0'],
    });
  });

  it('updates catalog and channel constraints without narrowing channel choices to current selections', () => {
    const { result, rerender } = renderHook(
      ({ catalog }: { catalog: CatalogSource['catalog'] }) =>
        useClusterExtensionPackageOptions(catalog),
      {
        initialProps: {
          catalog: {
            packageName: 'operator',
            selector: { matchLabels: { [CATALOG_LABEL_KEY]: 'redhat' } },
            channels: ['stable'],
          },
        },
      },
    );
    expect(result.current).toEqual({ channels: ['beta', 'stable'], versions: ['1.2.3'] });
    rerender({ catalog: { packageName: 'operator', channels: ['beta'] } });
    expect(result.current).toEqual({
      channels: ['beta', 'preview', 'stable'],
      versions: ['1.3.0'],
    });
  });

  it('applies catalog name expressions and intersects all selector requirements', () => {
    const { result, rerender } = renderHook(
      ({ catalog }: { catalog: CatalogSource['catalog'] }) =>
        useClusterExtensionPackageOptions(catalog),
      {
        initialProps: {
          catalog: {
            packageName: 'operator',
            selector: {
              matchExpressions: [{ key: CATALOG_LABEL_KEY, operator: 'In', values: ['community'] }],
            },
          },
        },
      },
    );
    expect(result.current).toEqual({ channels: ['preview', 'stable'], versions: ['2.0.0'] });
    rerender({
      catalog: {
        packageName: 'operator',
        selector: {
          matchLabels: { [CATALOG_LABEL_KEY]: 'redhat' },
          matchExpressions: [{ key: CATALOG_LABEL_KEY, operator: 'NotIn', values: ['redhat'] }],
        },
      },
    });
    expect(result.current).toEqual(emptyOptions);
  });

  it('does not suggest options for custom catalog labels whose eligibility is unknown', () => {
    const { result } = renderHook(() =>
      useClusterExtensionPackageOptions({
        packageName: 'operator',
        selector: { matchLabels: { provider: 'trusted' } },
      }),
    );
    expect(result.current).toEqual(emptyOptions);
  });

  it('returns no options before loading or when catalog loading fails', () => {
    jest.mocked(useOLMCatalogItems).mockReturnValue([[], false, '']);
    const { result, rerender } = renderHook(() =>
      useClusterExtensionPackageOptions({ packageName: 'operator' }),
    );
    expect(result.current).toEqual(emptyOptions);
    jest.mocked(useOLMCatalogItems).mockReturnValue([items, true, 'Network error']);
    rerender();
    expect(result.current).toEqual(emptyOptions);
  });

  it('handles missing package data and packages without channels or versions', () => {
    const { result, rerender } = renderHook(
      ({ catalog }: { catalog?: CatalogSource['catalog'] }) =>
        useClusterExtensionPackageOptions(catalog),
      { initialProps: {} },
    );
    expect(result.current).toEqual(emptyOptions);
    jest
      .mocked(useOLMCatalogItems)
      .mockReturnValue([[{ name: 'operator', catalog: 'redhat' } as OLMCatalogItem], true, '']);
    rerender({ catalog: { packageName: 'operator' } });
    expect(result.current).toEqual(emptyOptions);
  });
});

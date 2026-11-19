import { useMemo } from 'react';
import { LabelSelector } from '@console/internal/module/k8s/label-selector';
import type { CatalogSource } from '../components/cluster-extension/cluster-extension-catalog-selector';
import { CATALOG_LABEL_KEY } from '../const';
import { useOLMCatalogItems } from './useCatalogItems';

interface ClusterExtensionPackageOptions {
  channels: string[];
  versions: string[];
}

/** Share package and catalog filtering between the channel and version fields. */
export const useClusterExtensionPackageOptions = (
  catalog?: CatalogSource['catalog'],
): ClusterExtensionPackageOptions => {
  const [items, loaded, error] = useOLMCatalogItems();
  return useMemo(() => {
    const emptyOptions = { channels: [], versions: [] };
    if (!loaded || error || !catalog?.packageName) return emptyOptions;
    const { channels, selector } = catalog;
    // Catalog items contain names, not arbitrary ClusterCatalog labels. Avoid
    // suggestions whose eligibility under a custom selector is unknown.
    if (
      Object.keys(selector?.matchLabels ?? {}).some((key) => key !== CATALOG_LABEL_KEY) ||
      selector?.matchExpressions?.some(({ key }) => key !== CATALOG_LABEL_KEY)
    )
      return emptyOptions;

    const catalogSelector = new LabelSelector(selector, true);
    const packageItems = items.filter(
      (item) =>
        item.name === catalog.packageName &&
        catalogSelector.matchesLabels({ [CATALOG_LABEL_KEY]: item.catalog }),
    );
    return {
      channels: [
        ...new Set(
          packageItems.flatMap((item) => (item.channels ?? []).map((channel) => channel.name)),
        ),
      ].sort(),
      versions: packageItems.flatMap((item) =>
        channels?.length
          ? (item.channels ?? [])
              .filter((channel) => channels.includes(channel.name))
              .flatMap((channel) => channel.versions)
          : (item.versions ?? []),
      ),
    };
  }, [items, loaded, error, catalog]);
};

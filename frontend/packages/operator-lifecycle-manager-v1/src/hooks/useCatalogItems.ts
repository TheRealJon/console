import * as React from 'react';
import { getConsoleRequestHeaders } from '@console/dynamic-plugin-sdk/dist/core/lib/utils/fetch';
import { CatalogItem } from '@console/dynamic-plugin-sdk/src';
import { consoleFetch } from '@console/dynamic-plugin-sdk/src/lib-core';
import { usePoll } from '@console/shared/src/hooks/usePoll';
import { OLMCatalogItem } from '../types';
import { normalizeCatalogItem } from '../utils/catalog-item';

export type OLMCatalogItemData = {
  categories: string[];
  latestVersion: string;
};

type UseCatalogItems = () => [CatalogItem<OLMCatalogItemData>[], boolean, string];
const useCatalogItems: UseCatalogItems = () => {
  const [items, setItems] = React.useState<CatalogItem<OLMCatalogItemData>[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState('');
  const [lastModified, setLastModified] = React.useState('');

  const headers = React.useMemo(() => {
    const consoleHeaders = getConsoleRequestHeaders();
    return {
      ...consoleHeaders,
      'If-Modified-Since': lastModified,
      'Cache-Control': 'max-age=60',
    };
  }, [lastModified]);

  // Fetch function that only updates state on 200 responses
  const fetchItems = React.useCallback(() => {
    consoleFetch('/api/olm/catalog-items/', { headers })
      .then((response) => {
        setLastModified(response.headers.get('Last-Modified') ?? '');

        if (response.status === 304) {
          setLoading(false);
          return null;
        }

        if (response.status === 200) {
          return response.json();
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      })
      .then((olmItems: OLMCatalogItem[] | null) => {
        if (olmItems && Array.isArray(olmItems)) {
          const newItems = olmItems.map(normalizeCatalogItem);

          // Only update state on successful 200 response
          setItems(newItems);
          setError('');
          setLoading(false);
        }
      })
      .catch((err) => {
        const errorMessage = err instanceof Error ? err.message : err.toString();
        setError(errorMessage);
        setLoading(false);
      });
  }, [headers]);

  usePoll(fetchItems, 5000);

  return [items, loading, error];
};

export default useCatalogItems;

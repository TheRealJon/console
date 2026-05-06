import { useCallback, useState } from 'react';
import { flushSync } from 'react-dom';
import { useNavigate } from 'react-router';
import type { PerspectiveType, UseActivePerspective } from '@console/dynamic-plugin-sdk';
import { usePerspectives } from '@console/shared/src/hooks/usePerspectives';
import { useTelemetry } from '@console/shared/src/hooks/useTelemetry';
import { usePreferredPerspective } from '../user-preferences/perspective/usePreferredPerspective';
import { useLastPerspective } from './useLastPerspective';

type SetActivePerspective = ReturnType<UseActivePerspective>[1];

export const useValuesForPerspectiveContext = (): [
  PerspectiveType,
  SetActivePerspective,
  boolean,
] => {
  const navigate = useNavigate();
  const fireTelemetryEvent = useTelemetry();
  const perspectiveExtensions = usePerspectives();
  const [lastPerspective, setLastPerspective, lastPerspectiveLoaded] = useLastPerspective();
  const [preferredPerspective, , preferredPerspectiveLoaded] = usePreferredPerspective();
  const [activePerspective, setActivePerspective] = useState('');
  const loaded = lastPerspectiveLoaded && preferredPerspectiveLoaded;
  const latestPerspective = loaded && (preferredPerspective || lastPerspective);
  const existingPerspective = activePerspective || latestPerspective;
  const perspective = existingPerspective || '';
  const isValidPerspective =
    loaded && perspectiveExtensions.some((p) => p.properties.id === perspective);

  const setPerspective = useCallback<SetActivePerspective>(
    (newPerspective, next) => {
      // Use flushSync to ensure state updates commit before navigation
      // This prevents split-render where plugins observe perspective change before pathname change
      flushSync(() => {
        setLastPerspective(newPerspective);
        setActivePerspective(newPerspective);
      });
      // Navigate to next or root and let the default page determine where to go to next
      navigate(next || '/');
      fireTelemetryEvent('Perspective Changed', { perspective: newPerspective });
    },
    [setLastPerspective, setActivePerspective, navigate, fireTelemetryEvent],
  );

  return [isValidPerspective ? perspective : '', setPerspective, loaded];
};

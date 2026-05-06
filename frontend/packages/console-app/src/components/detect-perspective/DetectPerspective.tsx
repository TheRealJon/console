import type { FC } from 'react';
import { useEffect } from 'react';
import { useLocation } from 'react-router';
import type { Perspective } from '@console/dynamic-plugin-sdk';
import { PerspectiveContext } from '@console/dynamic-plugin-sdk';
import { LoadingBox } from '@console/shared/src/components/loading/LoadingBox';
import { usePerspectives } from '@console/shared/src/hooks/usePerspectives';
import PerspectiveDetector from './PerspectiveDetector';
import { useValuesForPerspectiveContext } from './useValuesForPerspectiveContext';

type DetectPerspectiveProps = {
  children: React.ReactNode;
};

const getPerspectiveURLParam = (perspectives: Perspective[]) => {
  const perspectiveIDs = perspectives.map(
    (nextPerspective: Perspective) => nextPerspective.properties.id,
  );

  const urlParams = new URLSearchParams(window.location.search);
  const perspectiveParam = urlParams.get('perspective');
  return perspectiveParam && perspectiveIDs.includes(perspectiveParam) ? perspectiveParam : '';
};

const DetectPerspective: FC<DetectPerspectiveProps> = ({ children }) => {
  const [activePerspective, setActivePerspective, loaded] = useValuesForPerspectiveContext();
  const perspectiveExtensions = usePerspectives();
  const perspectiveParam = getPerspectiveURLParam(perspectiveExtensions);
  const location = useLocation();
  useEffect(() => {
    if (perspectiveParam && perspectiveParam !== activePerspective) {
      // Pass pathname without query params to avoid ?perspective= param loop
      setActivePerspective(perspectiveParam, location.pathname);
    }
    // location is intentionally excluded from deps to prevent firing on every navigation
    // The effect should only run when perspectiveParam changes (URL param added/changed)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [perspectiveParam, activePerspective, setActivePerspective]);

  return loaded ? (
    activePerspective ? (
      <PerspectiveContext.Provider
        value={{
          activePerspective,
          setActivePerspective,
        }}
      >
        {children}
      </PerspectiveContext.Provider>
    ) : (
      <PerspectiveDetector setActivePerspective={setActivePerspective} />
    )
  ) : (
    <LoadingBox blame="DetectPerspective" />
  );
};

export default DetectPerspective;

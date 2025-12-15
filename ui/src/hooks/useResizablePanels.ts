import type React from 'react';
import { useCallback, useState } from 'react';

export function useResizablePanels(options?: {
  sessionsWidthInitial?: number;
  requestsWidthInitial?: number;
}) {
  const [sessionsWidth, setSessionsWidth] = useState(options?.sessionsWidthInitial ?? 280);
  const [requestsWidth, setRequestsWidth] = useState(options?.requestsWidthInitial ?? 320);
  const [isSessionsCollapsed, setIsSessionsCollapsed] = useState(false);
  const [isRequestsCollapsed, setIsRequestsCollapsed] = useState(false);

  const startResizingSessions = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      const startX = e.clientX;
      const startWidth = sessionsWidth;

      const onMouseMove = (moveEvent: MouseEvent) => {
        const newWidth = Math.max(200, Math.min(600, startWidth + (moveEvent.clientX - startX)));
        setSessionsWidth(newWidth);
      };

      const onMouseUp = () => {
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
      };

      document.addEventListener('mousemove', onMouseMove);
      document.addEventListener('mouseup', onMouseUp);
    },
    [sessionsWidth]
  );

  const startResizingRequests = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      const startX = e.clientX;
      const startWidth = requestsWidth;

      const onMouseMove = (moveEvent: MouseEvent) => {
        const newWidth = Math.max(250, Math.min(600, startWidth + (moveEvent.clientX - startX)));
        setRequestsWidth(newWidth);
      };

      const onMouseUp = () => {
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
      };

      document.addEventListener('mousemove', onMouseMove);
      document.addEventListener('mouseup', onMouseUp);
    },
    [requestsWidth]
  );

  return {
    sessionsWidth,
    setSessionsWidth,
    requestsWidth,
    setRequestsWidth,
    isSessionsCollapsed,
    setIsSessionsCollapsed,
    isRequestsCollapsed,
    setIsRequestsCollapsed,
    startResizingSessions,
    startResizingRequests,
  };
}

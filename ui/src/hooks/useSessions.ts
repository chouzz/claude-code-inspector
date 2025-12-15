import { useEffect, useState } from 'react';
import type { Session, SessionSummary } from '../types';
import { normalizeSession } from '../utils';

export function useSessions(options: { apiBase: string; pollMs?: number }) {
  const { apiBase, pollMs = 2000 } = options;

  // Data State
  const [sessionList, setSessionList] = useState<SessionSummary[]>([]);
  const [currentSession, setCurrentSession] = useState<Session | null>(null);
  const [isLoadingList, setIsLoadingList] = useState(true);

  // Selection State
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedExchangeId, setSelectedExchangeId] = useState<string | null>(null);

  const fetchSessionList = async () => {
    try {
      const res = await fetch(`${apiBase}/api/sessions`);
      if (res.ok) {
        const data = await res.json();
        setSessionList(data);
        return data as SessionSummary[];
      }
    } catch (error) {
      console.error('Failed to fetch sessions', error);
    }
    return [] as SessionSummary[];
  };

  const fetchSessionDetails = async (sessionId: string) => {
    try {
      const res = await fetch(`${apiBase}/api/sessions/${sessionId}`);
      if (res.ok) {
        const data = await res.json();
        // Normalize the API data to UI structure
        const session = normalizeSession(data);
        setCurrentSession(session);

        // Auto-select last exchange (most recent)
        if (session.exchanges.length > 0) {
          setSelectedExchangeId(session.exchanges[session.exchanges.length - 1].id);
        }
      }
    } catch (error) {
      console.error('Failed to fetch session details', error);
    }
  };

  // Poll for session list updates
  useEffect(() => {
    const load = async () => {
      await fetchSessionList();
      setIsLoadingList(false);
    };

    load();
    const interval = setInterval(fetchSessionList, pollMs);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiBase, pollMs]);

  // When selectedSessionId changes, fetch details
  useEffect(() => {
    if (selectedSessionId) {
      fetchSessionDetails(selectedSessionId);
    } else {
      setCurrentSession(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedSessionId, apiBase]);

  // Auto-select the newest session once the list loads, and handle removed sessions
  useEffect(() => {
    if (sessionList.length === 0) {
      if (selectedSessionId !== null) {
        setSelectedSessionId(null);
      }
      setSelectedExchangeId(null);
      return;
    }

    const hasSelection =
      selectedSessionId && sessionList.some((session) => session.id === selectedSessionId);
    if (!hasSelection) {
      setSelectedSessionId(sessionList[0].id);
    }
  }, [sessionList, selectedSessionId]);

  return {
    sessionList,
    currentSession,
    isLoadingList,
    selectedSessionId,
    setSelectedSessionId,
    selectedExchangeId,
    setSelectedExchangeId,
    refreshSessionList: fetchSessionList,
    fetchSessionDetails,
  };
}

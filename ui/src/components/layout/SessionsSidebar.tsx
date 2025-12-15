import React, { useState } from 'react';
import {
  Activity,
  Check,
  ChevronLeft,
  ChevronRight,
  FolderOpen,
  MessageCircle,
  Moon,
  Pencil,
  Sun,
} from 'lucide-react';
import type { AnnotationData, SessionSummary } from '../../types';
import { formatTimestamp } from '../../utils';
import { Tooltip } from '../common/Tooltip';

export const SessionsSidebar: React.FC<{
  width: number;
  isCollapsed: boolean;
  setIsCollapsed: (v: boolean) => void;
  onStartResize: (e: React.MouseEvent) => void;

  sessionList: SessionSummary[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;

  isDarkMode: boolean;
  onToggleTheme: () => void;

  annotations: Record<string, AnnotationData>;
  onUpdateSessionNote: (sessionId: string, note: string) => void;
}> = ({
  width,
  isCollapsed,
  setIsCollapsed,
  onStartResize,
  sessionList,
  selectedSessionId,
  onSelectSession,
  isDarkMode,
  onToggleTheme,
  annotations,
  onUpdateSessionNote,
}) => {
  const [editingSessionNote, setEditingSessionNote] = useState<string | null>(null);

  return (
    <div
      style={{ width: isCollapsed ? '48px' : width }}
      className="flex-shrink-0 border-r border-gray-200 dark:border-slate-800 bg-white dark:bg-[#0b1120] flex flex-col relative transition-all duration-300 ease-in-out"
    >
      {/* Sessions Header */}
      <div
        className={`p-4 border-b border-gray-200 dark:border-slate-800 flex items-center ${
          isCollapsed ? 'justify-center flex-col gap-4' : 'justify-between'
        }`}
      >
        {!isCollapsed && (
          <div className="flex items-center gap-2">
            <Activity size={18} className="text-blue-600 dark:text-blue-500" />
            <h2 className="font-bold text-sm tracking-wide text-slate-700 dark:text-slate-200">
              SESSIONS
            </h2>
          </div>
        )}

        <div className={`flex ${isCollapsed ? 'flex-col gap-3' : 'gap-1'}`}>
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="p-1.5 hover:bg-gray-100 dark:hover:bg-slate-800 rounded text-slate-500 dark:text-slate-400 transition-colors"
            title={isCollapsed ? 'Expand' : 'Collapse'}
            type="button"
          >
            {isCollapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
          </button>
          {!isCollapsed && (
            <button
              onClick={onToggleTheme}
              className="p-1.5 hover:bg-gray-100 dark:hover:bg-slate-800 rounded text-slate-500 dark:text-slate-400 transition-colors"
              title="Toggle Theme"
              type="button"
            >
              {isDarkMode ? <Sun size={14} /> : <Moon size={14} />}
            </button>
          )}
        </div>
      </div>

      {/* Sessions List */}
      <div className="overflow-y-auto flex-1 p-2 space-y-1 custom-scrollbar">
        {sessionList.map((session) => {
          const sessionNote = annotations[session.id]?.session_note || '';
          const hasNote = sessionNote.length > 0;
          const isEditing = editingSessionNote === session.id;

          return (
            <div key={session.id} className="relative">
              <button
                onClick={() => {
                  onSelectSession(session.id);
                  if (isCollapsed) setIsCollapsed(false);
                }}
                className={`w-full text-left rounded-lg text-sm font-medium transition-all duration-200 group relative ${
                  isCollapsed ? 'p-2 flex justify-center' : 'px-3 py-3'
                } ${
                  selectedSessionId === session.id
                    ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-200 shadow-inner ring-1 ring-blue-100 dark:ring-blue-900/30'
                    : 'text-slate-500 dark:text-slate-400 hover:bg-gray-100 dark:hover:bg-slate-800/50 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
                title={session.id}
                type="button"
              >
                {selectedSessionId === session.id && !isCollapsed && (
                  <div className="absolute left-0 top-3 bottom-3 w-1 bg-blue-500 rounded-r-full"></div>
                )}
                {isCollapsed ? (
                  <div className="relative">
                    <FolderOpen
                      size={20}
                      className={
                        selectedSessionId === session.id
                          ? 'text-blue-600 dark:text-blue-400'
                          : 'text-slate-400 dark:text-slate-600'
                      }
                    />
                    {hasNote && <div className="absolute -top-1 -right-1 w-2 h-2 bg-amber-500 rounded-full"></div>}
                  </div>
                ) : (
                  <>
                    <div className="flex items-center gap-2.5 mb-1">
                      <FolderOpen
                        size={16}
                        className={
                          selectedSessionId === session.id
                            ? 'text-blue-600 dark:text-blue-400'
                            : 'text-slate-400 dark:text-slate-600 group-hover:text-slate-500'
                        }
                      />
                      <span className="truncate flex-1 font-semibold">{session.id}</span>
                      {hasNote && <MessageCircle size={12} className="text-amber-500 flex-shrink-0" />}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setEditingSessionNote(isEditing ? null : session.id);
                        }}
                        className="p-1 hover:bg-gray-200 dark:hover:bg-slate-700 rounded opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0"
                        title="Edit note"
                        type="button"
                      >
                        <Pencil size={12} className="text-slate-400 dark:text-slate-500" />
                      </button>
                    </div>
                    <div className="pl-7 text-[10px] text-slate-400 dark:text-slate-500 flex justify-between items-center">
                      <span>{session.request_count} requests</span>
                      <span className="font-mono opacity-50">{formatTimestamp(session.timestamp)}</span>
                    </div>
                  </>
                )}
              </button>

              {/* Inline Note Editor */}
              {!isCollapsed && isEditing && (
                <div className="mx-2 mt-1 mb-2">
                  <div className="relative">
                    <textarea
                      autoFocus
                      value={sessionNote}
                      onChange={(e) => onUpdateSessionNote(session.id, e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Escape') {
                          setEditingSessionNote(null);
                        } else if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault();
                          setEditingSessionNote(null);
                        }
                        // Shift+Enter allows natural newline
                      }}
                      placeholder="Add a note... (Enter to save, Shift+Enter for newline)"
                      className="w-full text-xs p-2 pr-8 border border-amber-300 dark:border-amber-700 rounded-md bg-amber-50 dark:bg-amber-950/30 text-slate-700 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 resize-none focus:outline-none focus:ring-2 focus:ring-amber-400 dark:focus:ring-amber-600"
                      rows={2}
                    />
                    <button
                      onClick={() => setEditingSessionNote(null)}
                      className="absolute top-1.5 right-1.5 p-1 hover:bg-amber-200 dark:hover:bg-amber-800 rounded text-amber-600 dark:text-amber-400"
                      title="Done (Enter)"
                      type="button"
                    >
                      <Check size={12} />
                    </button>
                  </div>
                </div>
              )}

              {/* Display Note (when not editing) */}
              {!isCollapsed && !isEditing && hasNote && (
                <Tooltip text={sessionNote}>
                  <div
                    className="mx-2 mt-1 mb-2 px-2 py-1.5 text-[10px] text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/20 rounded border-l-2 border-amber-400 dark:border-amber-600 cursor-pointer hover:bg-amber-100 dark:hover:bg-amber-950/30 transition-colors"
                    onClick={() => setEditingSessionNote(session.id)}
                    title="Click to edit"
                  >
                    <div className="line-clamp-2">{sessionNote}</div>
                  </div>
                </Tooltip>
              )}
            </div>
          );
        })}
      </div>

      {/* Resizer Handle */}
      {!isCollapsed && (
        <div
          className="absolute top-0 right-0 w-1 h-full cursor-col-resize hover:bg-blue-500/50 transition-colors z-10 flex items-center justify-center group"
          onMouseDown={onStartResize}
        >
          <div className="w-[1px] h-full bg-gray-200 dark:bg-slate-800 group-hover:bg-blue-500"></div>
        </div>
      )}
    </div>
  );
};

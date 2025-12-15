import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Terminal } from 'lucide-react';
import { CopyButton } from '../common/CopyButton';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

export const ToolCallBlock: React.FC<{ content: unknown }> = ({ content }) => {
  // Default expanded to true as requested
  const [expanded, setExpanded] = useState(true);
  const toolName =
    isRecord(content) && typeof content.name === 'string' ? content.name : 'unknown';
  const toolInput = isRecord(content) ? content.input : undefined;
  const toolCallText = `[Tool Call: ${toolName}]\n${JSON.stringify(toolInput, null, 2)}`;

  return (
    <div className="my-2 border border-yellow-500/30 dark:border-yellow-600/50 bg-yellow-50 dark:bg-yellow-950/20 rounded-md overflow-hidden group/tool shadow-sm">
      <div
        className="px-3 py-2 bg-yellow-100/50 dark:bg-yellow-900/30 flex items-center gap-2 cursor-pointer hover:bg-yellow-200/50 dark:hover:bg-yellow-900/50 transition select-none"
        onClick={() => setExpanded(!expanded)}
      >
        <Terminal size={14} className="text-yellow-600 dark:text-yellow-500" />
        <span className="text-xs font-bold text-yellow-700 dark:text-yellow-500 font-mono">
          Tool Call: {toolName}
        </span>
        <div className="flex-1" />
        <CopyButton content={toolCallText} className="opacity-0 group-hover/tool:opacity-100" />
        {expanded ? (
          <ChevronDown size={14} className="text-yellow-600 dark:text-yellow-500" />
        ) : (
          <ChevronRight
            size={14}
            className="text-yellow-600 dark:text-yellow-500 opacity-50 group-hover/tool:opacity-100"
          />
        )}
      </div>
      {expanded && (
        <div className="p-3 bg-white dark:bg-black/20">
          <div className="text-[10px] uppercase text-gray-400 dark:text-gray-500 mb-1 font-semibold tracking-wider">
            Arguments
          </div>
          <pre className="text-xs font-mono text-yellow-800 dark:text-yellow-100/80 overflow-x-auto whitespace-pre-wrap break-all custom-scrollbar">
            {JSON.stringify(toolInput, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

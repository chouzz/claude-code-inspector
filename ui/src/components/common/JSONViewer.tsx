import React from 'react';
import { safeJSONStringify } from '../../utils/ui';

export const JSONViewer: React.FC<{ data: unknown; wrap?: boolean }> = ({
  data,
  wrap = false,
}) => (
  <pre
    className={`text-xs font-mono bg-gray-50 dark:bg-black/40 p-4 rounded overflow-auto max-h-[600px] text-green-700 dark:text-green-400 border border-gray-200 dark:border-gray-800 custom-scrollbar ${
      wrap ? 'whitespace-pre-wrap break-words' : 'whitespace-pre'
    }`}
  >
    {safeJSONStringify(data)}
  </pre>
);

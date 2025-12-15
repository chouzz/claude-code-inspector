import React, { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { copyToClipboard } from '../../utils/ui';

export const CopyButton: React.FC<{ content: string; className?: string }> = ({
  content,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    const success = await copyToClipboard(content);
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <button
      onClick={handleCopy}
      className={`p-1 rounded hover:bg-gray-200 dark:hover:bg-slate-700 transition-colors ${className}`}
      title={copied ? 'Copied!' : 'Copy to clipboard'}
      type="button"
    >
      {copied ? (
        <Check size={12} className="text-green-500" />
      ) : (
        <Copy
          size={12}
          className="text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300"
        />
      )}
    </button>
  );
};

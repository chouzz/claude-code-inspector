import React, { useRef, useState } from 'react';

export const Tooltip: React.FC<{ text: string; children: React.ReactNode }> = ({
  text,
  children,
}) => {
  const [show, setShow] = useState(false);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  const handleMouseEnter = (e: React.MouseEvent) => {
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    setPosition({ x: rect.left, y: rect.bottom + 4 });
    setShow(true);
  };

  return (
    <div
      ref={containerRef}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={() => setShow(false)}
      className="relative"
    >
      {children}
      {show && text && (
        <div
          className="fixed z-50 max-w-md p-2 text-xs bg-slate-900 dark:bg-slate-700 text-white rounded-md shadow-lg whitespace-pre-wrap break-words"
          style={{ left: position.x, top: position.y }}
        >
          {text}
        </div>
      )}
    </div>
  );
};

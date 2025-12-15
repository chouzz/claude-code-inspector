import { useEffect, useState } from 'react';

export function useTheme() {
  // Theme State (Default Light)
  const [isDarkMode, setIsDarkMode] = useState(false);

  const toggleTheme = () => setIsDarkMode((v) => !v);

  // Sync theme with HTML element for global styles (scrollbars etc)
  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDarkMode]);

  return { isDarkMode, setIsDarkMode, toggleTheme };
}

import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// The web engine offers a page menu on a right click — going back, reloading,
// opening its inspector. None of that belongs to this window. A text field
// keeps the menu that edits it, which is the one a person actually asks for.
document.addEventListener('contextmenu', (event) => {
  const target = event.target;
  const editable =
    target instanceof Element &&
    !!target.closest(
      'input:not([readonly]), textarea:not([readonly]), [contenteditable=""], [contenteditable="true"]',
    );
  if (!editable) event.preventDefault();
});

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

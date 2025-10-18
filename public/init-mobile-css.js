// Inject compact CSS and adjust detail row markup for tighter spacing on mobile
(function(){
  try {
    // Add mobile compact stylesheet if not present
    if (!document.querySelector('link[data-mobile-compact]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'styles/mobile-compact.css';
      link.setAttribute('data-mobile-compact','1');
      document.head.appendChild(link);
    }
  } catch(e) {}
})();

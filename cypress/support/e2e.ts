// Import commands.js using ES2015 syntax:
import './commands'

declare global {
  namespace Cypress {
    interface Chainable {
      // Add custom commands here
      // Example:
      // login(email: string, password: string): Chainable<void>
    }
  }
}

// Hide fetch/XHR requests from command log
const app = window.top;
if (app) {
  const log = app.console.log;
  app.console.log = (...args) => {
    if (args.length === 1 && typeof args[0] === 'string' && args[0].includes('Download the React DevTools')) {
      return;
    }
    log(...args);
  };
} 
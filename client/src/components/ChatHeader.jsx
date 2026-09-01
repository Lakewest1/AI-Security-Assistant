import React from "react";

const ChatHeader = ({ darkMode, setDarkMode, clearChat }) => {
  return (
    <header className="header">
      <div className="header-left">
        <div className="logo">🛡️</div>
        <div>
          <h1>AI Security Assistant</h1>
          <p>Cloud Security • AWS • Azure • Kubernetes</p>
        </div>
      </div>
      <div className="header-actions">
        <button 
          className="theme-toggle" 
          onClick={() => setDarkMode(!darkMode)}
          aria-label="Toggle theme"
          title="Toggle theme"
        >
          {darkMode ? '☀️' : '🌙'}
        </button>
        <button 
          className="clear-button" 
          onClick={clearChat}
          aria-label="Clear chat"
        >
          Clear Chat
        </button>
      </div>
    </header>
  );
};

export default ChatHeader;
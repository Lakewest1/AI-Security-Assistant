import React from "react";

const TypingIndicator = () => {
  return (
    <div className="typing-indicator">
      <div className="typing-dots">
        <span></span>
        <span></span>
        <span></span>
      </div>
      <span className="typing-text">AI is thinking...</span>
    </div>
  );
};

export default TypingIndicator;
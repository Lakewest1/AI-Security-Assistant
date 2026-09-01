import React, { useState } from "react";
import MarkdownRenderer from "./MarkdownRenderer";
import VisualCard from "./VisualCard";

const Message = ({ message, onRetry }) => {
  const [showActions, setShowActions] = useState(false);
  const isUser = message.role === "user";

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
  };

  const handleCopyResponse = async () => {
    try {
      await navigator.clipboard.writeText(message.content);
    } catch (error) {
      console.error("Failed to copy response:", error);
    }
  };

  return (
    <div 
      className={`message-row ${isUser ? 'user' : 'assistant'}`}
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
    >
      <div className="message-header">
        <div className="message-label">
          {isUser ? "YOU" : "AI"}
        </div>
        {message.timestamp && (
          <div className="message-time">
            {formatTimestamp(message.timestamp)}
          </div>
        )}
      </div>

      <div className="message-bubble">
        {isUser ? (
          message.content
        ) : (
          <>
            <MarkdownRenderer content={message.content} />
            {message.visual && <VisualCard visualData={message.visual} />}
          </>
        )}
      </div>

      {!isUser && showActions && (
        <div className="message-actions">
          <button 
            className="action-button"
            onClick={handleCopyResponse}
            aria-label="Copy response"
          >
            📋 Copy
          </button>
          <button 
            className="action-button"
            onClick={onRetry}
            aria-label="Retry"
          >
            🔄 Retry
          </button>
        </div>
      )}
    </div>
  );
};

export default Message;
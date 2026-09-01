import React, { useEffect, useRef } from "react";

const ChatComposer = ({ input, setInput, sendMessage, loading }) => {
  const textareaRef = useRef(null);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = textareaRef.current.scrollHeight + 'px';
    }
  }, [input]);

  const handleKeyDown = (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="composer-wrapper">
      <div className="input-area">
        <textarea
          ref={textareaRef}
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask a security question..."
          rows="1"
          disabled={loading}
          maxLength={4000}
          aria-label="Message input"
        />
        <div className="input-actions">
          <span className="char-count" aria-hidden="true">
            {input.length}/4000
          </span>
          <button
            className="send-button"
            onClick={() => sendMessage()}
            disabled={loading || !input.trim()}
            aria-label="Send message"
          >
            {loading ? "..." : "Send →"}
          </button>
        </div>
      </div>
      <p className="hint">
        Press Enter to send • Shift + Enter for new line • Markdown supported
      </p>
    </div>
  );
};

export default ChatComposer;
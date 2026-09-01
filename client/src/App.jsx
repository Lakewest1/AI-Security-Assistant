import { useEffect, useRef, useState, useCallback } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

// Standalone CodeBlock component (fixed React hook issue)
function CodeBlock({ inline, className, children, ...props }) {
  const [copied, setCopied] = useState(false);

  const match = /language-(\w+)/.exec(className || "");
  const code = String(children).replace(/\n$/, "");

  const handleCopyCode = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error("Failed to copy code:", error);
    }
  };

  if (!inline && match) {
    return (
      <div className="code-block">
        <div className="code-header">
          <span className="code-language">{match[1]}</span>
          <button 
            className="code-copy-button"
            onClick={handleCopyCode}
            aria-label="Copy code"
          >
            {copied ? '✓ Copied' : 'Copy'}
          </button>
        </div>
        <SyntaxHighlighter
          style={oneDark}
          language={match[1]}
          PreTag="div"
          customStyle={{
            margin: 0,
            borderRadius: 0,
            fontSize: '13px',
            lineHeight: '1.5',
          }}
          {...props}
        >
          {code}
        </SyntaxHighlighter>
      </div>
    );
  }

  return (
    <code className={`inline-code ${className || ''}`} {...props}>
      {children}
    </code>
  );
}

function App() {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content: "👋 Hello! I'm your AI Security Assistant. I can help with cloud security, AWS, Azure, Kubernetes, IAM, incident response, and more. What would you like to explore?",
      timestamp: new Date().toISOString(),
    },
  ]);

  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [typing, setTyping] = useState(false);
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem("darkMode");
    return saved ? JSON.parse(saved) : window.matchMedia("(prefers-color-scheme: dark)").matches;
  });
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [intents, setIntents] = useState([]);
  const [copiedMessageId, setCopiedMessageId] = useState(null);
  const [conversationId, setConversationId] = useState(null);

  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);
  const messagesContainerRef = useRef(null);

  // Suggested questions
  const suggestedQuestions = [
    "How do I secure my AWS S3 buckets?",
    "What are the best practices for Kubernetes security?",
    "Explain IAM roles vs policies",
    "How to detect and respond to security incidents?",
    "What is a WAF and when should I use it?",
  ];

  // Persist dark mode preference
  useEffect(() => {
    localStorage.setItem("darkMode", JSON.stringify(darkMode));
    document.documentElement.classList.toggle("dark", darkMode);
  }, [darkMode]);

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 200) + 'px';
    }
  }, [input]);

  // Auto-scroll to newest message
  useEffect(() => {
    if (!showScrollButton) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [messages, loading, typing, showScrollButton]);

  // Handle scroll position
  const handleScroll = useCallback(() => {
    const container = messagesContainerRef.current;
    if (container) {
      const { scrollTop, scrollHeight, clientHeight } = container;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 120;
      setShowScrollButton(!isNearBottom);
    }
  }, []);

  // Typing effect for AI responses
  const typeMessage = useCallback(async (fullMessage) => {
    setTyping(true);
    const words = fullMessage.split(' ');
    let currentMessage = '';
    
    // For long messages, use chunk-based typing instead of word-by-word
    if (words.length > 100) {
      setMessages(prev => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: 'assistant',
          content: fullMessage,
          timestamp: new Date().toISOString(),
        };
        return updated;
      });
      setTyping(false);
      return;
    }
    
    for (let i = 0; i < words.length; i++) {
      currentMessage += (i === 0 ? '' : ' ') + words[i];
      setMessages(prev => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          role: 'assistant',
          content: currentMessage,
          timestamp: new Date().toISOString(),
        };
        return updated;
      });
      const delay = words.length > 50 ? 15 : 25;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
    
    setTyping(false);
  }, []);

  const sendMessage = async (content = input) => {
    const trimmedInput = content.trim();

    if (!trimmedInput || loading) {
      return;
    }

    const userMessage = {
      role: "user",
      content: trimmedInput,
      timestamp: new Date().toISOString(),
    };

    const updatedMessages = [...messages, userMessage];
    setMessages(updatedMessages);
    setInput("");
    setLoading(true);
    setIntents([]);

    try {
      const response = await fetch(`${API_URL}/api/chat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          messages: updatedMessages.map(({ role, content }) => ({ role, content })),
          conversationId,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "AI request failed");
      }

      if (data.conversationId) {
        setConversationId(data.conversationId);
      }

      if (data.intents) {
        setIntents(data.intents);
      }

      setMessages(prev => [...prev, {
        role: "assistant",
        content: "",
        timestamp: new Date().toISOString(),
        visual: data.visual || null,
      }]);
      
      await typeMessage(data.reply);
    } catch (error) {
      setMessages(prev => [
        ...prev,
        {
          role: "assistant",
          content: `⚠️ ${error.message || "Unable to connect to the AI server. Please check your connection or try again."}`,
          timestamp: new Date().toISOString(),
          error: true,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  };

  const clearChat = async () => {
    if (conversationId) {
      try {
        await fetch(`${API_URL}/api/clear-conversation`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ conversationId }),
        });
      } catch (error) {
        console.error("Failed to clear conversation:", error);
      }
    }
    
    setConversationId(null);
    setIntents([]);
    setMessages([
      {
        role: "assistant",
        content: "👋 Chat cleared! Ready for a new security question. What would you like to explore?",
        timestamp: new Date().toISOString(),
      },
    ]);
  };

  const handleSuggestionClick = (suggestion) => {
    sendMessage(suggestion);
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
    setShowScrollButton(false);
  };

  const handleCopyMessage = async (content, index) => {
    try {
      await navigator.clipboard.writeText(content);
      setCopiedMessageId(index);
      setTimeout(() => setCopiedMessageId(null), 2000);
    } catch (error) {
      console.error("Failed to copy:", error);
    }
  };

  const handleRetry = () => {
    const lastUserMessage = [...messages].reverse().find(m => m.role === "user");
    if (lastUserMessage) {
      sendMessage(lastUserMessage.content);
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
  };

  return (
    <div className={`app ${darkMode ? 'dark' : ''}`}>
      <header className="header">
        <div className="header-content">
          <div className="header-left">
            <span className="logo" aria-hidden="true">🛡️</span>
            <div>
              <h1 className="header-title">AI Security Assistant</h1>
              <p className="header-subtitle">Cloud Security • AWS • Azure • Kubernetes</p>
            </div>
          </div>
          <div className="header-actions">
            <button 
              className="theme-toggle" 
              onClick={() => setDarkMode(!darkMode)}
              aria-label={darkMode ? "Switch to light mode" : "Switch to dark mode"}
              title={darkMode ? "Light mode" : "Dark mode"}
            >
              {darkMode ? '☀️' : '🌙'}
            </button>
            <button 
              className="clear-button" 
              onClick={clearChat}
              aria-label="Clear chat"
              title="Clear chat"
            >
              Clear Chat
            </button>
          </div>
        </div>
      </header>

      {intents.length > 0 && (
        <div className="intent-badges">
          {intents.map((intent) => (
            <span key={intent} className="intent-badge">
              {intent.replace('_', ' ')}
            </span>
          ))}
        </div>
      )}

      <main className="chat-container">
        {messages.length === 1 && (
          <div className="suggestions-container">
            <p className="suggestions-title">Try asking about:</p>
            <div className="suggestions-list">
              {suggestedQuestions.map((question, index) => (
                <button
                  key={index}
                  className="suggestion-chip"
                  onClick={() => handleSuggestionClick(question)}
                >
                  {question}
                </button>
              ))}
            </div>
          </div>
        )}

        <div 
          className="messages" 
          ref={messagesContainerRef}
          onScroll={handleScroll}
          role="log"
          aria-live="polite"
          aria-label="Chat messages"
        >
          {messages.map((message, index) => (
            <div
              key={index}
              className={`message ${message.role} ${message.error ? 'error' : ''}`}
            >
              <div className="message-meta">
                <span className="message-author">
                  {message.role === "user" ? "YOU" : "AI"}
                </span>
                {message.timestamp && (
                  <span className="message-time">{formatTimestamp(message.timestamp)}</span>
                )}
              </div>

              <div className="message-content">
                {message.role === "assistant" && !message.error ? (
                  <>
                    <div className="markdown-content">
                      <ReactMarkdown
                        remarkPlugins={[remarkGfm]}
                        components={{
                          code: CodeBlock,
                          table({ children }) {
                            return (
                              <div className="table-wrapper">
                                <table>{children}</table>
                              </div>
                            );
                          },
                          blockquote({ children }) {
                            return <blockquote className="blockquote">{children}</blockquote>;
                          },
                        }}
                      >
                        {message.content}
                      </ReactMarkdown>
                    </div>

                    {message.visual && message.visual.needed && (
                      <div className="visual-card">
                        <div className="visual-card-header">
                          <span className="visual-icon" aria-hidden="true">📊</span>
                          <span>Visual Learning</span>
                        </div>
                        <div className="visual-card-body">
                          <div className="visual-placeholder">
                            <div className="placeholder-icon" aria-hidden="true">🔍</div>
                            <p>Visual content coming soon</p>
                            <span>We're preparing diagram support</span>
                          </div>
                        </div>
                        {message.visual.query && (
                          <div className="visual-card-footer">
                            <span>Topic: {message.visual.query}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </>
                ) : (
                  <div className="plain-message">{message.content}</div>
                )}
              </div>

              {message.role === "assistant" && !message.error && (
                <div className="message-actions">
                  <button
                    className="message-action-btn"
                    onClick={() => handleCopyMessage(message.content, index)}
                    aria-label="Copy response"
                  >
                    {copiedMessageId === index ? '✓ Copied' : '📋 Copy'}
                  </button>
                  <button
                    className="message-action-btn"
                    onClick={handleRetry}
                    aria-label="Retry"
                  >
                    🔄 Retry
                  </button>
                </div>
              )}
            </div>
          ))}

          {loading && !typing && (
            <div className="message assistant loading">
              <div className="message-meta">
                <span className="message-author">AI</span>
              </div>
              <div className="message-content">
                <div className="typing-indicator" aria-label="AI is thinking">
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
            </div>
          )}

          {typing && (
            <div className="typing-status">
              AI is typing...
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {showScrollButton && (
          <button 
            className="scroll-button" 
            onClick={scrollToBottom}
            aria-label="Scroll to bottom"
          >
            ↓
          </button>
        )}

        <div className="composer">
          <div className="composer-box">
            <textarea
              ref={textareaRef}
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask a security question..."
              rows="1"
              disabled={loading}
              aria-label="Message input"
              maxLength={4000}
            />
            <button
              className="send-button"
              onClick={() => sendMessage()}
              disabled={loading || !input.trim()}
              aria-label="Send message"
            >
              {loading ? "..." : "Send →"}
            </button>
          </div>
          <p className="composer-hint">
            Press Enter to send • Shift + Enter for new line • Markdown supported
          </p>
        </div>
      </main>
    </div>
  );
}

export default App;
import { useEffect, useRef, useState, useCallback } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

// Dynamic thinking words based on question context
const THINKING_WORDS = [
  "Fathoming...",
  "Calculating...",
  "Reasoning...",
  "Strategizing...",
  "Analyzing...",
  "Correlating...",
  "Evaluating...",
  "Synthesizing...",
  "Processing...",
  "Connecting...",
  "Examining...",
  "Formulating...",
  "Compiling...",
  "Reviewing...",
  "Assessing...",
  "Mapping...",
  "Scanning...",
  "Retrieving...",
  "Investigating...",
  "Building...",
];

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
            userSelect: 'text',
            WebkitUserSelect: 'text',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            overflowWrap: 'break-word',
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
  const [thinkingWord, setThinkingWord] = useState(THINKING_WORDS[0]);
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

  // Rotate thinking words while loading
  useEffect(() => {
    if (loading) {
      const interval = setInterval(() => {
        setThinkingWord(prev => {
          const currentIndex = THINKING_WORDS.indexOf(prev);
          const nextIndex = (currentIndex + 1) % THINKING_WORDS.length;
          return THINKING_WORDS[nextIndex];
        });
      }, 1500);
      
      return () => clearInterval(interval);
    }
  }, [loading]);

  // Persist dark mode preference
  useEffect(() => {
    localStorage.setItem("darkMode", JSON.stringify(darkMode));
    document.documentElement.classList.toggle("dark", darkMode);
  }, [darkMode]);

  // Auto-resize textarea with LARGER max height
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 300) + 'px';
    }
  }, [input]);

  // Auto-scroll to newest message
  useEffect(() => {
    if (!showScrollButton) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [messages, loading, showScrollButton]);

  // Handle scroll position
  const handleScroll = useCallback(() => {
    const container = messagesContainerRef.current;
    if (container) {
      const { scrollTop, scrollHeight, clientHeight } = container;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 120;
      setShowScrollButton(!isNearBottom);
    }
  }, []);

  // Smooth scroll to bottom after answer is fully displayed
  const smoothScrollToBottom = useCallback(() => {
    if (messagesContainerRef.current) {
      const container = messagesContainerRef.current;
      const targetScroll = container.scrollHeight - container.clientHeight;
      const startScroll = container.scrollTop;
      const distance = targetScroll - startScroll;
      const duration = 1500;
      let startTime = null;
      
      const animateScroll = (currentTime) => {
        if (startTime === null) startTime = currentTime;
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        const easeInOut = progress < 0.5 
          ? 2 * progress * progress 
          : 1 - Math.pow(-2 * progress + 2, 2) / 2;
        
        container.scrollTop = startScroll + distance * easeInOut;
        
        if (progress < 1) {
          requestAnimationFrame(animateScroll);
        }
      };
      
      requestAnimationFrame(animateScroll);
    }
  }, []);

  const sendMessage = async (content = input) => {
    const trimmedInput = content.trim();

    if (!trimmedInput || loading) {
      return;
    }

    if (trimmedInput.length > 4000) {
      setMessages(prev => [
        ...prev,
        {
          role: "assistant",
          content: "⚠️ Your message exceeds the 4000 character limit. Please shorten it and try again.",
          timestamp: new Date().toISOString(),
          error: true,
        },
      ]);
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
    setThinkingWord(THINKING_WORDS[Math.floor(Math.random() * THINKING_WORDS.length)]);

    try {
      const apiMessages = updatedMessages
        .filter(
          (message) =>
            (message.role === "user" || message.role === "assistant") &&
            typeof message.content === "string"
        )
        .map(({ role, content }) => ({
          role,
          content: content.slice(0, 4000),
        }));

      const response = await fetch(`${API_URL}/api/chat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          messages: apiMessages,
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

      // Display full answer immediately (no typing reveal)
      setMessages(prev => [
        ...prev,
        {
          role: "assistant",
          content: data.reply,
          timestamp: new Date().toISOString(),
          visual: data.visual || null,
        },
      ]);

      setTimeout(() => {
        smoothScrollToBottom();
      }, 300);
      
    } catch (error) {
      setMessages(prev => [
        ...prev,
        {
          role: "assistant",
          content: `⚠️ ${
            error.message ||
            "Unable to connect to the AI server. Please check your connection or try again."
          }`,
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
    smoothScrollToBottom();
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
          style={{ 
            userSelect: 'text', 
            WebkitUserSelect: 'text', 
            cursor: 'text',
            overflowX: 'hidden',
            overflowY: 'auto',
            wordBreak: 'break-word',
            overflowWrap: 'break-word',
            maxWidth: '100%',
          }}
        >
          {messages.map((message, index) => (
            <div
              key={index}
              className={`message ${message.role} ${message.error ? 'error' : ''}`}
              style={{ 
                userSelect: 'text', 
                WebkitUserSelect: 'text',
                wordBreak: 'break-word',
                overflowWrap: 'break-word',
                maxWidth: '100%',
                boxSizing: 'border-box',
              }}
            >
              <div className="message-meta">
                <span className="message-author">
                  {message.role === "user" ? "YOU" : "AI"}
                </span>
                {message.timestamp && (
                  <span className="message-time">{formatTimestamp(message.timestamp)}</span>
                )}
              </div>

              <div 
                className="message-content" 
                style={{ 
                  userSelect: 'text', 
                  WebkitUserSelect: 'text', 
                  cursor: 'text',
                  wordBreak: 'break-word',
                  overflowWrap: 'break-word',
                  maxWidth: '100%',
                  boxSizing: 'border-box',
                }}
              >
                {message.role === "assistant" && !message.error ? (
                  <>
                    <div 
                      className="markdown-content" 
                      style={{ 
                        userSelect: 'text', 
                        WebkitUserSelect: 'text',
                        wordBreak: 'break-word',
                        overflowWrap: 'break-word',
                        maxWidth: '100%',
                        boxSizing: 'border-box',
                      }}
                    >
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
                          pre({ children }) {
                            return (
                              <pre style={{ 
                                userSelect: 'text', 
                                WebkitUserSelect: 'text',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word',
                                overflowWrap: 'break-word',
                                maxWidth: '100%',
                                boxSizing: 'border-box',
                                overflowX: 'auto',
                              }}>
                                {children}
                              </pre>
                            );
                          },
                          p({ children }) {
                            return (
                              <p style={{ 
                                wordBreak: 'break-word',
                                overflowWrap: 'break-word',
                                maxWidth: '100%',
                                boxSizing: 'border-box',
                              }}>
                                {children}
                              </p>
                            );
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
                  <div 
                    className="plain-message"
                    style={{ 
                      wordBreak: 'break-word',
                      overflowWrap: 'break-word',
                      maxWidth: '100%',
                      boxSizing: 'border-box',
                    }}
                  >
                    {message.content}
                  </div>
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

          {loading && (
            <div className="message assistant loading">
              <div className="message-meta">
                <span className="message-author">AI</span>
              </div>
              <div className="message-content">
                <div className="thinking-indicator">
                  <div className="thinking-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                  <span className="thinking-text">{thinkingWord}</span>
                </div>
              </div>
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
              rows="3"
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
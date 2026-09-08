import { useEffect, useRef, useState, useCallback } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";
import { Shield, Sun, Moon, Send, Copy, Check, RotateCcw, ArrowDown, Trash2, Sparkles } from "lucide-react";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

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

function useVisualViewport() {
  const [viewport, setViewport] = useState(() => ({
    height: typeof window !== 'undefined' && window.visualViewport 
      ? window.visualViewport.height 
      : window.innerHeight,
    keyboardOpen: false,
  }));

  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) {
      const handleResize = () => {
        setViewport({ height: window.innerHeight, keyboardOpen: false });
      };
      window.addEventListener('resize', handleResize);
      return () => window.removeEventListener('resize', handleResize);
    }

    let rafId = null;
    let lastHeight = vv.height;

    const handleViewportChange = () => {
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(() => {
        const heightDiff = Math.abs(vv.height - lastHeight);
        if (heightDiff < 2) return;
        lastHeight = vv.height;
        setViewport({
          height: vv.height,
          keyboardOpen: vv.height < window.innerHeight - 100,
        });
      });
    };

    vv.addEventListener('resize', handleViewportChange);
    vv.addEventListener('scroll', handleViewportChange);
    handleViewportChange();

    return () => {
      vv.removeEventListener('resize', handleViewportChange);
      vv.removeEventListener('scroll', handleViewportChange);
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, []);

  return viewport;
}

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
          <button className="code-copy-button" onClick={handleCopyCode} aria-label="Copy code">
            {copied ? <Check size={14} /> : <Copy size={14} />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
        <SyntaxHighlighter
          style={oneDark}
          language={match[1]}
          PreTag="div"
          customStyle={{ margin: 0, borderRadius: 0, fontSize: '13px', lineHeight: '1.5' }}
          {...props}
        >
          {code}
        </SyntaxHighlighter>
      </div>
    );
  }

  return <code className={`inline-code ${className || ''}`} {...props}>{children}</code>;
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
  const revealTimerRef = useRef(null);
  const isRevealingRef = useRef(false);
  const isNearBottomRef = useRef(true);
  const { viewportHeight, keyboardOpen } = useVisualViewport();

  const suggestedQuestions = [
    "How do I secure my AWS S3 buckets?",
    "What are the best practices for Kubernetes security?",
    "Explain IAM roles vs policies",
    "How to detect and respond to security incidents?",
    "What is a WAF and when should I use it?",
  ];

  useEffect(() => {
    if (loading) {
      const interval = setInterval(() => {
        setThinkingWord(prev => {
          const idx = THINKING_WORDS.indexOf(prev);
          return THINKING_WORDS[(idx + 1) % THINKING_WORDS.length];
        });
      }, 1500);
      return () => clearInterval(interval);
    }
  }, [loading]);

  useEffect(() => {
    localStorage.setItem("darkMode", JSON.stringify(darkMode));
    document.documentElement.classList.toggle("dark", darkMode);
  }, [darkMode]);

  useEffect(() => {
    const el = textareaRef.current;
    if (el) {
      el.style.height = 'auto';
      const maxHeight = window.innerWidth <= 600 ? 160 : 220;
      el.style.height = Math.min(el.scrollHeight, maxHeight) + 'px';
      el.style.overflowY = el.scrollHeight > maxHeight ? 'auto' : 'hidden';
    }
  }, [input]);

  useEffect(() => {
    return () => {
      if (revealTimerRef.current) clearTimeout(revealTimerRef.current);
      isRevealingRef.current = false;
    };
  }, []);

  const scrollToBottom = useCallback(() => {
    const container = messagesContainerRef.current;
    if (container) {
      container.scrollTop = container.scrollHeight;
    }
  }, []);

  const progressiveReveal = useCallback((fullMessage, messageIndex) => {
    if (revealTimerRef.current) clearTimeout(revealTimerRef.current);
    isRevealingRef.current = true;

    const words = fullMessage.split(' ');
    if (words.length <= 15) {
      setMessages(prev => {
        const updated = [...prev];
        updated[messageIndex] = { ...updated[messageIndex], content: fullMessage };
        return updated;
      });
      isRevealingRef.current = false;
      return;
    }

    const chunkSize = words.length > 300 ? 15 : words.length > 150 ? 10 : words.length > 50 ? 7 : 5;
    const delay = words.length > 300 ? 30 : words.length > 150 ? 40 : words.length > 50 ? 50 : 60;
    let currentIndex = 0;

    const revealChunk = () => {
      if (!isRevealingRef.current) return;

      currentIndex += chunkSize;
      const endIndex = Math.min(currentIndex, words.length);
      const revealedText = words.slice(0, endIndex).join(' ');

      setMessages(prev => {
        const updated = [...prev];
        updated[messageIndex] = { ...updated[messageIndex], content: revealedText };
        return updated;
      });

      if (isNearBottomRef.current) {
        const container = messagesContainerRef.current;
        if (container) container.scrollTop = container.scrollHeight;
      }

      if (endIndex < words.length) {
        revealTimerRef.current = setTimeout(revealChunk, delay);
      } else {
        isRevealingRef.current = false;
        revealTimerRef.current = null;
      }
    };

    revealTimerRef.current = setTimeout(revealChunk, delay);
  }, []);

  const handleScroll = useCallback(() => {
    const container = messagesContainerRef.current;
    if (container) {
      const { scrollTop, scrollHeight, clientHeight } = container;
      const nearBottom = scrollHeight - scrollTop - clientHeight < 100;
      isNearBottomRef.current = nearBottom;
      setShowScrollButton(!nearBottom);
    }
  }, []);

  const sendMessage = async (content = input) => {
    const trimmedInput = content.trim();

    if (!trimmedInput || loading) return;

    if (trimmedInput.length > 4000) {
      setMessages(prev => [...prev, {
        role: "assistant",
        content: "⚠️ Your message exceeds the 4000 character limit. Please shorten it and try again.",
        timestamp: new Date().toISOString(),
        error: true,
      }]);
      return;
    }

    if (revealTimerRef.current) clearTimeout(revealTimerRef.current);
    isRevealingRef.current = false;

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
    setThinkingWord(THINKING_WORDS[Math.floor(Math.random() * 10)]);
    isNearBottomRef.current = true;

    if (textareaRef.current) textareaRef.current.style.height = 'auto';

    try {
      const apiMessages = updatedMessages
        .filter(m => (m.role === "user" || m.role === "assistant") && typeof m.content === "string")
        .map(({ role, content: c }) => ({ role, content: c.slice(0, 4000) }));

      const response = await fetch(`${API_URL}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: apiMessages, conversationId }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "AI request failed");

      if (data.conversationId) setConversationId(data.conversationId);
      if (data.intents) setIntents(data.intents);

      const newIndex = updatedMessages.length;
      setMessages(prev => [...prev, {
        role: "assistant",
        content: "",
        timestamp: new Date().toISOString(),
        visual: data.visual || null,
      }]);

      progressiveReveal(data.reply, newIndex);
    } catch (error) {
      setMessages(prev => [...prev, {
        role: "assistant",
        content: `⚠️ ${error.message || "Unable to connect to the AI server. Please check your connection or try again."}`,
        timestamp: new Date().toISOString(),
        error: true,
      }]);
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
    if (revealTimerRef.current) clearTimeout(revealTimerRef.current);
    isRevealingRef.current = false;

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
    setMessages([{
      role: "assistant",
      content: "👋 Chat cleared! Ready for a new security question. What would you like to explore?",
      timestamp: new Date().toISOString(),
    }]);
  };

  const handleSuggestionClick = (suggestion) => {
    sendMessage(suggestion);
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
    if (revealTimerRef.current) clearTimeout(revealTimerRef.current);
    isRevealingRef.current = false;

    const lastUserMessage = [...messages].reverse().find(m => m.role === "user");
    if (lastUserMessage) {
      setMessages(prev => prev.filter(m => !m.error));
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
    <div className={`app ${darkMode ? 'dark' : ''}`} style={{ height: `${viewportHeight}px` }}>
      <header className="header">
        <div className="header-content">
          <div className="header-left">
            <Shield size={22} className="header-icon" />
            <div className="header-text">
              <h1 className="header-title">AI Security</h1>
              <p className="header-subtitle">Cloud Security • AWS • Azure • Kubernetes</p>
            </div>
          </div>
          <div className="header-actions">
            <button 
              className="icon-button" 
              onClick={() => setDarkMode(!darkMode)}
              aria-label={darkMode ? "Switch to light mode" : "Switch to dark mode"}
              title={darkMode ? "Light mode" : "Dark mode"}
            >
              {darkMode ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <button 
              className="icon-button" 
              onClick={clearChat}
              aria-label="Clear chat"
              title="Clear chat"
            >
              <Trash2 size={18} />
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
            <p className="suggestions-title">
              <Sparkles size={14} />
              Try asking about:
            </p>
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

              {message.role === "assistant" && !message.error && message.content && (
                <div className="message-actions">
                  <button
                    className="message-action-btn"
                    onClick={() => handleCopyMessage(message.content, index)}
                    aria-label="Copy response"
                  >
                    {copiedMessageId === index ? <Check size={14} /> : <Copy size={14} />}
                    <span>{copiedMessageId === index ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    className="message-action-btn"
                    onClick={handleRetry}
                    aria-label="Retry response"
                  >
                    <RotateCcw size={14} />
                    <span>Retry</span>
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
            <ArrowDown size={18} />
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
              <Send size={18} />
              <span>Send</span>
            </button>
          </div>
          <p className="composer-hint">
            Enter to send • Shift + Enter for new line • Markdown supported
          </p>
        </div>
      </main>
    </div>
  );
}

export default App;
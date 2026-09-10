import { useEffect, useRef, useState, useCallback, memo } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";
import {
  Shield,
  Sun,
  Moon,
  Send,
  Square,
  Copy,
  Check,
  RotateCcw,
  ArrowDown,
  Plus,
  Search,
  Lock,
  Terminal,
  ClipboardCheck,
  LifeBuoy,
  ShieldCheck,
} from "lucide-react";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:5000";

const THINKING_WORDS = [
  "Analyzing your question...",
  "Reviewing relevant security patterns...",
  "Working through the analysis...",
  "Preparing a practical answer...",
  "Evaluating risks and mitigations...",
  "Structuring a clear response...",
];

const INITIAL_GREETING =
  "Hello. I'm your AI Security Assistant. I can help with cybersecurity, cloud and application security, identity, incident response, digital privacy, and everyday safety. What would you like to explore?";

const CLEARED_GREETING =
  "Chat cleared. Ready for a new security or safety question.";

/**
 * Safe Markdown normalization — only fixes artifacts, never touches code blocks.
 */
function normalizeMarkdown(text) {
  if (!text || typeof text !== "string") return text;

  const lines = text.split("\n");
  const result = [];
  let inCodeBlock = false;

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      inCodeBlock = !inCodeBlock;
      result.push(line);
      continue;
    }

    if (inCodeBlock) {
      result.push(line);
      continue;
    }

    let cleaned = line;
    cleaned = cleaned.replace(/svgCopy$/, "");
    cleaned = cleaned.replace(/&lt;br&gt;/gi, "");
    cleaned = cleaned.replace(/<br\s*\/?>/gi, "");
    result.push(cleaned);
  }

  return result.join("\n");
}

/**
 * Build a fresh greeting/system message. The `init-` id prefix is what the
 * empty-state detector uses to distinguish a genuinely new conversation.
 */
function buildGreetingMessage(content = INITIAL_GREETING) {
  return {
    id: "init-" + Date.now(),
    role: "assistant",
    displayContent: content,
    fullContent: content,
    timestamp: new Date().toISOString(),
  };
}

function useVisualViewport() {
  const [viewport, setViewport] = useState(() => ({
    height:
      typeof window !== "undefined" && window.visualViewport
        ? window.visualViewport.height
        : typeof window !== "undefined"
        ? window.innerHeight
        : 800,
    keyboardOpen: false,
  }));

  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) {
      const handleResize = () =>
        setViewport({ height: window.innerHeight, keyboardOpen: false });
      window.addEventListener("resize", handleResize);
      return () => window.removeEventListener("resize", handleResize);
    }

    let rafId = null;
    let lastHeight = vv.height;

    const handleViewportChange = () => {
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(() => {
        if (Math.abs(vv.height - lastHeight) < 2) return;
        lastHeight = vv.height;
        setViewport({
          height: vv.height,
          keyboardOpen: vv.height < window.innerHeight - 100,
        });
      });
    };

    vv.addEventListener("resize", handleViewportChange);
    vv.addEventListener("scroll", handleViewportChange);
    handleViewportChange();

    return () => {
      vv.removeEventListener("resize", handleViewportChange);
      vv.removeEventListener("scroll", handleViewportChange);
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, []);

  return viewport;
}

/* --------------------------------------------------------------------------
   Static suggestion card definitions — hoisted out of App()
   -------------------------------------------------------------------------- */

const SUGGESTION_CARDS = [
  {
    icon: Search,
    title: "Investigate a threat",
    description: "Analyze suspicious activity or an incident",
    prompt:
      "Help me investigate a suspicious security incident. What information do you need and how should I approach the analysis?",
  },
  {
    icon: Lock,
    title: "Secure my system",
    description: "Find practical ways to reduce security risk",
    prompt:
      "What are the most effective steps I can take to reduce security risk on a system I manage?",
  },
  {
    icon: Terminal,
    title: "Write a detection",
    description: "Create a KQL, Sigma, YARA, or detection rule",
    prompt:
      "Help me write a detection rule. Suggest the right format (KQL, Sigma, YARA, or similar) and explain the logic.",
  },
  {
    icon: ClipboardCheck,
    title: "Review security",
    description: "Assess a configuration, architecture, or control",
    prompt:
      "Help me review a security configuration or architecture. What should I be evaluating and what common weaknesses should I look for?",
  },
  {
    icon: ShieldCheck,
    title: "Respond to an incident",
    description: "Build a step-by-step response plan",
    prompt:
      "Help me build a step-by-step incident response plan. What should I do first, and how should I structure the response?",
  },
  {
    icon: LifeBuoy,
    title: "Stay safe",
    description: "Practical digital, privacy, or personal safety guidance",
    prompt:
      "What practical steps can I take to stay safe online and protect my personal data?",
  },
];

/* --------------------------------------------------------------------------
   CodeBlock
   -------------------------------------------------------------------------- */

const CodeBlock = memo(function CodeBlock({
  inline,
  className,
  children,
  ...props
}) {
  const [copied, setCopied] = useState(false);
  const match = /language-(\w+)/.exec(className || "");
  const code = String(children).replace(/\n$/, "");

  const handleCopyCode = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error("Failed to copy code:", error);
    }
  }, [code]);

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
            {copied ? <Check size={13} /> : <Copy size={13} />}
            <span>{copied ? "Copied" : "Copy"}</span>
          </button>
        </div>
        <SyntaxHighlighter
          style={oneDark}
          language={match[1]}
          PreTag="div"
          customStyle={{
            margin: 0,
            borderRadius: 0,
            fontSize: "14.5px",
            lineHeight: "1.65",
            maxWidth: "none",
          }}
          {...props}
        >
          {code}
        </SyntaxHighlighter>
      </div>
    );
  }

  return (
    <code className={`inline-code ${className || ""}`} {...props}>
      {children}
    </code>
  );
});

/* --------------------------------------------------------------------------
   MessageItem
   -------------------------------------------------------------------------- */

const MessageItem = memo(function MessageItem({
  message,
  index,
  copiedMessageId,
  onCopy,
  onRetry,
}) {
  const isUser = message.role === "user";
  const formatTime = (ts) =>
    new Date(ts).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });

  return (
    <div
      className={`message ${isUser ? "user" : "assistant"} ${
        message.isError ? "error" : ""
      }`}
    >
      <div className="message-meta">
        {!isUser && (
          <Shield size={13} className="message-author-icon" aria-hidden="true" />
        )}
        <span className="message-author">{isUser ? "YOU" : "AI"}</span>
        {message.timestamp && (
          <span className="message-time">{formatTime(message.timestamp)}</span>
        )}
      </div>

      <div className="message-content">
        {!isUser && !message.isError ? (
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
                    return <blockquote>{children}</blockquote>;
                  },
                }}
              >
                {message.displayContent}
              </ReactMarkdown>
            </div>

            {message.visual && message.visual.needed && (
              <div className="visual-card">
                <div className="visual-card-header">
                  <span className="visual-icon">📊</span>
                  <span>Visual Learning</span>
                </div>
                <div className="visual-card-body">
                  <div className="visual-placeholder">
                    <div className="placeholder-icon">🔍</div>
                    <p>Security diagram</p>
                    <span>
                      Interactive architecture and attack-flow visualizations can
                      appear here.
                    </span>
                  </div>
                </div>
                {message.visual.query && (
                  <div className="visual-card-footer">
                    <span>Topic: {message.visual.query}</span>
                  </div>
                )}
              </div>
            )}

            {message.metadata && (
              <div className="metadata-footer">
                <span className="metadata-provider">
                  Generated in{" "}
                  {(message.metadata.responseTimeMs / 1000).toFixed(1)}s
                </span>
              </div>
            )}
          </>
        ) : (
          <div className="plain-message">{message.displayContent}</div>
        )}
      </div>

      {!isUser && !message.isError && message.fullContent && (
        <div className="message-actions">
          <button
            className="message-action-btn"
            onClick={() => onCopy(message.fullContent, index)}
            aria-label="Copy response"
            title="Copy response"
          >
            {copiedMessageId === index ? (
              <Check size={13} />
            ) : (
              <Copy size={13} />
            )}
          </button>
          <button
            className="message-action-btn"
            onClick={onRetry}
            aria-label="Retry response"
            title="Retry"
          >
            <RotateCcw size={13} />
          </button>
        </div>
      )}

      {message.isError && (
        <div className="message-actions visible">
          <button
            className="message-action-btn error"
            onClick={onRetry}
            aria-label="Try again"
          >
            <RotateCcw size={13} />
            <span>Try Again</span>
          </button>
        </div>
      )}
    </div>
  );
});

/* --------------------------------------------------------------------------
   App
   -------------------------------------------------------------------------- */

function App() {
  const [messages, setMessages] = useState(() => [buildGreetingMessage()]);
  const [input, setInput] = useState("");
  const [isRequesting, setIsRequesting] = useState(false);
  const [thinkingWord, setThinkingWord] = useState(THINKING_WORDS[0]);
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem("darkMode");
    return saved
      ? JSON.parse(saved)
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
  });
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [intents, setIntents] = useState([]);
  const [copiedMessageId, setCopiedMessageId] = useState(null);
  const [conversationId, setConversationId] = useState(null);

  const textareaRef = useRef(null);
  const messagesContainerRef = useRef(null);
  const scrollStateRef = useRef({ isNearBottom: true });
  const requestAbortRef = useRef(null);

  const { height: viewportHeight } = useVisualViewport();

  const isEmptyState =
    messages.length === 1 &&
    messages[0]?.role === "assistant" &&
    typeof messages[0]?.id === "string" &&
    messages[0].id.startsWith("init-");

  /* ---------- Effects ---------- */

  useEffect(() => {
    if (!isRequesting) return;
    const interval = setInterval(() => {
      setThinkingWord(
        (prev) =>
          THINKING_WORDS[
            (THINKING_WORDS.indexOf(prev) + 1) % THINKING_WORDS.length
          ]
      );
    }, 2500);
    return () => clearInterval(interval);
  }, [isRequesting]);

  useEffect(() => {
    localStorage.setItem("darkMode", JSON.stringify(darkMode));
    document.documentElement.classList.toggle("dark", darkMode);
  }, [darkMode]);

  useEffect(() => {
    const el = textareaRef.current;
    if (el) {
      el.style.height = "auto";
      const maxHeight = window.innerWidth <= 600 ? 180 : 220;
      el.style.height = Math.min(el.scrollHeight, maxHeight) + "px";
      el.style.overflowY = el.scrollHeight > maxHeight ? "auto" : "hidden";
    }
  }, [input]);

  useEffect(() => {
    return () => {
      if (requestAbortRef.current) requestAbortRef.current.abort();
    };
  }, []);

  /* ---------- Scroll ---------- */

  const scrollToBottom = useCallback(() => {
    const container = messagesContainerRef.current;
    if (container) {
      container.scrollTop = container.scrollHeight;
      scrollStateRef.current.isNearBottom = true;
    }
  }, []);

  const handleScroll = useCallback(() => {
    const container = messagesContainerRef.current;
    if (!container) return;
    const { scrollTop, scrollHeight, clientHeight } = container;
    const nearBottom = scrollHeight - scrollTop - clientHeight < 100;
    scrollStateRef.current.isNearBottom = nearBottom;
    setShowScrollButton(!nearBottom);
  }, []);

  /* ---------- Shared request runner ---------- */

  const runChatRequest = useCallback(
    async (apiMessages) => {
      if (requestAbortRef.current) requestAbortRef.current.abort();
      const controller = new AbortController();
      requestAbortRef.current = controller;

      setIsRequesting(true);
      setThinkingWord(THINKING_WORDS[0]);
      scrollStateRef.current.isNearBottom = true;

      try {
        const response = await fetch(`${API_URL}/api/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ messages: apiMessages, conversationId }),
          signal: controller.signal,
        });

        if (!response.ok) {
          const data = await response.json().catch(() => ({}));
          throw new Error(data.error || `HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.conversationId) setConversationId(data.conversationId);
        if (data.intents) setIntents(data.intents);

        const normalizedReply = normalizeMarkdown(data.reply);

        setMessages((prev) => [
          ...prev,
          {
            id: "assistant-" + Date.now(),
            role: "assistant",
            displayContent: normalizedReply,
            fullContent: normalizedReply,
            timestamp: new Date().toISOString(),
            visual: data.visual || null,
            metadata: data.metadata,
          },
        ]);

        if (scrollStateRef.current.isNearBottom) {
          setTimeout(scrollToBottom, 50);
        }
      } catch (error) {
        if (error.name === "AbortError") return;

        setMessages((prev) => [
          ...prev,
          {
            id: "error-" + Date.now(),
            role: "assistant",
            displayContent: `⚠️ ${
              error.message ||
              "Unable to reach the AI service. Please try again."
            }`,
            fullContent: `⚠️ ${
              error.message ||
              "Unable to reach the AI service. Please try again."
            }`,
            timestamp: new Date().toISOString(),
            isError: true,
          },
        ]);
      } finally {
        if (requestAbortRef.current === controller) {
          requestAbortRef.current = null;
        }
        setIsRequesting(false);
      }
    },
    [conversationId, scrollToBottom]
  );

  /* ---------- Send ---------- */

  const sendMessage = useCallback(
    async (content = input) => {
      const trimmedInput = content.trim();
      if (!trimmedInput || isRequesting) return;

      if (trimmedInput.length > 4000) {
        setMessages((prev) => [
          ...prev,
          {
            id: "error-" + Date.now(),
            role: "assistant",
            displayContent: "⚠️ Your message exceeds the 4000 character limit.",
            fullContent: "⚠️ Your message exceeds the 4000 character limit.",
            timestamp: new Date().toISOString(),
            isError: true,
          },
        ]);
        return;
      }

      const userMessage = {
        id: "user-" + Date.now(),
        role: "user",
        displayContent: trimmedInput,
        fullContent: trimmedInput,
        timestamp: new Date().toISOString(),
      };

      const updatedMessages = [...messages, userMessage];
      setMessages(updatedMessages);
      setInput("");
      setIntents([]);
      if (textareaRef.current) textareaRef.current.style.height = "auto";

      const apiMessages = updatedMessages
        .filter(
          (m) =>
            (m.role === "user" || m.role === "assistant") &&
            typeof m.fullContent === "string"
        )
        .map(({ role, fullContent: c }) => ({
          role,
          content: c.slice(0, 4000),
        }));

      await runChatRequest(apiMessages);
    },
    [input, isRequesting, messages, runChatRequest]
  );

  /* ---------- Stop ---------- */

  const handleStop = useCallback(() => {
    if (requestAbortRef.current) {
      requestAbortRef.current.abort();
      requestAbortRef.current = null;
    }
    setIsRequesting(false);
  }, []);

  /* ---------- Keyboard ---------- */

  const handleKeyDown = useCallback(
    (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
      }
    },
    [sendMessage]
  );

  /* ---------- Clear / New chat ---------- */

  const clearChat = useCallback(async () => {
    if (requestAbortRef.current) requestAbortRef.current.abort();
    requestAbortRef.current = null;
    setIsRequesting(false);

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
    setMessages([buildGreetingMessage(CLEARED_GREETING)]);
  }, [conversationId]);

  /* ---------- Suggestions ---------- */

  const handleSuggestionClick = useCallback(
    (suggestion) => {
      sendMessage(suggestion);
    },
    [sendMessage]
  );

  /* ---------- Copy ---------- */

  const handleCopyMessage = useCallback(async (content, index) => {
    try {
      await navigator.clipboard.writeText(content);
      setCopiedMessageId(index);
      setTimeout(() => setCopiedMessageId(null), 2000);
    } catch (error) {
      console.error("Failed to copy:", error);
    }
  }, []);

  /* ---------- Retry ---------- */

  const handleRetry = useCallback(() => {
    if (requestAbortRef.current) requestAbortRef.current.abort();
    requestAbortRef.current = null;
    setIsRequesting(false);

    const lastUserIndex = [...messages]
      .reverse()
      .findIndex((m) => m.role === "user");
    if (lastUserIndex === -1) return;

    const actualIndex = messages.length - 1 - lastUserIndex;
    const lastUserMessage = messages[actualIndex];

    const historyBeforeUser = messages.slice(0, actualIndex);
    const userMsg = { ...lastUserMessage };
    const cleanHistory = historyBeforeUser.filter((m) => !m.isError);
    const newMessages = [...cleanHistory, userMsg];
    setMessages(newMessages);

    const apiMessages = newMessages
      .filter(
        (m) =>
          (m.role === "user" || m.role === "assistant") &&
          typeof m.fullContent === "string"
      )
      .map(({ role, fullContent: c }) => ({
        role,
        content: c.slice(0, 4000),
      }));

    runChatRequest(apiMessages);
  }, [messages, runChatRequest]);

  return (
    <div
      className={`app ${darkMode ? "dark" : ""}`}
      style={{ height: `${viewportHeight}px` }}
    >
      <header className="header">
        <div className="header-content">
          <div className="header-brand">
            <div className="header-icon-container">
              <Shield size={18} strokeWidth={2.25} />
            </div>
            <div className="header-text">
              <div className="header-title-row">
                <h1 className="header-title">
                  <span className="header-title-gradient">
                    Lakewest AI Security Assistant
                  </span>
                </h1>
                <span className="header-status">
                  <span className="status-dot" />
                  Ready
                </span>
              </div>
              <p className="header-subtitle">Security &amp; Safety Copilot</p>
            </div>
          </div>

          <div className="header-actions">
            <button
              className="new-chat-button"
              onClick={clearChat}
              aria-label="Start new chat"
            >
              <Plus size={16} />
              <span className="new-chat-label">New Chat</span>
            </button>
            <button
              className="icon-button"
              onClick={() => setDarkMode(!darkMode)}
              aria-label="Toggle theme"
              title="Toggle theme"
            >
              {darkMode ? <Sun size={18} /> : <Moon size={18} />}
            </button>
          </div>
        </div>
      </header>

      {intents.length > 0 && (
        <div className="intent-badges">
          <span className="intent-badges-label">Security context:</span>
          {intents.map((intent) => (
            <span key={intent} className="intent-badge">
              {intent.replace(/_/g, " ")}
            </span>
          ))}
        </div>
      )}

      <main className="chat-container">
        <div
          className={`messages ${isEmptyState ? "messages--empty" : ""}`}
          ref={messagesContainerRef}
          onScroll={handleScroll}
          role="log"
          aria-live="polite"
          aria-label="Chat messages"
        >
          {isEmptyState ? (
            <div className="empty-state">
              <div className="empty-state-icon">
                <Shield size={22} strokeWidth={2} />
              </div>
              <p className="empty-state-eyebrow">AI Security Assistant</p>
              <h2 className="empty-state-title">
                How can I help you stay secure?
              </h2>
              <p className="empty-state-description">
                Ask about threats, security, privacy, incidents, systems,
                applications, or everyday safety.
              </p>

              <div className="suggestion-grid">
                {SUGGESTION_CARDS.map((card) => {
                  const Icon = card.icon;
                  return (
                    <button
                      key={card.title}
                      type="button"
                      className="suggestion-card"
                      onClick={() => handleSuggestionClick(card.prompt)}
                    >
                      <span className="suggestion-card-icon">
                        <Icon size={18} />
                      </span>
                      <span className="suggestion-card-body">
                        <span className="suggestion-card-title">
                          {card.title}
                        </span>
                        <span className="suggestion-card-desc">
                          {card.description}
                        </span>
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            messages.map((message, index) => (
              <MessageItem
                key={message.id}
                message={message}
                index={index}
                copiedMessageId={copiedMessageId}
                onCopy={handleCopyMessage}
                onRetry={handleRetry}
              />
            ))
          )}

          {isRequesting && (
            <div className="message assistant loading">
              <div className="message-meta">
                <Shield
                  size={13}
                  className="message-author-icon"
                  aria-hidden="true"
                />
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
          <div className="composer-inner">
            <div className="composer-box">
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(event) => setInput(event.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about security or safety..."
                rows="1"
                disabled={isRequesting}
                aria-label="Message input"
                maxLength={4000}
              />
              {isRequesting ? (
                <button
                  className="stop-button"
                  onClick={handleStop}
                  aria-label="Stop generation"
                >
                  <Square size={18} />
                </button>
              ) : (
                <button
                  className="send-button"
                  onClick={() => sendMessage()}
                  disabled={!input.trim()}
                  aria-label="Send message"
                >
                  <Send size={18} />
                </button>
              )}
            </div>
            <p className="composer-hint">
              Enter to send · Shift + Enter for newline
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
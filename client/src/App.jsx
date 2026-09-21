import {
  useEffect,
  useRef,
  useState,
  useCallback,
  memo,
} from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  Prism as SyntaxHighlighter,
} from "react-syntax-highlighter";
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
  ShieldAlert,
  Wrench,
  Target,
  Tag,
  Activity,
  Eye,
  Gauge,
  Link2,
  GitCompare,
  Building2,
  LayoutGrid,
  Info,
  ListTodo,
  Flag,
  Crosshair,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Clock,
  ListChecks,
  Radar,
  X,
  Minimize2,
  FileText,
} from "lucide-react";

import "./App.css";

/* ==========================================================================
   CONFIGURATION
   ========================================================================== */

const API_URL =
  import.meta.env.VITE_API_URL ||
  "http://localhost:5000";

const SCROLL_BOTTOM_THRESHOLD = 48;

const THINKING_WORDS = [
  "Analyzing your question...",
  "Reviewing relevant security patterns...",
  "Working through the analysis...",
  "Preparing a practical answer...",
  "Evaluating risks and mitigations...",
  "Structuring a clear response...",
];

const AGENT_THINKING_WORDS = [
  "Investigating with security tools...",
  "Querying threat intelligence...",
  "Correlating indicators...",
  "Checking reputation data...",
  "Analyzing security evidence...",
  "Preparing investigation summary...",
];

const INITIAL_GREETING =
  "Hello. I'm your AI Security Assistant. I can help with cybersecurity, cloud and application security, identity, incident response, digital privacy, and everyday safety. What would you like to explore?";

const CLEARED_GREETING =
  "Chat cleared. Ready for a new security or safety question.";

/* ==========================================================================
   AGENT ROUTING
   ========================================================================== */

const IPV4_REGEX =
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

const IPV6_REGEX =
  /\b(?:[a-f0-9]{1,4}:){2,}[a-f0-9]{1,4}\b/i;

const DOMAIN_REGEX =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/i;

const AGENT_TRIGGER_WORDS = [
  "investigate",
  "analyze this ip",
  "analyze this domain",
  "analyze this host",
  "look up",
  "lookup",
  "threat intel",
  "threat intelligence",
  "reputation",
  "virustotal",
  "whois",
  "shodan",
  "abuseipdb",
  "indicator of compromise",
  "ioc",
  "c2 server",
  "command and control",
];

function shouldUseAgent(text) {
  if (!text || typeof text !== "string") {
    return false;
  }

  const lower = text.toLowerCase();

  if (
    AGENT_TRIGGER_WORDS.some((word) =>
      lower.includes(word)
    )
  ) {
    return true;
  }

  if (IPV4_REGEX.test(text)) {
    return true;
  }

  if (IPV6_REGEX.test(text)) {
    return true;
  }

  if (DOMAIN_REGEX.test(text)) {
    const match = text.match(DOMAIN_REGEX);

    if (
      match &&
      match[0].includes(".") &&
      !match[0]
        .toLowerCase()
        .endsWith(".json")
    ) {
      if (
        text.trim().split(/\s+/).length <=
        8
      ) {
        return true;
      }
    }
  }

  return false;
}

/* ==========================================================================
   MARKDOWN NORMALIZATION
   ========================================================================== */

function normalizeMarkdown(text) {
  if (!text || typeof text !== "string") {
    return text;
  }

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

    cleaned = cleaned.replace(
      /svgCopy$/,
      ""
    );

    cleaned = cleaned.replace(
      /<br>/gi,
      ""
    );

    cleaned = cleaned.replace(
      /<br\s*\/?>/gi,
      ""
    );

    result.push(cleaned);
  }

  return result.join("\n");
}

/* ==========================================================================
   REMOVE UNWANTED SCHEMA LABELS
   ========================================================================== */

const SCHEMA_LABELS = [
  "WHY IT MATTERS FOR AN S3 BUCKET",
  "WHY IT MATTERS",
  "WHAT IT MEANS FOR AN S3 BUCKET",
  "WHAT IT MEANS FOR S3",
  "WHAT IT MEANS",
  "WHEN YOU NEED IT",
  "WHEN TO USE IT",
  "HOW TO CREATE (CONSOLE)",
  "HOW TO CREATE",
  "HOW TO CONFIGURE",
  "WHAT IT IS",
  "WHY IT EXISTS",
  "OBJECT",
  "FEATURE",
  "CONCEPT",
  "ACTION",
  "RESULT",
  "DESCRIPTION",
  "OVERVIEW",
];

function stripSchemaLabels(text) {
  if (!text || typeof text !== "string") {
    return text;
  }

  const escapeRegex = (value) =>
    value.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&"
    );

  const labelAlternation = SCHEMA_LABELS
    .map(escapeRegex)
    .join("|");

  const standaloneLabel = new RegExp(
    `^(#{1,6}\\s+|[-*+]\\s+|\\*\\*\\s*)?(${labelAlternation})\\s*:?\\s*(\\*\\*)?\\s*$`,
    "i"
  );

  const lines = text.split("\n");
  const output = [];
  let inCodeBlock = false;

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      inCodeBlock = !inCodeBlock;
      output.push(line);
      continue;
    }

    if (inCodeBlock) {
      output.push(line);
      continue;
    }

    if (standaloneLabel.test(line.trim())) {
      continue;
    }

    output.push(line);
  }

  return output
    .join("\n")
    .replace(/\n{3,}/g, "\n\n");
}

/* ==========================================================================
   GREETING
   ========================================================================== */

function buildGreetingMessage(
  content = INITIAL_GREETING
) {
  return {
    id: `init-${Date.now()}`,
    role: "assistant",
    displayContent: content,
    fullContent: content,
    timestamp: new Date().toISOString(),
  };
}

/* ==========================================================================
   VISUAL VIEWPORT
   ========================================================================== */

function useVisualViewport() {
  const [viewport, setViewport] =
    useState(() => {
      if (typeof window === "undefined") {
        return {
          height: 800,
          keyboardOpen: false,
        };
      }

      const visualViewport =
        window.visualViewport;

      return {
        height:
          visualViewport?.height ||
          window.innerHeight,
        keyboardOpen: false,
      };
    });

  useEffect(() => {
    if (typeof window === "undefined") {
      return undefined;
    }

    const visualViewport =
      window.visualViewport;

    if (!visualViewport) {
      const handleResize = () => {
        setViewport({
          height: window.innerHeight,
          keyboardOpen: false,
        });
      };

      window.addEventListener(
        "resize",
        handleResize
      );

      return () => {
        window.removeEventListener(
          "resize",
          handleResize
        );
      };
    }

    let rafId = null;

    const updateViewport = () => {
      if (rafId) {
        cancelAnimationFrame(rafId);
      }

      rafId = requestAnimationFrame(() => {
        const height =
          visualViewport.height;

        const keyboardOpen =
          height <
          window.innerHeight - 120;

        setViewport({
          height,
          keyboardOpen,
        });
      });
    };

    updateViewport();

    visualViewport.addEventListener(
      "resize",
      updateViewport
    );

    visualViewport.addEventListener(
      "scroll",
      updateViewport
    );

    window.addEventListener(
      "orientationchange",
      updateViewport
    );

    return () => {
      visualViewport.removeEventListener(
        "resize",
        updateViewport
      );

      visualViewport.removeEventListener(
        "scroll",
        updateViewport
      );

      window.removeEventListener(
        "orientationchange",
        updateViewport
      );

      if (rafId) {
        cancelAnimationFrame(rafId);
      }
    };
  }, []);

  return viewport;
}

/* ==========================================================================
   SUGGESTIONS
   ========================================================================== */

const SUGGESTION_CARDS = [
  {
    icon: Search,
    title: "Investigate a threat",
    description:
      "Analyze suspicious activity, an IP, or a domain",
    prompt:
      "Investigate this IP: 185.220.101.34",
  },
  {
    icon: Lock,
    title: "Secure my system",
    description:
      "Find practical ways to reduce security risk",
    prompt:
      "What are the most effective steps I can take to reduce security risk on a system I manage?",
  },
  {
    icon: Terminal,
    title: "Write a detection",
    description:
      "Create a KQL, Sigma, YARA, or detection rule",
    prompt:
      "Help me write a detection rule. Suggest the right format and explain the logic.",
  },
  {
    icon: ClipboardCheck,
    title: "Review security",
    description:
      "Assess a configuration, architecture, or control",
    prompt:
      "Help me review a security configuration or architecture. What should I evaluate?",
  },
  {
    icon: ShieldCheck,
    title: "Respond to an incident",
    description:
      "Build a step-by-step response plan",
    prompt:
      "Help me build a step-by-step incident response plan.",
  },
  {
    icon: LifeBuoy,
    title: "Stay safe",
    description:
      "Practical digital, privacy, or personal safety guidance",
    prompt:
      "What practical steps can I take to stay safe online and protect my personal data?",
  },
];

/* ==========================================================================
   NODE TO TEXT
   ========================================================================== */

function nodeToText(node) {
  if (
    node === null ||
    node === undefined ||
    node === false
  ) {
    return "";
  }

  if (
    typeof node === "string" ||
    typeof node === "number"
  ) {
    return String(node);
  }

  if (Array.isArray(node)) {
    return node
      .map(nodeToText)
      .join("");
  }

  if (
    typeof node === "object" &&
    node.props
  ) {
    return nodeToText(
      node.props.children
    );
  }

  return "";
}

/* ==========================================================================
   REPORT FORMATTING
   ========================================================================== */

const LEVEL_TONE = {
  low: "tone-good",
  none: "tone-good",
  moderate: "tone-warn",
  medium: "tone-warn",
  partial: "tone-warn",
  high: "tone-bad",
  elevated: "tone-bad",
  critical: "tone-bad",
  severe: "tone-bad",
  unknown: "tone-neutral",
};

const SOURCE_STATUS_TONE = {
  success: "tone-good",
  completed: "tone-good",
  timeout: "tone-warn",
  rate_limited: "tone-warn",
  "rate limited": "tone-warn",
  partial: "tone-warn",
  unauthorized: "tone-bad",
  unavailable: "tone-bad",
  error: "tone-bad",
  skipped: "tone-neutral",
};

const TONE_ICON = {
  "tone-good": CheckCircle2,
  "tone-warn": AlertTriangle,
  "tone-bad": XCircle,
  "tone-neutral": HelpCircle,
};

const SOURCE_LINE_RE_ICON_FIRST =
  /^([✓⚠])\s*([A-Za-z0-9][\w .+-]*?)\s*[—-]\s*([A-Za-z][\w ]*)$/;

const SOURCE_LINE_RE_NAME_FIRST =
  /^([A-Za-z0-9][\w .+-]*?)\s*:\s*([✓⚠])\s*([A-Za-z][\w ]*)$/;

const CONFIDENCE_LINE_RE =
  /^([A-Za-z][\w ]*confidence)\s*:\s*(low|moderate|medium|high|elevated|critical|unknown|none)\s*$/i;

const BARE_LEVEL_RE =
  /^(low|moderate|medium|high|elevated|critical|unknown|none|partial)$/i;

const KEY_VALUE_LINE_RE =
  /^([A-Za-z][\w .]{1,40}?)\s*:\s*(.+)$/;

/* ==========================================================================
   FORMATTING HELPERS
   ========================================================================== */

function tryFormatEpoch(value) {
  if (!/^\d{9,13}$/.test(value.trim())) {
    return null;
  }

  const trimmed = value.trim();
  const num = Number(trimmed);

  const milliseconds =
    trimmed.length >= 12
      ? num
      : num * 1000;

  const date = new Date(
    milliseconds
  );

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  if (
    date.getFullYear() < 2000 ||
    date.getFullYear() > 2100
  ) {
    return null;
  }

  try {
    return new Intl.DateTimeFormat(
      undefined,
      {
        dateStyle: "medium",
        timeStyle: "short",
      }
    ).format(date);
  } catch {
    return null;
  }
}

function tryFormatInteger(value) {
  const trimmed = value.trim();

  if (!/^-?\d{4,}$/.test(trimmed)) {
    return null;
  }

  const num = Number(trimmed);

  if (!Number.isFinite(num)) {
    return null;
  }

  try {
    return new Intl.NumberFormat(
      undefined
    ).format(num);
  } catch {
    return null;
  }
}

/* ==========================================================================
   STATUS PILL
   ========================================================================== */

function StatusPill({
  tone,
  children,
}) {
  const Icon =
    TONE_ICON[tone] ||
    HelpCircle;

  return (
    <span
      className={`status-pill ${tone}`}
    >
      <Icon
        size={13}
        strokeWidth={2.4}
        aria-hidden="true"
      />

      {children}
    </span>
  );
}

/* ==========================================================================
   SOURCE LINE
   ========================================================================== */

function renderSourceLine(text) {
  const iconFirst = text.match(
    SOURCE_LINE_RE_ICON_FIRST
  );

  if (iconFirst) {
    const [
      ,
      icon,
      provider,
      statusWord,
    ] = iconFirst;

    const key =
      statusWord
        .trim()
        .toLowerCase();

    const tone =
      SOURCE_STATUS_TONE[key] ||
      (icon === "✓"
        ? "tone-good"
        : "tone-bad");

    return (
      <span className="report-line">
        <StatusPill tone={tone}>
          {statusWord.trim()}
        </StatusPill>

        <span className="report-line-label">
          {provider.trim()}
        </span>
      </span>
    );
  }

  const nameFirst = text.match(
    SOURCE_LINE_RE_NAME_FIRST
  );

  if (nameFirst) {
    const [
      ,
      provider,
      icon,
      statusWord,
    ] = nameFirst;

    const key =
      statusWord
        .trim()
        .toLowerCase();

    const tone =
      SOURCE_STATUS_TONE[key] ||
      (icon === "✓"
        ? "tone-good"
        : "tone-bad");

    return (
      <span className="report-line">
        <span className="report-line-label">
          {provider.trim()}
        </span>

        <StatusPill tone={tone}>
          {statusWord.trim()}
        </StatusPill>
      </span>
    );
  }

  return null;
}

/* ==========================================================================
   CONFIDENCE LINE
   ========================================================================== */

function renderConfidenceLine(text) {
  const match = text.match(
    CONFIDENCE_LINE_RE
  );

  if (!match) {
    return null;
  }

  const [, label, level] =
    match;

  const tone =
    LEVEL_TONE[
      level.toLowerCase()
    ] ||
    "tone-neutral";

  return (
    <span className="report-line">
      <span className="report-line-label">
        {label.trim()}
      </span>

      <StatusPill tone={tone}>
        {level.trim()}
      </StatusPill>
    </span>
  );
}

/* ==========================================================================
   BARE LEVEL
   ========================================================================== */

function renderBareLevel(text) {
  if (!BARE_LEVEL_RE.test(text)) {
    return null;
  }

  const tone =
    LEVEL_TONE[
      text.toLowerCase()
    ] ||
    "tone-neutral";

  return (
    <StatusPill tone={tone}>
      {text}
    </StatusPill>
  );
}

/* ==========================================================================
   KEY/VALUE EVIDENCE
   ========================================================================== */

function renderKeyValueLine(text) {
  const match = text.match(
    KEY_VALUE_LINE_RE
  );

  if (!match) {
    return null;
  }

  const [, rawKey, rawValue] =
    match;

  const key = rawKey.trim();
  const value = rawValue.trim();

  if (!value) {
    return null;
  }

  const looksStructured =
    /^[{[]/.test(value) ||
    value.length > 90;

  const formattedDate =
    tryFormatEpoch(value);

  const formattedNumber =
    !formattedDate
      ? tryFormatInteger(value)
      : null;

  return (
    <span className="kv-line">
      <span className="kv-line-key">
        {key}
      </span>

      {looksStructured ? (
        <code className="kv-line-value kv-line-value--block">
          {value}
        </code>
      ) : (
        <span className="kv-line-value">
          {formattedDate ||
            formattedNumber ||
            value}

          {formattedDate && (
            <Clock
              size={12}
              className="kv-line-icon"
              aria-hidden="true"
            />
          )}
        </span>
      )}
    </span>
  );
}

/* ==========================================================================
   INVESTIGATION SECTION ICONS
   ========================================================================== */

const SECTION_ICONS = [
  [/^target type$/i, Tag],
  [/^target$/i, Target],
  [/^investigation status$/i, Activity],
  [
    /^threat intelligence sources$/i,
    Radar,
  ],
  [/^observed intelligence$/i, Eye],
  [/^key findings$/i, ListChecks],
  [/^correlated evidence$/i, Link2],
  [
    /^conflict(ing evidence|s)?$/i,
    GitCompare,
  ],
  [
    /^external threat assessment$/i,
    ShieldAlert,
  ],
  [/^environmental risk$/i, Building2],
  [/^evidence coverage$/i, LayoutGrid],
  [/^confidence$/i, Gauge],
  [/^risk$/i, Gauge],
  [
    /^mitre att&?ck( mapping)?$/i,
    Crosshair,
  ],
  [/^limitations?$/i, Info],
  [
    /^recommended investigation$/i,
    ListTodo,
  ],
  [/^mitigation$/i, ShieldCheck],
  [/^bottom line$/i, Flag],
  [/^assessment$/i, ClipboardCheck],
];

function iconForSectionTitle(title) {
  const clean = String(
    title || ""
  ).trim();

  for (const [
    pattern,
    Icon,
  ] of SECTION_ICONS) {
    if (pattern.test(clean)) {
      return Icon;
    }
  }

  return null;
}

/* ==========================================================================
   INVESTIGATION HEADING
   ========================================================================== */

const InvestigationHeading = memo(
  function InvestigationHeading({
    level,
    children,
    ...props
  }) {
    const text =
      nodeToText(children).trim();

    const Icon =
      iconForSectionTitle(text);

    const HeadingTag = `h${level}`;

    if (!Icon) {
      return (
        <HeadingTag {...props}>
          {children}
        </HeadingTag>
      );
    }

    return (
      <HeadingTag
        {...props}
        className={`${
          props.className || ""
        } heading-with-icon`.trim()}
      >
        <Icon
          size={level === 2 ? 19 : 16}
          strokeWidth={2.2}
          className="heading-icon"
          aria-hidden="true"
        />

        <span>{children}</span>
      </HeadingTag>
    );
  }
);

/* ==========================================================================
   INVESTIGATION LIST ITEM
   ========================================================================== */

const InvestigationListItem = memo(
  function InvestigationListItem({
    children,
    ...props
  }) {
    const text =
      nodeToText(children).trim();

    const node =
      renderSourceLine(text) ||
      renderConfidenceLine(text) ||
      renderKeyValueLine(text);

    if (node) {
      return (
        <li className="li-report-line">
          {node}
        </li>
      );
    }

    return (
      <li {...props}>
        {children}
      </li>
    );
  }
);

/* ==========================================================================
   INVESTIGATION PARAGRAPH
   ========================================================================== */

const InvestigationParagraph = memo(
  function InvestigationParagraph({
    children,
    ...props
  }) {
    const text =
      nodeToText(children).trim();

    const node =
      renderSourceLine(text) ||
      renderConfidenceLine(text) ||
      renderBareLevel(text);

    if (node) {
      return (
        <p className="p-report-line">
          {node}
        </p>
      );
    }

    return (
      <p {...props}>
        {children}
      </p>
    );
  }
);

/* ==========================================================================
   RESPONSIVE TABLE
   ========================================================================== */

const ResponsiveTable = memo(
  function ResponsiveTable({
    children,
  }) {
    const nodes = Array.isArray(
      children
    )
      ? children.filter(Boolean)
      : [children].filter(Boolean);

    const headerRow = (() => {
      for (const node of nodes) {
        if (
          !node ||
          !node.props
        ) {
          continue;
        }

        const kids =
          node.props.children;

        if (
          node.type === "thead" &&
          kids
        ) {
          const headRow =
            Array.isArray(kids)
              ? kids[0]
              : kids;

          const cells =
            headRow?.props?.children;

          const arr = Array.isArray(
            cells
          )
            ? cells
            : [cells];

          return arr
            .filter(Boolean)
            .map((cell) =>
              nodeToText(
                cell?.props
                  ?.children
              )
            );
        }
      }

      return [];
    })();

    const bodyRows = (() => {
      const rows = [];

      for (const node of nodes) {
        if (
          !node ||
          !node.props
        ) {
          continue;
        }

        if (
          node.type !== "tbody"
        ) {
          continue;
        }

        const rowNodes =
          Array.isArray(
            node.props.children
          )
            ? node.props.children
            : [node.props.children];

        for (const row of rowNodes) {
          if (
            !row ||
            !row.props
          ) {
            continue;
          }

          const cellNodes =
            Array.isArray(
              row.props.children
            )
              ? row.props.children
              : [row.props.children];

          rows.push(
            cellNodes
              .filter(Boolean)
              .map((cell) =>
                nodeToText(
                  cell?.props
                    ?.children
                )
              )
          );
        }
      }

      return rows;
    })();

    return (
      <div className="responsive-table">
        <div className="table-wrapper">
          <table>
            {headerRow.length > 0 && (
              <thead>
                <tr>
                  {headerRow.map(
                    (
                      label,
                      index
                    ) => (
                      <th
                        key={
                          index
                        }
                      >
                        {label}
                      </th>
                    )
                  )}
                </tr>
              </thead>
            )}

            {bodyRows.length > 0 && (
              <tbody>
                {bodyRows.map(
                  (
                    row,
                    rowIndex
                  ) => (
                    <tr
                      key={
                        rowIndex
                      }
                    >
                      {row.map(
                        (
                          cell,
                          cellIndex
                        ) => (
                          <td
                            key={
                              cellIndex
                            }
                          >
                            {cell}
                          </td>
                        )
                      )}
                    </tr>
                  )
                )}
              </tbody>
            )}
          </table>
        </div>

        <div
          className="mobile-table"
          role="list"
        >
          {bodyRows.map(
            (
              row,
              rowIndex
            ) => (
              <div
                className="mobile-table-row"
                role="listitem"
                key={
                  rowIndex
                }
              >
                {row.map(
                  (
                    cell,
                    cellIndex
                  ) => (
                    <div
                      className="mobile-table-field"
                      key={
                        cellIndex
                      }
                    >
                      {headerRow[
                        cellIndex
                      ] && (
                        <div className="mobile-table-label">
                          {
                            headerRow[
                              cellIndex
                            ]
                          }
                        </div>
                      )}

                      <div className="mobile-table-value">
                        {cell || (
                          <span className="mobile-table-empty">
                            —
                          </span>
                        )}
                      </div>
                    </div>
                  )
                )}
              </div>
            )
          )}
        </div>
      </div>
    );
  }
);

/* ==========================================================================
   CODE BLOCK
   ========================================================================== */

const CodeBlock = memo(
  function CodeBlock({
    inline,
    className,
    children,
    ...props
  }) {
    const [
      copied,
      setCopied,
    ] = useState(false);

    const match =
      /language-(\w+)/.exec(
        className || ""
      );

    const code = String(
      children
    ).replace(/\n$/, "");

    const handleCopyCode =
      useCallback(async () => {
        try {
          await navigator.clipboard.writeText(
            code
          );

          setCopied(true);

          setTimeout(
            () =>
              setCopied(false),
            2000
          );
        } catch (error) {
          console.error(
            "Failed to copy code:",
            error
          );
        }
      }, [code]);

    if (!inline && match) {
      return (
        <div className="code-block">
          <div className="code-header">
            <span className="code-language">
              {match[1]}
            </span>

            <button
              type="button"
              className="code-copy-button"
              onClick={
                handleCopyCode
              }
              aria-label="Copy code"
            >
              {copied ? (
                <Check size={13} />
              ) : (
                <Copy size={13} />
              )}

              <span>
                {copied
                  ? "Copied"
                  : "Copy"}
              </span>
            </button>
          </div>

          <SyntaxHighlighter
            style={oneDark}
            language={match[1]}
            PreTag="div"
            customStyle={{
              margin: 0,
              borderRadius: 0,
              fontSize: "14px",
              lineHeight: "1.6",
              maxWidth: "100%",
              overflowX: "auto",
            }}
            {...props}
          >
            {code}
          </SyntaxHighlighter>
        </div>
      );
    }

    return (
      <code
        className={`inline-code ${
          className || ""
        }`}
        {...props}
      >
        {children}
      </code>
    );
  }
);

/* ==========================================================================
   MESSAGE ITEM
   ========================================================================== */

const MessageItem = memo(
  function MessageItem({
    message,
    index,
    copiedMessageId,
    onCopy,
    onRetry,
    onDownloadReport,
  }) {
    const isUser =
      message.role === "user";

    const formatTime =
      (timestamp) =>
        new Date(
          timestamp
        ).toLocaleTimeString(
          [],
          {
            hour: "2-digit",
            minute: "2-digit",
          }
        );

    const usedTools =
      Array.isArray(
        message.metadata
          ?.toolsUsed
      )
        ? message.metadata
            .toolsUsed
        : [];

    /*
     * A report can only be generated when
     * the backend returned structured
     * investigation data.
     */
    const hasInvestigation =
      Boolean(
        message.metadata
          ?.investigation
      );

    return (
      <div
        className={`message ${
          isUser
            ? "user"
            : "assistant"
        } ${
          message.isError
            ? "error"
            : ""
        }`}
      >
        <div className="message-meta">
          {!isUser && (
            <Shield
              size={13}
              className="message-author-icon"
              aria-hidden="true"
            />
          )}

          <span className="message-author">
            {isUser ? "YOU" : "AI"}
          </span>

          {message.timestamp && (
            <span className="message-time">
              {formatTime(
                message.timestamp
              )}
            </span>
          )}

          {!isUser &&
            usedTools.length >
              0 && (
              <span
                className="message-tool-badge"
                title={`Tools used: ${usedTools.join(
                  ", "
                )}`}
              >
                <Wrench size={11} />

                {usedTools.length}{" "}
                tool
                {usedTools.length >
                1
                  ? "s"
                  : ""}
              </span>
            )}
        </div>

        <div className="message-content">
          {!isUser &&
          !message.isError ? (
            <>
              <div className="markdown-content">
                <ReactMarkdown
                  remarkPlugins={[
                    remarkGfm,
                  ]}
                  components={{
                    code: CodeBlock,

                    table:
                      ResponsiveTable,

                    li:
                      InvestigationListItem,

                    p:
                      InvestigationParagraph,

                    h2: (props) => (
                      <InvestigationHeading
                        level={2}
                        {...props}
                      />
                    ),

                    h3: (props) => (
                      <InvestigationHeading
                        level={3}
                        {...props}
                      />
                    ),

                    h4: (props) => (
                      <InvestigationHeading
                        level={4}
                        {...props}
                      />
                    ),

                    a({
                      children,
                      href,
                      ...props
                    }) {
                      return (
                        <a
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                          {...props}
                        >
                          {children}
                        </a>
                      );
                    },

                    img({
                      src,
                      alt,
                      ...props
                    }) {
                      return (
                        <img
                          src={src}
                          alt={
                            alt || ""
                          }
                          loading="lazy"
                          {...props}
                        />
                      );
                    },

                    blockquote({
                      children,
                    }) {
                      return (
                        <blockquote>
                          {children}
                        </blockquote>
                      );
                    },
                  }}
                >
                  {
                    message.displayContent
                  }
                </ReactMarkdown>
              </div>

              {message.metadata
                ?.responseTimeMs ? (
                <div className="metadata-footer">
                  <span className="metadata-provider">
                    Generated in{" "}
                    {(
                      message
                        .metadata
                        .responseTimeMs /
                      1000
                    ).toFixed(1)}
                    s
                    {message
                      .metadata
                      .provider
                      ? ` · ${message.metadata.provider}`
                      : ""}
                    {message
                      .metadata
                      .toolMode
                      ? " · tool-assisted"
                      : ""}
                  </span>
                </div>
              ) : null}
            </>
          ) : (
            <div className="plain-message">
              {message.displayContent}
            </div>
          )}
        </div>

        {!isUser &&
          !message.isError &&
          message.fullContent && (
            <div className="message-actions">

              {/* ============================================================
                  DOWNLOAD SECURITY REPORT
                  ============================================================ */}

              {hasInvestigation && (
                <button
                  type="button"
                  className="message-action-btn report-download-btn"
                  onClick={() =>
                    onDownloadReport(
                      message
                    )
                  }
                  aria-label="Download security report"
                  title="Download security report"
                >
                  <FileText
                    size={13}
                  />

                  <span className="report-button-label">
                    Report
                  </span>
                </button>
              )}

              {/* ============================================================
                  COPY RESPONSE
                  ============================================================ */}

              <button
                type="button"
                className="message-action-btn"
                onClick={() =>
                  onCopy(
                    message.fullContent,
                    index
                  )
                }
                aria-label="Copy response"
                title="Copy response"
              >
                {copiedMessageId ===
                index ? (
                  <Check size={13} />
                ) : (
                  <Copy size={13} />
                )}
              </button>

              {/* ============================================================
                  RETRY RESPONSE
                  ============================================================ */}

              <button
                type="button"
                className="message-action-btn"
                onClick={onRetry}
                aria-label="Retry response"
                title="Retry"
              >
                <RotateCcw
                  size={13}
                />
              </button>
            </div>
          )}

        {message.isError && (
          <div className="message-actions visible">
            <button
              type="button"
              className="message-action-btn error"
              onClick={onRetry}
              aria-label="Try again"
            >
              <RotateCcw size={13} />

              <span>
                Try Again
              </span>
            </button>
          </div>
        )}
      </div>
    );
  }
);

/* ==========================================================================
   LIVE RESPONSE FLOATING BUTTON
   ========================================================================== */

function LiveResponseButton({
  isRequesting,
  isAgentMode,
  isOpen,
  onClick,
}) {
  if (!isRequesting && !isOpen) {
    return null;
  }

  return (
    <button
      type="button"
      className={`live-response-button ${
        isRequesting
          ? "is-active"
          : "is-ready"
      } ${isOpen ? "is-open" : ""}`}
      onClick={onClick}
      aria-label={
        isOpen
          ? "Close live response"
          : "View live response"
      }
      title={
        isOpen
          ? "Close live response"
          : "View live response"
      }
    >
      {isOpen ? (
        <Minimize2 size={14} />
      ) : (
        <>
          <span className="live-response-pulse" />

          <span className="live-response-icon">
            {isAgentMode ? (
              <Radar size={14} />
            ) : (
              <Activity size={14} />
            )}
          </span>
        </>
      )}
    </button>
  );
}

/* ==========================================================================
   LIVE RESPONSE PANEL
   ========================================================================== */

const LiveResponsePanel = memo(
  function LiveResponsePanel({
    isOpen,
    isRequesting,
    isAgentMode,
    thinkingWord,
    liveContent,
    onClose,
    onStop,
  }) {
    if (!isOpen) {
      return null;
    }

    return (
      <div
        className={`live-response-panel ${
          isRequesting
            ? "is-generating"
            : "is-complete"
        }`}
        role="dialog"
        aria-label="Live response"
        aria-live="polite"
      >
        <div className="live-response-panel-header">
          <div className="live-response-title">
            <span className="live-response-title-icon">
              {isAgentMode ? (
                <Radar size={15} />
              ) : (
                <Activity size={15} />
              )}
            </span>

            <div>
              <strong>
                Live Response
              </strong>

              <span className="live-response-status">
                {isRequesting
                  ? isAgentMode
                    ? "Investigation in progress"
                    : "Generating response"
                  : "Response ready"}
              </span>
            </div>
          </div>

          <div className="live-response-panel-actions">
            {isRequesting && (
              <button
                type="button"
                className="live-response-stop"
                onClick={onStop}
                aria-label="Stop generation"
                title="Stop generation"
              >
                <Square size={13} />
              </button>
            )}

            <button
              type="button"
              className="live-response-close"
              onClick={onClose}
              aria-label="Close live response"
              title="Close"
            >
              <X size={15} />
            </button>
          </div>
        </div>

        <div className="live-response-panel-body">
          {isRequesting && (
            <div className="live-response-thinking">
              <span className="live-response-thinking-dot" />

              <span>
                {thinkingWord}
              </span>
            </div>
          )}

          {liveContent ? (
            <div className="live-response-content">
              <ReactMarkdown
                remarkPlugins={[
                  remarkGfm,
                ]}
              >
                {liveContent}
              </ReactMarkdown>
            </div>
          ) : (
            <div className="live-response-empty">
              <Activity
                size={18}
              />

              <span>
                The assistant is
                working. You can
                continue using the
                interface while it
                finishes.
              </span>
            </div>
          )}
        </div>
      </div>
    );
  }
);

/* ==========================================================================
   APP
   ========================================================================== */

function App() {
  const [messages, setMessages] =
    useState(() => [
      buildGreetingMessage(),
    ]);

  const [input, setInput] =
    useState("");

  const [isRequesting, setIsRequesting] =
    useState(false);

  const [isAgentMode, setIsAgentMode] =
    useState(false);

  const [thinkingWord, setThinkingWord] =
    useState(
      THINKING_WORDS[0]
    );

  const [darkMode, setDarkMode] =
    useState(() => {
      if (
        typeof window ===
        "undefined"
      ) {
        return false;
      }

      const saved =
        localStorage.getItem(
          "darkMode"
        );

      if (saved === null) {
        return false;
      }

      try {
        return JSON.parse(saved);
      } catch {
        return false;
      }
    });

  const [showScrollButton, setShowScrollButton] =
    useState(false);

  const [intents, setIntents] =
    useState([]);

  const [copiedMessageId, setCopiedMessageId] =
    useState(null);

  const [conversationId, setConversationId] =
    useState(null);

  /* ------------------------------------------------------------------------
     LIVE RESPONSE STATE
     ------------------------------------------------------------------------ */

  const [showLiveResponse, setShowLiveResponse] =
    useState(false);

  const [liveResponseContent, setLiveResponseContent] =
    useState("");

  const textareaRef =
    useRef(null);

  const messagesContainerRef =
    useRef(null);

  const scrollStateRef =
    useRef({
      isNearBottom: true,
    });

  const requestAbortRef =
    useRef(null);

  const {
    height: viewportHeight,
  } = useVisualViewport();

  const isEmptyState =
    messages.length === 1 &&
    messages[0]?.role ===
      "assistant" &&
    typeof messages[0]?.id ===
      "string" &&
    messages[0].id.startsWith(
      "init-"
    );

  /* ==========================================================================
     THINKING ANIMATION
     ========================================================================== */

  useEffect(() => {
    if (!isRequesting) {
      return;
    }

    const pool = isAgentMode
      ? AGENT_THINKING_WORDS
      : THINKING_WORDS;

    const interval =
      setInterval(() => {
        setThinkingWord(
          (previous) => {
            const index =
              pool.indexOf(
                previous
              );

            return pool[
              (index + 1) %
                pool.length
            ];
          }
        );
      }, 2500);

    return () =>
      clearInterval(interval);
  }, [
    isRequesting,
    isAgentMode,
  ]);

  /* ==========================================================================
     THEME
     ========================================================================== */

  useEffect(() => {
    localStorage.setItem(
      "darkMode",
      JSON.stringify(darkMode)
    );

    document.documentElement.classList.toggle(
      "dark",
      darkMode
    );
  }, [darkMode]);

  /* ==========================================================================
     AUTO-SIZE TEXTAREA
     ========================================================================== */

  useEffect(() => {
    const element =
      textareaRef.current;

    if (!element) {
      return;
    }

    element.style.height =
      "auto";

    const isMobile =
      typeof window !==
        "undefined" &&
      window.innerWidth <= 600;

    const maxHeight = isMobile
      ? 140
      : 220;

    const nextHeight =
      Math.min(
        element.scrollHeight,
        maxHeight
      );

    element.style.height =
      `${nextHeight}px`;

    element.style.overflowY =
      element.scrollHeight >
      maxHeight
        ? "auto"
        : "hidden";
  }, [input]);

  /* ==========================================================================
     CLEANUP
     ========================================================================== */

  useEffect(() => {
    return () => {
      if (
        requestAbortRef.current
      ) {
        requestAbortRef.current.abort();
      }
    };
  }, []);

  /* ==========================================================================
     SCROLL METRICS
     ========================================================================== */

  const computeScrollMetrics =
    useCallback(() => {
      const container =
        messagesContainerRef.current;

      if (!container) {
        return;
      }

      const {
        scrollTop,
        scrollHeight,
        clientHeight,
      } = container;

      const distanceFromBottom =
        scrollHeight -
        scrollTop -
        clientHeight;

      const hasOverflow =
        scrollHeight -
          clientHeight >
        SCROLL_BOTTOM_THRESHOLD;

      const isAtBottom =
        distanceFromBottom <=
        SCROLL_BOTTOM_THRESHOLD;

      scrollStateRef.current.isNearBottom =
        isAtBottom;

      setShowScrollButton(
        hasOverflow && !isAtBottom
      );
    }, []);

  /* ==========================================================================
     KEEP MESSAGES PINNED
     ========================================================================== */

  useEffect(() => {
    const container =
      messagesContainerRef.current;

    if (!container) {
      return;
    }

    const raf =
      requestAnimationFrame(
        computeScrollMetrics
      );

    const observer =
      new MutationObserver(() => {
        if (
          scrollStateRef.current
            .isNearBottom
        ) {
          container.scrollTop =
            container.scrollHeight;
        }

        computeScrollMetrics();
      });

    observer.observe(
      container,
      {
        childList: true,
        subtree: true,
        characterData: true,
      }
    );

    return () => {
      cancelAnimationFrame(raf);
      observer.disconnect();
    };
  }, [computeScrollMetrics]);

  /* ==========================================================================
     SCROLL TO BOTTOM
     ========================================================================== */

  const scrollToBottom =
    useCallback(() => {
      const container =
        messagesContainerRef.current;

      if (!container) {
        return;
      }

      const prefersReducedMotion =
        typeof window !==
          "undefined" &&
        window.matchMedia(
          "(prefers-reduced-motion: reduce)"
        ).matches;

      if (
        prefersReducedMotion
      ) {
        container.scrollTop =
          container.scrollHeight;
      } else {
        container.scrollTo({
          top: container.scrollHeight,
          behavior: "smooth",
        });
      }

      scrollStateRef.current.isNearBottom =
        true;

      setShowScrollButton(false);
    }, []);

  const handleScroll =
    useCallback(() => {
      computeScrollMetrics();
    }, [computeScrollMetrics]);

  /* ==========================================================================
     REQUEST RUNNER
     ========================================================================== */

  const runRequest =
    useCallback(
      async (
        apiMessages,
        { useAgent }
      ) => {
        if (
          requestAbortRef.current
        ) {
          requestAbortRef.current.abort();
        }

        const controller =
          new AbortController();

        requestAbortRef.current =
          controller;

        setIsRequesting(true);
        setIsAgentMode(useAgent);

        setShowLiveResponse(false);
        setLiveResponseContent("");

        setThinkingWord(
          useAgent
            ? AGENT_THINKING_WORDS[0]
            : THINKING_WORDS[0]
        );

        scrollStateRef.current.isNearBottom =
          true;

        const endpoint = useAgent
          ? "/api/agent"
          : "/api/chat";

        try {
          const response =
            await fetch(
              `${API_URL}${endpoint}`,
              {
                method: "POST",

                headers: {
                  "Content-Type":
                    "application/json",
                },

                body: JSON.stringify({
                  messages:
                    apiMessages,
                  conversationId,
                }),

                signal:
                  controller.signal,
              }
            );

          if (!response.ok) {
            const data =
              await response
                .json()
                .catch(
                  () => ({})
                );

            throw new Error(
              data.error ||
                `HTTP ${response.status}`
            );
          }

          const data =
            await response.json();

          if (
            data.conversationId
          ) {
            setConversationId(
              data.conversationId
            );
          }

          if (data.intents) {
            setIntents(
              data.intents
            );
          }

          const normalizedReply =
            stripSchemaLabels(
              normalizeMarkdown(
                data.reply || ""
              )
            );

          setLiveResponseContent(
            normalizedReply
          );

          setMessages(
            (previous) => [
              ...previous,
              {
                id:
                  "assistant-" +
                  Date.now(),
                role: "assistant",
                displayContent:
                  normalizedReply,
                fullContent:
                  normalizedReply,
                timestamp:
                  new Date().toISOString(),

                /*
                 * IMPORTANT:
                 * This preserves the complete
                 * backend metadata, including:
                 *
                 * metadata.investigation
                 * metadata.toolsUsed
                 * metadata.target
                 * metadata.requestId
                 *
                 * The PDF report button uses
                 * metadata.investigation.
                 */
                metadata:
                  data.metadata || {},
              },
            ]
          );

          if (
            scrollStateRef.current
              .isNearBottom
          ) {
            setTimeout(
              scrollToBottom,
              50
            );
          }
        } catch (error) {
          if (
            error.name ===
            "AbortError"
          ) {
            return;
          }

          const errorMessage =
            error.message ||
            "Unable to reach the AI service. Please try again.";

          const finalError =
            `⚠️ ${errorMessage}`;

          setLiveResponseContent(
            finalError
          );

          setMessages(
            (previous) => [
              ...previous,
              {
                id:
                  "error-" +
                  Date.now(),
                role: "assistant",
                displayContent:
                  finalError,
                fullContent:
                  finalError,
                timestamp:
                  new Date().toISOString(),
                isError: true,
              },
            ]
          );
        } finally {
          if (
            requestAbortRef.current ===
            controller
          ) {
            requestAbortRef.current =
              null;
          }

          setIsRequesting(false);
          setIsAgentMode(false);
        }
      },
      [
        conversationId,
        scrollToBottom,
      ]
    );

  /* ==========================================================================
     SEND MESSAGE
     ========================================================================== */

  const sendMessage =
    useCallback(
      async (
        content = input
      ) => {
        const trimmedInput =
          content.trim();

        if (
          !trimmedInput ||
          isRequesting
        ) {
          return;
        }

        if (
          trimmedInput.length >
          4000
        ) {
          const errorMessage =
            "⚠️ Your message exceeds the 4000 character limit.";

          setMessages(
            (previous) => [
              ...previous,
              {
                id:
                  "error-" +
                  Date.now(),
                role: "assistant",
                displayContent:
                  errorMessage,
                fullContent:
                  errorMessage,
                timestamp:
                  new Date().toISOString(),
                isError: true,
              },
            ]
          );

          return;
        }

        const useAgent =
          shouldUseAgent(
            trimmedInput
          );

        const userMessage = {
          id:
            "user-" +
            Date.now(),
          role: "user",
          displayContent:
            trimmedInput,
          fullContent:
            trimmedInput,
          timestamp:
            new Date().toISOString(),
        };

        const updatedMessages = [
          ...messages,
          userMessage,
        ];

        setMessages(
          updatedMessages
        );

        setInput("");
        setIntents([]);
        setLiveResponseContent("");

        if (textareaRef.current) {
          textareaRef.current.style.height =
            "auto";
        }

        const apiMessages =
          updatedMessages
            .filter(
              (message) =>
                (
                  message.role ===
                    "user" ||
                  message.role ===
                    "assistant"
                ) &&
                typeof message.fullContent ===
                  "string"
            )
            .map(
              ({
                role,
                fullContent:
                  contentValue,
              }) => ({
                role,
                content:
                  contentValue.slice(
                    0,
                    4000
                  ),
              })
            );

        await runRequest(
          apiMessages,
          {
            useAgent,
          }
        );
      },
      [
        input,
        isRequesting,
        messages,
        runRequest,
      ]
    );

  /* ==========================================================================
     STOP GENERATION
     ========================================================================== */

  const handleStop =
    useCallback(() => {
      if (
        requestAbortRef.current
      ) {
        requestAbortRef.current.abort();

        requestAbortRef.current =
          null;
      }

      setIsRequesting(false);
      setIsAgentMode(false);
    }, []);

  /* ==========================================================================
     KEYBOARD
     ========================================================================== */

  const handleKeyDown =
    useCallback(
      (event) => {
        if (
          event.key === "Enter" &&
          !event.shiftKey
        ) {
          event.preventDefault();
          sendMessage();
        }
      },
      [sendMessage]
    );

  /* ==========================================================================
     CLEAR CHAT
     ========================================================================== */

  const clearChat =
    useCallback(async () => {
      if (
        requestAbortRef.current
      ) {
        requestAbortRef.current.abort();
      }

      requestAbortRef.current =
        null;

      setIsRequesting(false);
      setIsAgentMode(false);

      setShowLiveResponse(false);
      setLiveResponseContent("");

      if (conversationId) {
        try {
          await fetch(
            `${API_URL}/api/clear-conversation`,
            {
              method: "POST",

              headers: {
                "Content-Type":
                  "application/json",
              },

              body: JSON.stringify({
                conversationId,
              }),
            }
          );
        } catch (error) {
          console.error(
            "Failed to clear conversation:",
            error
          );
        }
      }

      setConversationId(null);
      setIntents([]);

      setMessages([
        buildGreetingMessage(
          CLEARED_GREETING
        ),
      ]);

      setInput("");

      requestAnimationFrame(() => {
        if (
          messagesContainerRef.current
        ) {
          messagesContainerRef.current.scrollTop = 0;
        }
      });
    }, [conversationId]);

  /* ==========================================================================
     SUGGESTION CLICK
     ========================================================================== */

  const handleSuggestionClick =
    useCallback(
      (suggestion) => {
        sendMessage(
          suggestion
        );
      },
      [sendMessage]
    );

  /* ==========================================================================
     COPY MESSAGE
     ========================================================================== */

  const handleCopyMessage =
    useCallback(
      async (
        content,
        index
      ) => {
        try {
          await navigator.clipboard.writeText(
            content
          );

          setCopiedMessageId(
            index
          );

          setTimeout(
            () =>
              setCopiedMessageId(
                null
              ),
            2000
          );
        } catch (error) {
          console.error(
            "Failed to copy:",
            error
          );
        }
      },
      []
    );

  /* ==========================================================================
     RETRY
     ========================================================================== */

  const handleRetry =
    useCallback(() => {
      if (
        requestAbortRef.current
      ) {
        requestAbortRef.current.abort();
      }

      requestAbortRef.current =
        null;

      setIsRequesting(false);
      setIsAgentMode(false);

      setShowLiveResponse(false);
      setLiveResponseContent("");

      const lastUserIndex =
        [...messages]
          .reverse()
          .findIndex(
            (message) =>
              message.role ===
              "user"
          );

      if (
        lastUserIndex === -1
      ) {
        return;
      }

      const actualIndex =
        messages.length -
        1 -
        lastUserIndex;

      const lastUserMessage =
        messages[actualIndex];

      const historyBeforeUser =
        messages.slice(
          0,
          actualIndex
        );

      const userMsg = {
        ...lastUserMessage,
      };

      const cleanHistory =
        historyBeforeUser.filter(
          (message) =>
            !message.isError
        );

      const newMessages = [
        ...cleanHistory,
        userMsg,
      ];

      setMessages(newMessages);

      const apiMessages =
        newMessages
          .filter(
            (message) =>
              (
                message.role ===
                  "user" ||
                message.role ===
                  "assistant"
              ) &&
              typeof message.fullContent ===
                "string"
          )
          .map(
            ({
              role,
              fullContent:
                content,
            }) => ({
              role,
              content:
                content.slice(
                  0,
                  4000
                ),
            })
          );

      const useAgent =
        shouldUseAgent(
          lastUserMessage.fullContent ||
            ""
        );

      runRequest(
        apiMessages,
        {
          useAgent,
        }
      );
    }, [
      messages,
      runRequest,
    ]);

  /* ==========================================================================
     LIVE RESPONSE TOGGLE
     ========================================================================== */

  const toggleLiveResponse =
    useCallback(() => {
      setShowLiveResponse(
        (previous) => !previous
      );
    }, []);

  /* ==========================================================================
     DOWNLOAD SECURITY REPORT
     ========================================================================== */

  const downloadSecurityReport =
    useCallback(
      async (message) => {
        try {
          const metadata =
            message?.metadata || {};

          const investigation =
            metadata?.investigation;

          /*
           * The report is only possible
           * when the backend returned the
           * structured investigation object.
           */
          if (
            !investigation ||
            typeof investigation !==
              "object"
          ) {
            throw new Error(
              "No structured security investigation is available for this response."
            );
          }

          const target =
            investigation.target ||
            metadata.target ||
            "security-investigation";

          const response =
            await fetch(
              `${API_URL}/api/security-report`,
              {
                method: "POST",

                headers: {
                  "Content-Type":
                    "application/json",
                },

                body: JSON.stringify({
                  investigation,
                  metadata,
                  target,
                  requestId:
                    metadata.requestId ||
                    null,
                }),
              }
            );

          /*
           * The report endpoint returns
           * application/pdf on success and
           * JSON on failure.
           */
          if (!response.ok) {
            let errorMessage =
              `Report generation failed (${response.status})`;

            const contentType =
              response.headers.get(
                "content-type"
              ) || "";

            if (
              contentType.includes(
                "application/json"
              )
            ) {
              const errorData =
                await response
                  .json()
                  .catch(
                    () => ({})
                  );

              if (
                errorData?.error
              ) {
                errorMessage =
                  errorData.error;
              }
            } else {
              const text =
                await response
                  .text()
                  .catch(
                    () => ""
                  );

              if (text) {
                errorMessage =
                  text;
              }
            }

            throw new Error(
              errorMessage
            );
          }

          const contentType =
            response.headers.get(
              "content-type"
            ) || "";

          if (
            !contentType.includes(
              "application/pdf"
            )
          ) {
            throw new Error(
              "The server did not return a PDF report."
            );
          }

          const blob =
            await response.blob();

          if (!blob.size) {
            throw new Error(
              "The generated report was empty."
            );
          }

          const url =
            window.URL.createObjectURL(
              blob
            );

          const anchor =
            document.createElement(
              "a"
            );

          anchor.href = url;

          const safeTarget =
            String(target)
              .replace(
                /[^a-zA-Z0-9._-]/g,
                "-"
              )
              .slice(0, 80);

          anchor.download =
            `Lakewest-Security-Report-${safeTarget}.pdf`;

          document.body.appendChild(
            anchor
          );

          anchor.click();

          anchor.remove();

          /*
           * Give the browser a moment to
           * start the download before
           * releasing the object URL.
           */
          setTimeout(() => {
            window.URL.revokeObjectURL(
              url
            );
          }, 1000);
        } catch (error) {
          console.error(
            "Failed to download security report:",
            error
          );

          const errorMessage =
            `⚠️ Unable to generate the security report. ${
              error?.message || ""
            }`;

          setMessages(
            (previous) => [
              ...previous,
              {
                id:
                  "report-error-" +
                  Date.now(),
                role: "assistant",
                displayContent:
                  errorMessage,
                fullContent:
                  errorMessage,
                timestamp:
                  new Date().toISOString(),
                isError: true,
              },
            ]
          );
        }
      },
      []
    );

  /* ==========================================================================
     RENDER
     ========================================================================== */

  return (
    <div
      className={`app ${
        darkMode ? "dark" : ""
      }`}
      style={{
        height: `${viewportHeight}px`,
        minHeight: "100dvh",
      }}
    >
      {/* ====================================================================
          HEADER
          ==================================================================== */}

      <header className="header">
        <div className="header-content">
          <div className="header-brand">
            <div className="header-icon-container">
              <Shield
                size={18}
                strokeWidth={2.25}
              />
            </div>

            <div className="header-text">
              <div className="header-title-row">
                <h1 className="header-title">
                  <span className="header-title-gradient">
                    Lakewest AI Security
                    Assistant
                  </span>
                </h1>

                <span className="header-status">
                  <span className="status-dot" />
                  Ready
                </span>
              </div>

              <p className="header-subtitle">
                Security & Safety
                Copilot
              </p>
            </div>
          </div>

          <div className="header-actions">
            <button
              type="button"
              className="icon-button"
              onClick={() =>
                setDarkMode(
                  (value) => !value
                )
              }
              aria-label="Toggle theme"
              title="Toggle theme"
            >
              {darkMode ? (
                <Sun size={18} />
              ) : (
                <Moon size={18} />
              )}
            </button>
          </div>
        </div>
      </header>

      {/* ====================================================================
          INTENT BADGES
          ==================================================================== */}

      {intents.length > 0 && (
        <div className="intent-badges">
          <span className="intent-badges-label">
            Security context:
          </span>

          {intents.map((intent) => (
            <span
              key={intent}
              className="intent-badge"
            >
              {intent.replace(
                /_/g,
                " "
              )}
            </span>
          ))}
        </div>
      )}

      {/* ====================================================================
          MAIN CHAT
          ==================================================================== */}

      <main className="chat-container">
        <div
          className={`messages ${
            isEmptyState
              ? "messages--empty"
              : ""
          }`}
          ref={
            messagesContainerRef
          }
          onScroll={
            handleScroll
          }
          role="log"
          aria-live="polite"
          aria-label="Chat messages"
        >
          {isEmptyState ? (
            <div className="empty-state">
              <div className="empty-state-icon">
                <Shield
                  size={22}
                  strokeWidth={2}
                />
              </div>

              <p className="empty-state-eyebrow">
                AI Security Assistant
              </p>

              <h2 className="empty-state-title">
                How can I help you
                stay secure?
              </h2>

              <p className="empty-state-description">
                Ask about threats,
                security, privacy,
                incidents, systems,
                applications, or
                everyday safety.
              </p>

              <div className="suggestion-grid">
                {SUGGESTION_CARDS.map(
                  (card) => {
                    const Icon =
                      card.icon;

                    return (
                      <button
                        key={
                          card.title
                        }
                        type="button"
                        className="suggestion-card"
                        onClick={() =>
                          handleSuggestionClick(
                            card.prompt
                          )
                        }
                      >
                        <span className="suggestion-card-icon">
                          <Icon
                            size={18}
                          />
                        </span>

                        <span className="suggestion-card-body">
                          <span className="suggestion-card-title">
                            {
                              card.title
                            }
                          </span>

                          <span className="suggestion-card-desc">
                            {
                              card.description
                            }
                          </span>
                        </span>
                      </button>
                    );
                  }
                )}
              </div>
            </div>
          ) : (
            messages.map(
              (
                message,
                index
              ) => (
                <MessageItem
                  key={
                    message.id
                  }
                  message={
                    message
                  }
                  index={
                    index
                  }
                  copiedMessageId={
                    copiedMessageId
                  }
                  onCopy={
                    handleCopyMessage
                  }
                  onRetry={
                    handleRetry
                  }
                  onDownloadReport={
                    downloadSecurityReport
                  }
                />
              )
            )
          )}

          {/* ================================================================
              THINKING MESSAGE
              ================================================================ */}

          {isRequesting && (
            <div className="message assistant loading">
              <div className="message-meta">
                <Shield
                  size={13}
                  className="message-author-icon"
                  aria-hidden="true"
                />

                <span className="message-author">
                  AI
                </span>

                {isAgentMode && (
                  <span className="message-tool-badge">
                    <Wrench
                      size={11}
                    />
                    investigation
                  </span>
                )}
              </div>

              <div className="message-content">
                <div className="thinking-indicator">
                  <div className="thinking-dots">
                    <span />
                    <span />
                    <span />
                  </div>

                  <span className="thinking-text">
                    {thinkingWord}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ==================================================================
            SCROLL BUTTON
            ================================================================== */}

        {showScrollButton && (
          <button
            type="button"
            className="scroll-button"
            onClick={
              scrollToBottom
            }
            aria-label="Scroll to bottom"
          >
            <ArrowDown size={18} />
          </button>
        )}

        {/* ==================================================================
            LIVE RESPONSE BUTTON
            ================================================================== */}

        <LiveResponseButton
          isRequesting={
            isRequesting
          }
          isAgentMode={
            isAgentMode
          }
          isOpen={
            showLiveResponse
          }
          onClick={
            toggleLiveResponse
          }
        />

        {/* ==================================================================
            LIVE RESPONSE PANEL
            ================================================================== */}

        <LiveResponsePanel
          isOpen={
            showLiveResponse
          }
          isRequesting={
            isRequesting
          }
          isAgentMode={
            isAgentMode
          }
          thinkingWord={
            thinkingWord
          }
          liveContent={
            liveResponseContent
          }
          onClose={() =>
            setShowLiveResponse(
              false
            )
          }
          onStop={
            handleStop
          }
        />

        {/* ==================================================================
            COMPOSER
            ================================================================== */}

        <div className="composer">
          <div className="composer-inner">
            <div className="composer-box">
              <button
                type="button"
                className="new-chat-inline-button"
                onClick={
                  clearChat
                }
                aria-label="Start new chat"
                title="Start new chat"
              >
                <Plus size={18} />
              </button>

              <textarea
                ref={
                  textareaRef
                }
                value={input}
                onChange={(
                  event
                ) =>
                  setInput(
                    event.target
                      .value
                  )
                }
                onKeyDown={
                  handleKeyDown
                }
                placeholder="Ask about security or safety..."
                rows={1}
                disabled={
                  isRequesting
                }
                aria-label="Message input"
                maxLength={4000}
                enterKeyHint="send"
                spellCheck="true"
              />

              {isRequesting ? (
                <button
                  type="button"
                  className="stop-button"
                  onClick={
                    handleStop
                  }
                  aria-label="Stop generation"
                >
                  <Square
                    size={18}
                  />
                </button>
              ) : (
                <button
                  type="button"
                  className="send-button"
                  onClick={() =>
                    sendMessage()
                  }
                  disabled={
                    !input.trim()
                  }
                  aria-label="Send message"
                >
                  <Send size={18} />
                </button>
              )}
            </div>

            <p className="composer-hint">
              Enter to send · Shift +
              Enter for newline
            </p>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
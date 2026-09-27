/**
 * PdfReportRenderer
 *
 * Minimal dependency-free Markdown-to-PDF renderer for security reports.
 *
 * It intentionally renders text only: investigation values are never treated
 * as HTML, JavaScript, or executable content.
 */

const PAGE_WIDTH = 595;
const PAGE_HEIGHT = 842;

const LEFT = 50;
const RIGHT = 50;
const TOP = 790;
const BOTTOM = 55;

const BODY_FONT = 10;
const BODY_LEADING = 14;
const HEADING_LEADING = 20;
const SMALL_LEADING = 12;

const MAX_CHARS = 92;

function pdfSafeText(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(
      /[\u0000-\u001f\u007f-\u009f]/g,
      ' '
    )
    .replace(/[✓✔]/g, '[OK]')
    .replace(/[⚠]/g, '[WARN]')
    .replace(/[✗✕]/g, '[FAIL]')
    .replace(/[→➜]/g, '->')
    .replace(/[←]/g, '<-')
    .replace(/[—–]/g, '-')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/…/g, '...')
    .replace(/[^\x20-\x7E\xA0-\xFF]/g, '?');
}

function stripMarkdown(line) {
  return String(line ?? '')
    .replace(
      /^\s{0,3}#{1,6}\s+/,
      ''
    )
    .replace(
      /^\s*[-*+]\s+/,
      '  - '
    )
    .replace(
      /^\s*\d+\.\s+/,
      '  - '
    )
    .replace(
      /\*\*(.*?)\*\*/g,
      '$1'
    )
    .replace(
      /\*(.*?)\*/g,
      '$1'
    )
    .replace(
      /__(.*?)__/g,
      '$1'
    )
    .replace(
      /_(.*?)_/g,
      '$1'
    )
    .replace(
      /`([^`]+)`/g,
      '$1'
    )
    .replace(
      /\[([^\]]+)\]\([^)]+\)/g,
      '$1'
    )
    .trimEnd();
}

function classify(line) {
  if (/^#\s+/.test(line)) {
    return 'title';
  }

  if (/^##\s+/.test(line)) {
    return 'h2';
  }

  if (/^###\s+/.test(line)) {
    return 'h3';
  }

  if (
    /^\s*[-*+]\s+/.test(line) ||
    /^\s*\d+\.\s+/.test(line)
  ) {
    return 'bullet';
  }

  return line.trim()
    ? 'body'
    : 'blank';
}

function wrapText(
  text,
  maxChars = MAX_CHARS
) {
  const value = pdfSafeText(
    stripMarkdown(text)
  );

  if (!value) {
    return [''];
  }

  const words =
    value.split(/\s+/);

  const lines = [];
  let current = '';

  for (const word of words) {
    if (!current) {
      current = word;
      continue;
    }

    if (
      current.length +
        1 +
        word.length <=
      maxChars
    ) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }

  if (current) {
    lines.push(current);
  }

  return lines;
}

function renderMarkdown(markdown) {
  const source = String(
    markdown || ''
  ).replace(/\r\n/g, '\n');

  const rawLines =
    source.split('\n');

  const rendered = [];

  let inCode = false;

  for (const raw of rawLines) {
    if (/^\s*```/.test(raw)) {
      inCode = !inCode;

      if (!inCode) {
        rendered.push({
          text: '',
          type: 'blank',
        });
      }

      continue;
    }

    if (inCode) {
      for (
        const line of wrapText(
          raw,
          88
        )
      ) {
        rendered.push({
          text: line,
          type: 'code',
        });
      }

      continue;
    }

    const type =
      classify(raw);

    if (type === 'blank') {
      rendered.push({
        text: '',
        type,
      });

      continue;
    }

    const width =
      type === 'title'
        ? 76
        : type === 'h2'
          ? 82
          : 92;

    for (
      const line of wrapText(
        raw,
        width
      )
    ) {
      rendered.push({
        text: line,
        type,
      });
    }
  }

  return rendered;
}

function lineMetrics(type) {
  if (type === 'title') {
    return {
      size: 20,
      leading: 25,
      gap: 4,
    };
  }

  if (type === 'h2') {
    return {
      size: 14,
      leading: HEADING_LEADING,
      gap: 5,
    };
  }

  if (type === 'h3') {
    return {
      size: 11,
      leading: 16,
      gap: 3,
    };
  }

  if (type === 'code') {
    return {
      size: 8.5,
      leading: SMALL_LEADING,
      gap: 0,
    };
  }

  if (type === 'bullet') {
    return {
      size: BODY_FONT,
      leading: BODY_LEADING,
      gap: 0,
    };
  }

  if (type === 'blank') {
    return {
      size: BODY_FONT,
      leading: 7,
      gap: 0,
    };
  }

  return {
    size: BODY_FONT,
    leading: BODY_LEADING,
    gap: 0,
  };
}

class PdfReportRenderer {
  render(markdown) {
    if (
      typeof markdown !== 'string' ||
      !markdown.trim()
    ) {
      throw new Error(
        'Report Markdown is required'
      );
    }

    const items =
      renderMarkdown(markdown);

    const pages = [];

    let pageLines = [];
    let y = TOP;

    const pushPage = () => {
      if (pageLines.length) {
        pages.push(pageLines);
      }

      pageLines = [];
      y = TOP;
    };

    for (const item of items) {
      const metrics =
        lineMetrics(item.type);

      const height =
        metrics.leading +
        metrics.gap;

      if (
        y - height <
        BOTTOM
      ) {
        pushPage();
      }

      pageLines.push({
        ...item,
        y,
        size: metrics.size,
      });

      y -= height;
    }

    if (
      pageLines.length ||
      pages.length === 0
    ) {
      pushPage();
    }

    return this._buildPdf(
      pages
    );
  }

  _buildPdf(pages) {
    const objects = [];

    const addObject = (body) => {
      objects.push(body);
      return objects.length;
    };

    const catalogId =
      addObject('');

    const pagesId =
      addObject('');

    const fontId =
      addObject(
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'
      );

    const pageIds = [];

    pages.forEach(
      (lines, index) => {
        const commands = [
          'q',
          '0 0 0 rg',
          'BT',
        ];

        for (const line of lines) {
          const fontSize =
            line.size;

          const weight =
            line.type === 'title' ||
            line.type === 'h2'
              ? '0.08'
              : '0.18';

          commands.push(
            `${weight} g`
          );

          commands.push(
            `/F1 ${fontSize} Tf`
          );

          commands.push(
            `${LEFT} ${line.y.toFixed(
              2
            )} Td`
          );

          commands.push(
            `(${pdfSafeText(
              line.text
            )}) Tj`
          );

          commands.push(
            `${-LEFT} ${(
              -line.y
            ).toFixed(2)} Td`
          );
        }

        commands.push('ET');

        commands.push('BT');
        commands.push('/F1 8 Tf');
        commands.push('0.40 g');

        commands.push(
          `${LEFT} 30 Td`
        );

        commands.push(
          '(Lakewest AI Security Assistant - Security Investigation Report) Tj'
        );

        commands.push(
          `${
            PAGE_WIDTH -
            LEFT -
            RIGHT -
            65
          } 0 Td`
        );

        commands.push(
          `(Page ${
            index + 1
          }) Tj`
        );

        commands.push('ET');
        commands.push('Q');

        const stream =
          commands.join('\n');

        const contentId =
          addObject(
            `<< /Length ${Buffer.byteLength(
              stream,
              'latin1'
            )} >>\nstream\n${stream}\nendstream`
          );

        const pageId =
          addObject(
            `<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 ${fontId} 0 R >> >> /Contents ${contentId} 0 R >>`
          );

        pageIds.push(pageId);
      }
    );

    objects[catalogId - 1] =
      `<< /Type /Catalog /Pages ${pagesId} 0 R >>`;

    objects[pagesId - 1] =
      `<< /Type /Pages /Kids [${pageIds
        .map(
          (id) => `${id} 0 R`
        )
        .join(' ')}] /Count ${
        pageIds.length
      } >>`;

    let pdf =
      '%PDF-1.4\n%\xFF\xFF\xFF\xFF\n';

    const offsets = [0];

    objects.forEach(
      (object, index) => {
        offsets[index + 1] =
          Buffer.byteLength(
            pdf,
            'latin1'
          );

        pdf +=
          `${index + 1} 0 obj\n` +
          `${object}\n` +
          'endobj\n';
      }
    );

    const xrefOffset =
      Buffer.byteLength(
        pdf,
        'latin1'
      );

    pdf +=
      `xref\n0 ${
        objects.length + 1
      }\n`;

    pdf +=
      '0000000000 65535 f \n';

    for (
      let i = 1;
      i <= objects.length;
      i += 1
    ) {
      pdf +=
        `${String(
          offsets[i]
        ).padStart(
          10,
          '0'
        )} 00000 n \n`;
    }

    pdf +=
      `trailer\n<< /Size ${
        objects.length + 1
      } /Root ${catalogId} 0 R >>\n` +
      `startxref\n${xrefOffset}\n` +
      '%%EOF\n';

    return Buffer.from(
      pdf,
      'latin1'
    );
  }
}

module.exports =
  PdfReportRenderer;
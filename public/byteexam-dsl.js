(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.ByteExamDSL = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const START = '---BYTEEXAM-START---';
  const END = '---BYTEEXAM-END---';

  function extractBody(raw) {
    const source = String(raw || '').replace(/\r\n?/g, '\n');
    const start = source.indexOf(START);
    const end = source.indexOf(END);
    return start >= 0 && end > start ? source.slice(start + START.length, end) : source;
  }

  function normalizeTextbookId(value) {
    return String(value || '').trim().toLowerCase().replace(/\s+/g, ' ');
  }

  function appendTextbookReference(question, reference) {
    if (!question) return;
    const refs = String(question.textbook || '').split(/[,;|\n]/).map(v => v.trim()).filter(Boolean);
    const next = String(reference || '').trim();
    if (next && !refs.some(v => normalizeTextbookId(v) === normalizeTextbookId(next))) refs.push(next);
    question.textbook = refs.join(', ');
  }

  function parseExam(raw) {
    const body = extractBody(raw);
    const header = {};
    const textbooks = [];
    const questions = [];
    const answerSheet = {};
    const pages = [[]];
    let section = 'header';
    let target = header;
    let activeKey = '';

    function startTextbook() {
      const textbook = {};
      textbooks.push(textbook);
      section = 'textbook';
      target = textbook;
      activeKey = '';
    }

    function startQuestion() {
      const question = {};
      questions.push(question);
      pages[pages.length - 1].push(question);
      section = 'question';
      target = question;
      activeKey = '';
    }

    for (const sourceLine of body.split('\n')) {
      const line = sourceLine.replace(/\s+$/, '');
      const trimmed = line.trim();

      if (trimmed === '[HEADER]') {
        section = 'header'; target = header; activeKey = ''; continue;
      }
      if (trimmed === '[TEXTBOOK]' || trimmed === '[TEXTBOOK_TEXT]') {
        startTextbook(); continue;
      }
      if (trimmed === '[QUESTION]') {
        startQuestion(); continue;
      }
      if (trimmed === '[ANSWER_SHEET]') {
        section = 'answers'; target = answerSheet; activeKey = ''; continue;
      }
      if (trimmed === '[PAGE]') {
        pages.push([]); section = 'page'; target = null; activeKey = ''; continue;
      }
      if (trimmed.startsWith('---')) continue;

      // 사용자가 제안한 간단 표기도 함께 받는다:
      // {지문 내용} = (textbook text 1) 또는 (textbook text 1) = {지문 내용}
      const shorthand = trimmed.match(/^\{([\s\S]+)\}\s*=\s*\((textbook\s+text\s+\d+)\)$/i)
        || trimmed.match(/^\((textbook\s+text\s+\d+)\)\s*=\s*\{([\s\S]+)\}$/i);
      if (shorthand) {
        const normalOrder = trimmed.startsWith('{');
        textbooks.push({
          id: normalOrder ? shorthand[2] : shorthand[1],
          content: normalOrder ? shorthand[1] : shorthand[2]
        });
        activeKey = '';
        continue;
      }

      // [QUESTION] 안에 "textbook text 2"만 한 줄로 적어도 참조로 인식한다.
      if (section === 'question' && /^(textbook\s+text\s+\d+)$/i.test(trimmed)) {
        appendTextbookReference(target, trimmed);
        activeKey = '';
        continue;
      }

      const field = line.match(/^\s*([A-Za-z][A-Za-z0-9_ -]*|\d+)\s*=\s*(.*)$/);
      const key = field ? field[1].trim() : '';
      const allowed = section === 'header' ? /^(title|subject|difficulty|date|total)$/i
        : section === 'textbook' ? /^(id|title|source|content)$/i
        : section === 'question' ? /^(num|type|textbook|textbook_text|text|bogi_[1-3]|choice[1-5]|answer|answer_text|point|explain)$/i
        : section === 'answers' ? /^\d+$/ : /$a/;
      if (field && target && allowed.test(key)) {
        target[key] = field[2];
        activeKey = key;
        continue;
      }

      // text=, content=, explain= 등은 다음 필드/블록 전까지 여러 줄을 보존한다.
      if (target && activeKey) {
        target[activeKey] = String(target[activeKey] || '') + '\n' + line;
      }
    }

    for (const obj of [header, answerSheet, ...textbooks, ...questions]) {
      for (const key of Object.keys(obj)) obj[key] = String(obj[key]).trim();
    }

    return { header, textbooks, questions, answerSheet, pages };
  }

  function splitTextbookReferences(value) {
    const source = String(value || '');
    const named = source.match(/textbook\s+text\s+\d+/gi);
    if (named && named.length) return named;
    return source.split(/[,;|\n]/).map(v => v.trim()).filter(Boolean);
  }

  function getQuestionPassages(question, textbooks) {
    const lookup = new Map((textbooks || []).map(item => [normalizeTextbookId(item.id), item]));
    const refs = splitTextbookReferences(question && (question.textbook || question.textbook_text));
    const seen = new Set();
    return refs.map(ref => lookup.get(normalizeTextbookId(ref))).filter(item => {
      if (!item) return false;
      const id = normalizeTextbookId(item.id);
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
  }

  function serializeExam(header, textbooks, questions, answerSheet) {
    let output = `${START}\n[HEADER]\n`;
    const headerOrder = ['title', 'subject', 'difficulty', 'date', 'total'];
    const headerKeys = [...headerOrder, ...Object.keys(header || {}).filter(k => !headerOrder.includes(k))];
    for (const key of headerKeys) {
      if (header && header[key] !== undefined && String(header[key]).trim()) output += `${key}=${String(header[key]).trim()}\n`;
    }

    for (const item of textbooks || []) {
      output += '\n[TEXTBOOK]\n';
      const order = ['id', 'title', 'source', 'content'];
      const keys = [...order, ...Object.keys(item).filter(k => !order.includes(k))];
      for (const key of keys) {
        if (item[key] !== undefined && String(item[key]).trim()) output += `${key}=${String(item[key]).trim()}\n`;
      }
    }

    const questionOrder = ['num', 'type', 'textbook', 'text', 'bogi_1', 'bogi_2', 'bogi_3',
      'choice1', 'choice2', 'choice3', 'choice4', 'choice5', 'answer', 'answer_text', 'point', 'explain'];
    for (const question of questions || []) {
      output += '\n[QUESTION]\n';
      const keys = [...questionOrder, ...Object.keys(question).filter(k => !questionOrder.includes(k))];
      for (const key of keys) {
        if (question[key] !== undefined && String(question[key]).trim()) output += `${key}=${String(question[key]).trim()}\n`;
      }
    }

    output += '\n[ANSWER_SHEET]\n';
    for (const question of questions || []) {
      const number = String(question.num || '').trim();
      const supplied = answerSheet && answerSheet[number];
      const answer = question.answer_text || question.answer || supplied || '';
      if (number && String(answer).trim()) output += `${number}=${String(answer).trim()}\n`;
    }
    return output + END;
  }

  return { extractBody, normalizeTextbookId, parseExam, getQuestionPassages, serializeExam };
});

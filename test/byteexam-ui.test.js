'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

test('byteexam 3s 과목 버튼과 과목별 선택 제한이 포함된다', () => {
  assert.match(html, /byteexam <span class="badge">3s<\/span>/);
  for (const subject of ['사회', '정보', '파이썬']) {
    assert.match(html, new RegExp(`class="aig-subject-btn" data-subj="${subject}" onclick="selectAigSubject\\('${subject}'\\)"`));
  }
  assert.match(html, /const highSchoolOnly = subj === '정보' \|\| subj === '파이썬'/);
  assert.match(html, /const supportsRegion = subj === '사회' \|\| subj === '수학'/);
});

test('내신 난이도 선택은 요청한 다섯 단계로 유지된다', () => {
  const select = html.match(/<select id="diffSel">([\s\S]*?)<\/select>/);
  assert.ok(select);
  const values = [...select[1].matchAll(/<option value="([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(values, ['기본', '실력', '강남8학군+전국단위자사고', '모의고사변형', '과학고+영재고']);
});

test('교과서 지문 DSL과 전용 파서를 페이지에서 불러온다', () => {
  assert.match(html, /<script src="\/byteexam-dsl\.js"><\/script>/);
  assert.match(html, /id=textbook text 1/);
  assert.match(html, /textbook=textbook text 1/);
});

test('인라인 애플리케이션 스크립트 문법이 유효하다', () => {
  const blocks = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)]
    .map(match => match[1]).filter(source => source.trim());
  for (const source of blocks) assert.doesNotThrow(() => new Function(source));
});

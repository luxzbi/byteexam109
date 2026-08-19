'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseExam, getQuestionPassages, serializeExam } = require('../public/byteexam-dsl');

test('여러 줄 교과서 지문을 보존하고 문제 참조를 연결한다', () => {
  const parsed = parseExam(`---BYTEEXAM-START---
[HEADER]
title=사회 시험
[TEXTBOOK]
id=textbook text 1
title=헌법과 기본권
source=국가법령정보센터
content=모든 국민은 인간으로서의 존엄과 가치를 가진다.
국가는 개인의 기본적 인권을 보장할 의무를 진다.
[QUESTION]
num=1
type=5choice
textbook=textbook text 1
text=윗글을 바르게 이해한 것은?
answer=2
---BYTEEXAM-END---`);

  assert.equal(parsed.textbooks[0].content, '모든 국민은 인간으로서의 존엄과 가치를 가진다.\n국가는 개인의 기본적 인권을 보장할 의무를 진다.');
  assert.equal(getQuestionPassages(parsed.questions[0], parsed.textbooks)[0].title, '헌법과 기본권');
});

test('간단 지문 정의와 문제 안의 단독 textbook text 참조를 인식한다', () => {
  const parsed = parseExam(`{교과서형 재구성 지문} = (textbook text 2)
[QUESTION]
num=1
text=다음 글을 읽고 답하시오.
textbook text 2
answer=1`);

  assert.equal(parsed.questions[0].textbook, 'textbook text 2');
  assert.equal(getQuestionPassages(parsed.questions[0], parsed.textbooks)[0].content, '교과서형 재구성 지문');
});

test('직렬화 후에도 교과서 지문과 참조가 유지된다', () => {
  const source = {
    header: { title: '정보 시험', subject: '정보', total: '1' },
    textbooks: [{ id: 'textbook text 1', title: '알고리즘', content: '첫째 줄\n둘째 줄' }],
    questions: [{ num: '1', type: '5choice', textbook: 'textbook text 1', text: '적절한 것은?', answer: '3' }]
  };
  const roundTrip = parseExam(serializeExam(source.header, source.textbooks, source.questions));
  assert.equal(roundTrip.textbooks[0].content, '첫째 줄\n둘째 줄');
  assert.equal(roundTrip.questions[0].textbook, 'textbook text 1');
  assert.equal(roundTrip.answerSheet['1'], '3');
});

test('기존 여러 줄 PASSAGE와 지문 안 등호를 필드 손실 없이 보존한다', () => {
  const parsed = parseExam(`---BYTEEXAM-START---
[TEXTBOOK]
id=textbook text 1
content=경제 자료
GDP=국내 총생산을 뜻한다.
[QUESTION]
num=1
type=5choice
text=다음 글을 읽고 답하시오. [PASSAGE:자료
첫째 줄
둘째 줄] 핵심 내용은?
choice1=① 첫 번째 선택지
answer=1
---BYTEEXAM-END---`);

  assert.equal(parsed.textbooks[0].content, '경제 자료\nGDP=국내 총생산을 뜻한다.');
  assert.match(parsed.questions[0].text, /첫째 줄\n둘째 줄/);
  assert.equal(parsed.questions[0].choice1, '① 첫 번째 선택지');
});

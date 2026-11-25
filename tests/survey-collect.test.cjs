const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { runInNewContext } = require('node:vm');

/* The encrypted survey's collect() must keep exactly what collect_answers() in src/surveys.php keeps. */
const browser = {};
for (const file of ['flow.js', 'survey-collect.js']) runInNewContext(readFileSync(join(__dirname, '../assets', file), 'utf8'), browser);
const S = browser.MijnSurvey;
/** Values made inside the vm context have another prototype; compare plain copies. */
const plain = (v) => JSON.parse(JSON.stringify(v));

/** Enough of FormData for collect(): posted fields by name. */
function form(fields) {
  return {
    get: (name) => (name in fields && !Array.isArray(fields[name]) ? fields[name] : null),
    getAll: (name) => (Array.isArray(fields[name]) ? fields[name] : name in fields ? [fields[name]] : []),
  };
}

/** Yes/no question 1 sends Ja to 2 and Nee to 3, both continue at 4 (as in tests/answers_test.php). */
function branch(r2 = false, r3 = false, r1 = false) {
  return {
    questions: [
      { id: 1, type: 'yesno', required: r1, choices: [] }, { id: 2, type: 'short', required: r2, choices: [] },
      { id: 3, type: 'short', required: r3, choices: [] }, { id: 4, type: 'short', required: false, choices: [] },
    ],
    links: [{ next: 3, routes: [1, 2] }, { next: 3, routes: null }, { next: 3, routes: null }, { next: 4, routes: null }],
    t: {},
  };
}

test('answers on the stream not taken are dropped and reported as skipped', () => {
  const [answers, errors, skipped] = plain(S.collect(branch(), form({ 'q[1]': 'ja', 'q[2]': 'a', 'q[3]': 'b', 'q[4]': 'c' })));
  assert.deepEqual(errors, {});
  assert.deepEqual(answers, { 1: 'Ja', 2: 'a', 4: 'c' });
  assert.deepEqual(skipped, [3]);
});

test('a required question off the route is no error', () => {
  const [answers, errors] = plain(S.collect(branch(false, true), form({ 'q[1]': 'ja', 'q[2]': 'a' })));
  assert.deepEqual(errors, {});
  assert.deepEqual(answers, { 1: 'Ja', 2: 'a' });
});

test('a required question on the route is an error', () => {
  const [, errors] = plain(S.collect(branch(true), form({ 'q[1]': 'ja' })));
  assert.deepEqual(Object.keys(errors), ['2']);
});

test('a required split left unanswered gets the error and nothing after it is required', () => {
  const [, errors, skipped] = plain(S.collect(branch(true, true, true), form({})));
  assert.deepEqual(Object.keys(errors), ['1']);
  assert.deepEqual(skipped, [2, 3, 4]);
});

test('a single choice routes by the position of the picked choice', () => {
  const seal = branch();
  seal.questions[0] = { id: 1, type: 'single', required: false, choices: ['A', 'B'] };
  const [answers, errors, skipped] = plain(S.collect(seal, form({ 'q[1]': '1', 'q[2]': 'a', 'q[3]': 'b' })));
  assert.deepEqual(errors, {});
  assert.deepEqual(answers, { 1: 'B', 3: 'b' });
  assert.deepEqual(skipped, [2]);
});

test('an invalid answer off the route is no error either', () => {
  const seal = branch();
  seal.questions[2] = { id: 3, type: 'email', required: false, choices: [] };
  const [, errors] = plain(S.collect(seal, form({ 'q[1]': 'ja', 'q[3]': 'geen-adres' })));
  assert.deepEqual(errors, {});
});

test('without links every question is on the route, as before branching', () => {
  const seal = { questions: [{ id: 5, type: 'multi', required: false, choices: ['A', 'B', 'C'] }, { id: 6, type: 'scale', required: true, choices: [], min: 0, max: 10 }], t: { 'Deze vraag is verplicht.': 'Required.' } };
  const [answers, errors, skipped] = plain(S.collect(seal, form({ 'q[5][]': ['2', '0', '9'] })));
  assert.deepEqual(answers, { 5: ['A', 'C'] });
  assert.deepEqual(errors, { 6: 'Required.' });
  assert.deepEqual(skipped, []);
});

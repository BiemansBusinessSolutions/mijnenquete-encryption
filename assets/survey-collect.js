/*
 * The answers of a survey form, checked in the browser: the same checks and stored values as
 * collect_answers() in src/surveys.php. Encrypted surveys seal what this returns; the survey page
 * also uses it to see which questions are on the route. Needs assets/flow.js (MijnFlow).
 */
(function (global) {
  'use strict';

  var strip = function (s, max) { return String(s || '').replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').trim().slice(0, max); };

  /** The stored value of question q, or an error text when what was typed is not valid. */
  function read(q, data, T) {
    var name = 'q[' + q.id + ']';
    var raw = data.get(name);
    switch (q.type) {
      case 'multi': {
        var picked = data.getAll(name + '[]').map(Number).filter(function (i) { return Number.isInteger(i) && i in q.choices; })
          .sort(function (a, b) { return a - b; });
        return picked.length ? { value: picked.filter(function (i, k) { return picked.indexOf(i) === k; }).map(function (i) { return q.choices[i]; }) } : {};
      }
      case 'single': case 'dropdown':
        return raw !== null && /^\d+$/.test(raw) && Number(raw) in q.choices ? { value: q.choices[Number(raw)] } : {};
      case 'yesno':
        return raw === 'ja' || raw === 'nee' ? { value: raw === 'ja' ? 'Ja' : 'Nee' } : {};
      case 'stars': case 'scale': {
        var min = q.type === 'stars' ? 1 : q.min;
        var max = q.type === 'stars' ? 5 : q.max;
        return raw !== null && /^\d+$/.test(raw) && Number(raw) >= min && Number(raw) <= max ? { value: String(Number(raw)) } : {};
      }
      case 'date': {
        var day = strip(raw, 10);
        if (day === '') return {};
        var d = new Date(day + 'T00:00:00Z');
        if (/^\d{4}-\d{2}-\d{2}$/.test(day) && !isNaN(d) && d.toISOString().slice(0, 10) === day) return { value: day };
        return { invalid: T('Kies een geldige datum.') };
      }
      case 'email': {
        var address = strip(raw, 190);
        if (address === '') return {};
        if (/^[^\s@"(),:;<>[\]\\]+@[^\s@"(),:;<>[\]\\]+\.[^\s@"(),:;<>[\]\\.]{2,}$/.test(address)) return { value: address };
        return { invalid: T('Vul een geldig e-mailadres in, zoals naam@voorbeeld.nl.') };
      }
      default: {
        var text = strip(raw, q.type === 'long' ? 5000 : 500);
        return text !== '' ? { value: text } : {};
      }
    }
  }

  /**
   * [answers, errors, skipped] from form data ({get, getAll}, such as FormData). seal holds the
   * questions, their links in index form (none: every question in order) and t, the translations.
   * Only questions on the route count: the others are dropped, never required and listed in skipped.
   */
  function collect(seal, data) {
    var texts = seal.t || {};
    var T = function (key) { return texts[key] || key; };
    var questions = seal.questions;
    var links = seal.links || questions.map(function (q, i) { return { next: i + 1, routes: null }; });
    var got = questions.map(function (q) { return read(q, data, T); });
    var values = {};
    questions.forEach(function (q, i) { if ('value' in got[i]) values[q.id] = got[i].value; });
    var route = global.MijnFlow.route(questions, links, values);
    var answers = {};
    var errors = {};
    questions.forEach(function (q, i) {
      if (route.indexOf(q.id) < 0) return;
      if (got[i].invalid) errors[q.id] = got[i].invalid;
      else if ('value' in got[i]) answers[String(q.id)] = got[i].value;
      else if (q.required) errors[q.id] = T('Deze vraag is verplicht.');
    });
    return [answers, errors, global.MijnFlow.skipped(questions, links, values)];
  }

  /* An encrypted answer and its copies for collaborators go in one post, and post_max_size is 6M: a post that is larger
     arrives empty and the answer is lost. Copies are added only while the whole stays under this many characters; the
     owner's back-fill brings the ones left out. */
  var COPY_BUDGET = 5000000;
  /** Whether a copy of copyLength still fits after used characters (the answer and the copies so far). */
  function copyFits(used, copyLength) { return used + copyLength < COPY_BUDGET; }

  global.MijnSurvey = { collect: collect, copyFits: copyFits, COPY_BUDGET: COPY_BUDGET };
})(typeof window !== 'undefined' ? window : this);

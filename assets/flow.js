/*
 * Survey branching in the browser: the same route walk as src/flow.php, so the survey page can
 * show and hide questions as people answer. Links are in index form: a list aligned with the
 * questions, each {next, routes}, where targets are positions in that list and the end of the
 * survey is questions.length. A null route means "same as next". No dependencies.
 */
(function (global) {
  'use strict';

  var SPLIT = ['single', 'dropdown', 'yesno'];

  /** The route index a stored answer belongs to: its place in choices, or Ja/Nee for yes/no. */
  function choiceIndex(q, value) {
    if (q.type === 'yesno') return value === 'Ja' ? 0 : value === 'Nee' ? 1 : null;
    if (SPLIT.indexOf(q.type) < 0) return null;
    var i = (q.choices || []).indexOf(value);
    return i < 0 ? null : i;
  }

  /**
   * The ids on the route, in order. answers is keyed by question id with stored values. A required
   * split without an answer stops the route; an optional one follows next.
   */
  function route(questions, links, answers) {
    var ids = [];
    var i = 0;
    while (i < questions.length) {
      var q = questions[i];
      var link = links[i];
      var next = link.next;
      ids.push(q.id);
      var value = answers[q.id];
      if (typeof value === 'string' && value !== '') {
        var c = choiceIndex(q, value);
        if (c !== null && link.routes && link.routes[c] != null) next = link.routes[c];
      } else if (q.required && SPLIT.indexOf(q.type) >= 0 && link.routes) {
        break;
      }
      if (next <= i) break; // never loop, even with bad links
      i = next;
    }
    return ids;
  }

  /** The ids not on the route, ascending. */
  function skipped(questions, links, answers) {
    var on = route(questions, links, answers);
    return questions.map(function (q) { return q.id; })
      .filter(function (id) { return on.indexOf(id) < 0; })
      .sort(function (a, b) { return a - b; });
  }

  /**
   * Whether a respondent can ever leave question i by its next. A split only follows next for an
   * answer whose route is null, or (when optional) for no answer: a required split whose answers all
   * have their own route never uses it. required is aligned with links; missing means required.
   */
  function nextCounts(l, i, required) {
    return !l.routes || !l.routes.length || required[i] === false || l.routes.some(function (r) { return r == null; });
  }

  /** Indexes some respondent can reach from the first question: each route (null is next), and next when it counts. */
  function reachable(links, required) {
    var seen = {};
    if (links.length) seen[0] = true;
    links.forEach(function (l, i) {
      if (!seen[i]) return;
      var targets = nextCounts(l, i, required) ? [l.next] : [];
      (l.routes || []).forEach(function (r) { targets.push(r == null ? l.next : r); });
      targets.forEach(function (t) {
        if (t > i && t < links.length) seen[t] = true;
      });
    });
    return seen;
  }

  /**
   * Chains streams until every question is reachable: the first unreachable question U is linked
   * from the last reachable question P before it, by P.next = U when P's next counts, otherwise
   * (a required split whose answers all have their own route) by P's first route past U. Nothing
   * between P and U is reachable, so all of P's targets lie past U. Only that one link changes, so
   * everything before U stays reachable and U becomes reachable: the first unreachable index
   * strictly increases, which ends the loop. required as in reachable(). Returns new links.
   */
  function makeReachable(links, required) {
    required = required || [];
    links = links.map(function (l) { return { next: l.next, routes: l.routes ? l.routes.slice() : null }; });
    for (;;) {
      var seen = reachable(links, required);
      var u = -1;
      for (var i = 0; i < links.length; i++) if (!seen[i]) { u = i; break; }
      if (u < 0) return links;
      var p = u - 1;
      while (!seen[p]) p--;
      if (nextCounts(links[p], p, required)) links[p].next = u;
      else {
        // Should every route point backwards (bad links), the first one is used, so U is always linked in.
        var c = 0;
        while (c < links[p].routes.length && !(links[p].routes[c] > u)) c++;
        links[p].routes[c < links[p].routes.length ? c : 0] = u;
      }
    }
  }

  function mapTargets(l, f) {
    return { next: f(l.next), routes: l.routes ? l.routes.map(function (r) { return r == null ? null : f(r); }) : null };
  }

  /**
   * Takes question index out: what pointed at it now points at its next, later targets move down
   * one, and anything left unreachable is chained in. required is aligned with links before the
   * removal. Returns new links.
   */
  function remove(links, index, required) {
    var onward = links[index].next;
    function f(t) {
      if (t === index) t = onward;
      return t > index ? t - 1 : t;
    }
    var out = [];
    links.forEach(function (l, i) { if (i !== index) out.push(mapTargets(l, f)); });
    required = (required || []).slice();
    required.splice(index, 1);
    return makeReachable(out, required);
  }

  /**
   * Makes room for a new question at position at (the end is allowed). Targets from at on move up
   * one, so the new question is unreachable until the caller links to it; no make-reachable here.
   */
  function insert(links, at) {
    var out = links.map(function (l) { return mapTargets(l, function (t) { return t >= at ? t + 1 : t; }); });
    out.splice(at, 0, { next: at + 1, routes: null });
    return out;
  }

  /** Question index no longer splits: its routes go and the streams are chained. */
  function dropRoutes(links, index, required) {
    links = links.map(function (l) { return mapTargets(l, function (t) { return t; }); });
    links[index].routes = null;
    return makeReachable(links, required);
  }

  /** Answer choice of question index is gone: its route goes and a stream left alone is chained in. */
  function choiceRemoved(links, index, choice, required) {
    links = links.map(function (l) { return mapTargets(l, function (t) { return t; }); });
    if (links[index].routes) links[index].routes.splice(choice, 1);
    return makeReachable(links, required);
  }

  /**
   * The survey as nested lanes, for the builder's flow diagram. required is a boolean array aligned
   * with links (missing means required); it matters only because an optional split also gets a
   * no-answer lane when its next differs from every route. Returns a Seq:
   *   Seq  = Item[]
   *   Item = {q: index} | {split: index, lanes: Lane[], join: index|n}
   *   Lane = {answers: number[] (choice indexes, [] for the no-answer lane), seq: Seq, jump: index|n|null}
   * A split's join is its immediate post-dominator (n is the end). There is one lane per distinct
   * target; a lane whose target is the join has an empty seq, drawn as a straight line. Lanes that
   * meet at d before the join become one lane holding a nested block {split: same split, join: d},
   * followed by the questions from d to the join. Nothing is drawn twice: a lane that reaches a
   * question already drawn elsewhere stops there with jump set, drawn as a "ga naar" chip. Lanes are
   * ordered by their first answer, the no-answer lane last. Every index appears exactly once.
   */
  function layout(links, required) {
    var n = links.length;
    required = required || [];
    function ok(t, i) { return typeof t === 'number' && t > i && t <= n ? t : n; }
    function isSplit(i) { return Array.isArray(links[i].routes) && links[i].routes.length > 0; }

    /** Split i's distinct targets in first-seen order, and the answers going to each (no-answer: []). */
    function targetsOf(i) {
      var l = links[i];
      var next = ok(l.next, i);
      var map = {};
      var order = [];
      l.routes.forEach(function (r, c) {
        var t = r == null ? next : ok(r, i);
        if (!map[t]) { map[t] = []; order.push(t); }
        map[t].push(c);
      });
      if (required[i] === false && !map[next]) { map[next] = []; order.push(next); }
      return { map: map, order: order };
    }

    // Immediate post-dominators over the forward graph: every edge goes up, so walk from the end.
    var ipdom = new Array(n + 1);
    for (var i = n - 1; i >= 0; i--) {
      var succ = isSplit(i) ? targetsOf(i).order : [ok(links[i].next, i)];
      var d = succ[0];
      for (var k = 1; k < succ.length; k++) {
        var b = succ[k];
        while (d !== b) { if (d < b) d = ipdom[d]; else b = ipdom[b]; }
      }
      ipdom[i] = d;
    }

    var placed = {};

    /** Lays out from cur along the post-dominator chain up to stop; a drawn question ends it in a jump. */
    function seqFrom(cur, stop) {
      var seq = [];
      while (cur !== stop) {
        if (placed[cur]) return { seq: seq, jump: cur };
        placed[cur] = true;
        if (isSplit(cur)) {
          var blk = block(cur);
          seq.push(blk);
          cur = blk.join;
        } else {
          seq.push({ q: cur });
          cur = ipdom[cur];
        }
      }
      return { seq: seq, jump: null };
    }

    function block(s) {
      var tg = targetsOf(s);
      var join = ipdom[s];
      // The part of the post-dominator tree between the targets and the join: lanes are its branches.
      var children = {};
      tg.order.forEach(function (t) {
        for (var x = t; x !== join; x = ipdom[x]) {
          var p = ipdom[x];
          children[p] = children[p] || [];
          if (children[p].indexOf(x) >= 0) break;
          children[p].push(x);
        }
      });
      function below(x) {
        var out = tg.map[x] ? [x] : [];
        (children[x] || []).forEach(function (c) { out = out.concat(below(c)); });
        return out;
      }
      function answersOf(ts) {
        var a = [];
        ts.forEach(function (t) { a = a.concat(tg.map[t]); });
        return a.sort(function (p, q) { return p - q; });
      }
      function key(a) { return a.length ? a[0] : Infinity; }

      /** The lanes that meet at r: one per branch below r, plus an empty one if r is a target. */
      function lanesAt(r) {
        var parts = [];
        if (tg.map[r]) parts.push({ targets: [r], empty: true });
        (children[r] || []).forEach(function (c) { parts.push({ targets: below(c), top: c }); });
        parts.forEach(function (p) { p.answers = answersOf(p.targets); });
        parts.sort(function (p, q) { return key(p.answers) - key(q.answers); });
        return parts.map(function (p) {
          if (p.empty) return { answers: p.answers, seq: [], jump: null };
          if (p.targets.length === 1) {
            var one = seqFrom(p.targets[0], r);
            return { answers: p.answers, seq: one.seq, jump: one.jump };
          }
          // Several lanes meet at d before r: the lowest point all of them pass.
          var d = p.top;
          while (!tg.map[d] && children[d].length === 1) d = children[d][0];
          var inner = { split: s, lanes: lanesAt(d), join: d };
          var rest = seqFrom(d, r);
          return { answers: p.answers, seq: [inner].concat(rest.seq), jump: rest.jump };
        });
      }

      return { split: s, lanes: lanesAt(join), join: join };
    }

    var out = n ? seqFrom(0, n).seq : [];
    // Safety net: the editor keeps every question reachable, but never lose one from the drawing.
    for (var u = 0; u < n; u++) if (!placed[u]) { placed[u] = true; out.push({ q: u }); }
    return out;
  }

  global.MijnFlow = {
    route: route, skipped: skipped, makeReachable: makeReachable, choiceIndex: choiceIndex,
    remove: remove, insert: insert, dropRoutes: dropRoutes, choiceRemoved: choiceRemoved,
    layout: layout
  };
})(typeof window !== 'undefined' ? window : this);

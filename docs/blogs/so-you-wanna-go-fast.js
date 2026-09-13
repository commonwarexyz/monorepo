(() => {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const ITEMS = ['A1', 'B1', 'C1', 'A2', 'B2', 'C2', 'A3', 'C3'];
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  const clamp = value => Math.max(0, Math.min(1, value));

  function element(tag, attrs = {}, content = '', svg = false) {
    const node = svg ? document.createElementNS(NS, tag) : document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    if (content) node.textContent = content;
    return node;
  }

  function draw(parent, tag, attrs, content) {
    const node = element(tag, attrs, content, true);
    parent.append(node);
    return node;
  }

  function label(parent, x, y, content, attrs = {}) {
    return draw(parent, 'text', { x, y, ...attrs }, content);
  }

  function cell(parent, x, y, width, content) {
    const group = draw(parent, 'g', { class: 'log-cell', 'data-state': 'empty' });
    draw(group, 'rect', { x, y, width, height: 28 });
    const text = label(group, x + width / 2, y + 18, content, { 'text-anchor': 'middle' });
    return (state, value = content) => {
      group.dataset.state = state;
      text.textContent = value;
    };
  }

  function order(svg) {
    label(svg, 18, 22, 'One settled pass', { 'font-weight': 'bold' });
    label(svg, 18, 42, 'offset', { class: 'log-small log-muted' });
    ['A', 'B', 'C'].forEach((name, col) => {
      label(svg, 104 + col * 88, 42, name, { 'text-anchor': 'middle' });
      draw(svg, 'path', { d: `M ${104 + col * 88} 50 V ${col === 1 ? 117 : 155}`, class: 'log-wire' });
    });
    const sweep = draw(svg, 'rect', { x: 65, y: 48, width: 247, height: 34, class: 'log-sweep', opacity: 0 });
    const produced = ITEMS.map(item => {
      const col = 'ABC'.indexOf(item[0]);
      const row = Number(item[1]) - 1;
      return cell(svg, 76 + col * 88, 51 + row * 38, 56, item);
    });
    const arrivals = [1, 2, 1, 2, 3, 2, 3, 3];
    [1, 2, 3].forEach((offset, i) => label(svg, 38, 70 + i * 38, String(offset), { 'text-anchor': 'middle', class: 'log-muted' }));
    const frontier = label(svg, 18, 184, 'Frontier: waiting', { class: 'log-small' });
    const route = draw(svg, 'path', { class: 'log-route', opacity: 0 });
    label(svg, 18, 211, 'Output positions', { 'font-weight': 'bold' });
    const output = ITEMS.map((item, i) => {
      const x = 18 + (i % 4) * 84;
      const y = 240 + Math.floor(i / 4) * 64;
      draw(svg, 'rect', { x, y, width: 70, height: 14, fill: '#fff', stroke: '#bbb', 'stroke-width': 1 });
      label(svg, x + 35, y + 10, String(i + 1), { 'text-anchor': 'middle', class: 'log-small log-muted' });
      return cell(svg, x, y + 14, 70, item);
    });
    return {
      height: 356, steps: 14,
      render(step) {
        const count = Math.max(0, Math.min(8, step - 4));
        const current = count ? ITEMS[count - 1] : null;
        produced.forEach((set, i) => set(i < count ? 'acked' : step >= arrivals[i] ? 'produced' : 'empty'));
        output.forEach((set, i) => set(i < count ? 'produced' : 'empty', i < count ? ITEMS[i] : '·'));
        frontier.textContent = step < 4 ? 'Frontier: waiting' : 'Finalized frontier [3, 2, 3]';
        sweep.setAttribute('opacity', current ? 1 : 0);
        route.setAttribute('opacity', current && step < 13 ? 1 : 0);
        if (current) {
          const row = Number(current[1]) - 1;
          const x = 104 + 'ABC'.indexOf(current[0]) * 88;
          const y = 79 + row * 38;
          const dest = 53 + ((count - 1) % 4) * 84;
          const bottom = 240 + Math.floor((count - 1) / 4) * 64;
          const approach = bottom - 12;
          sweep.setAttribute('y', 48 + row * 38);
          route.setAttribute('d', `M ${x} ${y} V ${y + 5} H 354 V ${approach} H ${dest} V ${bottom - 3} m -4 -5 l 4 5 l 4 -5`);
        }
        if (step < 4) return 'Each producer extends its own chain. Arrival order assigns no output position.';
        if (step === 4) return 'The frontier settles. Sweep each segment offset in producer order: A, B, C.';
        if (step < 13) return `Offset ${current[1]}: reference ${current} takes output position ${count}. No body read is needed.`;
        return 'A1 B1 C1 A2 B2 C2 A3 C3. Skip B at offset 3: its settled segment has ended.';
      },
    };
  }

  function positionLane(svg, y, title, titleGap = 10) {
    label(svg, 18, y - titleGap, title, { 'font-weight': 'bold' });
    return ITEMS.slice(0, 6).map((item, i) => cell(svg, 18 + i * 54, y, 48, item));
  }

  function fetch(svg) {
    const bodies = positionLane(svg, 61, 'Body in custody (durable)', 38);
    ITEMS.slice(0, 6).forEach((_, i) => label(svg, 42 + i * 54, 51, String(i + 1), { 'text-anchor': 'middle', class: 'log-small log-muted' }));
    const windowLine = draw(svg, 'path', { class: 'log-window' });
    const prefixLine = draw(svg, 'path', { class: 'log-ready-line' });
    const cursor = label(svg, 18, 135, 'Ready prefix: 0');
    const windowText = label(svg, 18, 113, 'Custody window: 1–5 (limit: 5)', { class: 'log-small', fill: '#1f1fd1' });
    const archive = cell(svg, 18, 157, 146, 'Index/history sync');
    const checkpoint = cell(svg, 194, 157, 146, 'Checkpoint sync');
    draw(svg, 'path', { d: 'M 169 171 H 189 m -5 -4 l 5 4 l -5 4', class: 'log-wire' });
    const phase = label(svg, 18, 211, 'Publication waits for both syncs', { class: 'log-small' });
    const published = positionLane(svg, 245, 'Published output references');
    const completion = [1, 6, 2, 8, 3, 4];
    return {
      height: 286, steps: 14,
      render(step) {
        const ready = completion.map(at => step >= at);
        let prefix = 0;
        while (ready[prefix]) prefix++;
        bodies.forEach((set, i) => set(ready[i] ? 'ready' : i < prefix + 5 ? 'pending' : 'empty', ITEMS[i]));
        const left = 18 + prefix * 54;
        const width = Math.min(5, 6 - prefix) * 54 - 6;
        windowLine.setAttribute('d', prefix < 6 ? `M ${left} 94 v 5 h ${width} v -5` : '');
        prefixLine.setAttribute('d', prefix ? `M 18 91 H ${12 + prefix * 54}` : '');
        windowText.textContent = prefix === 6 ? 'Custody window drained (limit: 5)' : `Custody window: ${prefix + 1}–${Math.min(6, prefix + 5)} (limit: 5)`;
        cursor.textContent = `Ready prefix: ${prefix} / 6`;
        archive(step >= 10 ? 'ready' : step === 9 ? 'acked' : 'empty', step >= 10 ? 'Index/history saved' : step === 9 ? 'Syncing records' : 'Index/history sync');
        checkpoint(step >= 12 ? 'ready' : step === 11 ? 'acked' : 'empty', step >= 12 ? 'Checkpoint saved' : step === 11 ? 'Checkpoint syncing' : 'Checkpoint sync');
        published.forEach((set, i) => set(step >= 12 ? 'committed' : 'empty', step >= 12 ? ITEMS[i] : '·'));
        phase.textContent = step >= 12 ? 'Durable checkpoint → delivery may begin' : step >= 10 ? 'Index/history durable. Checkpoint next' : 'Publication waits for both syncs';
        if (!step) return 'Order is known. Track custody for positions 1–5. Position 6 waits outside this five-slot window.';
        if (step === 1) return 'A1 is durable and enters the publication batch. Its custody-window slot becomes available for position 6.';
        if (step === 2) return 'C1 reaches durable custody at position 3. The ready prefix still waits for B1 at position 2.';
        if (step === 3) return 'B2 reaches durable custody at position 5. B1 is still missing, so the ready prefix remains at 1.';
        if (step < 6) return 'C2 is also durable. Positions 3, 5, and 6 are ready, but missing B1 holds the prefix at 1.';
        if (step < 8) return 'Body 2 reaches durable custody. The ready prefix advances from 1 to 3, then waits for body 4.';
        if (step === 8) return 'Body 4 closes the gap. All six bodies are durable. Their output references are ready to publish.';
        if (step < 11) return 'First synchronize the output index and consensus history. A ready prefix alone is not published progress.';
        if (step === 11) return 'Then synchronize the checkpoint naming this batch. Delivery still waits.';
        return 'The checkpoint is durable. Publish references 1–6 in order so delivery can now locate their durable bodies.';
      },
    };
  }

  function recovery(svg) {
    const index = positionLane(svg, 37, 'Persisted output index');
    index.forEach((set, i) => set('committed', `${i + 1}:${ITEMS[i]}`));
    const route = draw(svg, 'path', { class: 'log-route', opacity: 0 });
    const deliveries = positionLane(svg, 104, 'Application delivery');
    const acks = positionLane(svg, 165, 'Application ack received');
    const durable = draw(svg, 'path', { class: 'log-cursor' });
    const cursor = label(svg, 18, 219, 'Durable ack cursor: 0');
    const sync = cell(svg, 18, 239, 162, 'Cursor sync: idle');
    const phase = label(svg, 193, 258, 'Live', { fill: '#1f1fd1' });
    return {
      height: 284, steps: 21,
      render(step) {
        const crashed = step >= 10;
        const received = crashed
          ? [true, true, step >= 16, step >= 16, step >= 17, step >= 17]
          : [step >= 2, step >= 3, false, step >= 7, step >= 8, false];
        const prefix = step >= 19 ? 6 : step >= 5 ? 2 : 0;
        const replay = step >= 12 ? Math.min(4, step - 11) : 0;
        deliveries.forEach((set, i) => {
          const replayed = crashed && i >= 2 && i < 2 + replay;
          set(replayed ? 'replay' : (!crashed && step >= 1) || (crashed && i < 2) ? 'sent' : 'empty',
            replayed ? ITEMS[i] : crashed && i >= 2 ? '·' : step >= 1 ? ITEMS[i] : '·');
        });
        acks.forEach((set, i) => set(i < prefix ? 'acked' : received[i] ? 'ready' : 'empty', i < prefix ? 'saved' : received[i] ? 'yes' : '—'));
        durable.setAttribute('d', prefix ? `M 18 199 H ${12 + prefix * 54}` : '');
        cursor.textContent = `Durable ack cursor: ${prefix}`;
        const syncing = step === 4 || step === 18;
        sync(syncing ? 'acked' : prefix ? 'ready' : 'empty', syncing ? 'Cursor syncing…' : prefix ? `Cursor ${prefix} synced` : 'Cursor sync: idle');
        phase.textContent = step === 10 || step === 11 ? 'CRASH' : crashed ? 'Restart' : 'Live';
        phase.setAttribute('fill', step === 10 || step === 11 ? '#d9251c' : '#1f1fd1');
        route.setAttribute('opacity', step >= 12 && step <= 15 ? 1 : 0);
        if (replay) {
          const x = 42 + (replay + 1) * 54;
          route.setAttribute('d', `M ${x} 67 V 91 m -4 -5 l 4 5 l 4 -5`);
        }
        if (!step) return 'Six output references and their bodies are durable. The application has acknowledged none.';
        if (step === 1) return 'Deliver all six positions. Delivery does not advance the durable acknowledgement cursor.';
        if (step === 2) return 'Ack 1 arrives. It is held in memory. The durable cursor is still 0.';
        if (step === 3) return 'Ack 2 arrives too. Both acknowledgements are in memory. The durable cursor is still 0.';
        if (step === 4) return 'Synchronize acknowledgement cursor 2. Until sync succeeds, recovery still starts at 1.';
        if (step < 7) return 'Sync succeeds: cursor 2 is durable. Recovery can now skip positions 1 and 2.';
        if (step === 7) return 'Ack 4 arrives, but ack 3 is still missing. Ack 4 stays in memory while the durable cursor remains at 2.';
        if (step < 10) return 'Ack 5 arrives too. Missing ack 3 holds the durable cursor at 2. Acks 4 and 5 remain in memory.';
        if (step < 12) return 'Crash: volatile acks 4 and 5 disappear. The persisted index and durable cursor 2 survive.';
        if (step < 16) return 'Read the persisted index after cursor 2. Replay positions 3–6 with their original references.';
        if (step === 16) return 'Fresh acks for 3 and 4 arrive. They are held in memory. The durable cursor remains at 2.';
        if (step === 17) return 'Fresh acks for 5 and 6 arrive too. All six positions are acknowledged, but only cursor 2 is durable.';
        if (step === 18) return 'Synchronize acknowledgement cursor 6. Received acks alone still do not advance it.';
        return 'Sync succeeds: durable cursor 6. A subsequent restart begins after this batch.';
      },
    };
  }

  function spatialCard(parent, width, height) {
    const group = draw(parent, 'g', { class: 'log-space-card', 'data-state': 'empty' });
    draw(group, 'rect', { width, height, rx: 4 });
    const name = label(group, width / 2, 23, '', { 'text-anchor': 'middle', 'font-weight': 'bold' });
    const status = label(group, width / 2, 42, '', { 'text-anchor': 'middle', class: 'log-small' });
    return (x, y, state, identity, detail, visible = true) => {
      group.style.transform = `translate(${x}px, ${y}px)`;
      group.style.opacity = visible ? 1 : 0;
      group.dataset.state = state;
      name.textContent = identity;
      status.textContent = detail;
    };
  }

  function forward(svg) {
    svg.classList.add('log-spatial');
    const names = Array.from({ length: 6 }, (_, i) => `A${i + 1}`);
    label(svg, 18, 24, 'Consensus', { 'font-weight': 'bold' });
    const live = label(svg, 342, 24, 'Selected references', { 'text-anchor': 'end', class: 'log-small log-muted' });
    names.forEach((name, i) => cell(svg, 18 + i * 55, 40, 48, name)('produced'));
    label(svg, 180, 88, 'Authenticated references · bodies needed', { 'text-anchor': 'middle', class: 'log-small log-muted' });
    draw(svg, 'rect', { x: 18, y: 125, width: 246, height: 210, rx: 8, class: 'log-space-workspace' });
    const feed = draw(svg, 'path', { d: 'M141 97 V113 M82 125 V113 H200 V125', class: 'log-space-feed' });
    label(svg, 32, 146, 'Acquire concurrently', { 'font-weight': 'bold' });
    const slotPositions = [[32, 165], [150, 165], [32, 251], [150, 251]];
    slotPositions.forEach(([x, y], i) => {
      label(svg, x, y - 7, `SLOT ${i + 1}`, { class: 'log-space-tiny log-muted' });
      draw(svg, 'rect', { x, y, width: 100, height: 58, rx: 4, class: 'log-space-slot' });
    });
    label(svg, 141, 324, 'Pending + ready ≤ 4', { 'text-anchor': 'middle', class: 'log-small log-muted' });
    label(svg, 303, 174, 'Next', { 'text-anchor': 'middle', class: 'log-small log-muted' });
    const next = cell(svg, 280, 184, 46, 'A1');
    const gate = label(svg, 303, 234, 'Waiting', { 'text-anchor': 'middle', class: 'log-small' });
    const held = label(svg, 303, 252, 'for body', { 'text-anchor': 'middle', class: 'log-small log-muted' });
    draw(svg, 'path', { d: 'M141 336 V367 m-4 -5 l4 5 l4 -5', class: 'log-space-feed' });
    label(svg, 151, 355, 'Consume in chain order', { class: 'log-small' });
    label(svg, 18, 389, 'Consumed by marshal', { 'font-weight': 'bold' });
    const output = names.map((name, i) => cell(svg, 18 + i * 55, 403, 48, name));
    draw(svg, 'path', { d: 'M18 445 H340 m-5 -4 l5 4 l-5 4', class: 'log-wire' });
    label(svg, 180, 464, 'Fixed order · A1 → A2 → A3 → A4 → A5 → A6', { 'text-anchor': 'middle', class: 'log-small log-muted' });
    const refill = label(svg, 18, 487, 'A freed slot admits the next reference', { class: 'log-small log-muted' });
    const cards = names.map(() => spatialCard(svg, 100, 58));
    const arrival = [4, 8, 3, 6, 7, 10];
    const consumption = [5, 9, 11, 12, 13, 14];
    const captions = [
      'Consensus supplies authenticated references A1 through A6. Marshal still needs their bodies.',
      'The references feed marshal’s acquisition workspace. Consensus continues without waiting for body acquisition.',
      'Request A1 through A4 concurrently. Each pending request occupies one of four slots.',
      'A3 arrives first. Its body stays in slot 3 while consumption waits for A1.',
      'A1 arrives. A3 is ready too, but marshal must consume the bodies in chain order.',
      'Consume A1 and refill its slot with a request for A5. A3 still waits behind missing A2.',
      'A4 arrives ahead of A2. Ready bodies occupy slots just as pending requests do.',
      'A5 arrives too. Missing A2 holds three ready bodies in the four-slot workspace.',
      'A2 arrives and closes the gap. The ready bodies can now leave in chain order.',
      'Consume A2 and refill its slot with a request for A6.',
      'A6 arrives. All four occupied slots now contain ready bodies.',
      'Consume A3 next, following the selected chain.',
      'Consume A4. Response order has no effect on chain order.',
      'Consume A5 before A6.',
      'Consume A6. The workspace is empty. All six bodies were consumed in chain order.',
      'Consensus kept running. Marshal used at most four slots, refilling them as it consumed bodies.',
    ];
    return {
      height: 502, steps: captions.length,
      render(step) {
        const prefix = consumption.filter(at => step >= at).length;
        live.textContent = step ? 'Keeps running →' : 'Selected references';
        feed.style.opacity = step >= 1 ? 1 : 0.2;
        cards.forEach((set, i) => {
          const requested = step >= (i < 4 ? 2 : i === 4 ? 5 : 9);
          const done = step >= consumption[i];
          const ready = step >= arrival[i];
          const [x, y] = slotPositions[i % 4];
          set(x, done ? 382 : requested ? y : y - 14, ready ? 'ready' : 'pending', names[i], ready ? 'Body ready' : 'Requesting…', requested && !done);
        });
        next(step < 2 ? 'produced' : prefix === 6 ? 'ready' : step >= arrival[prefix] ? 'ready' : 'pending', prefix === 6 ? '✓' : names[prefix]);
        gate.textContent = step < 2 ? 'Not started' : prefix === 6 ? 'Done' : step >= arrival[prefix] ? 'Ready' : 'Waiting';
        const waiting = arrival.filter((at, i) => i > prefix && step >= at && step < consumption[i]).length;
        held.textContent = step < 2 ? '' : prefix === 6 ? '6 consumed' : waiting && step < arrival[prefix] ? `${waiting} held` : 'in order';
        output.forEach((set, i) => set(i < prefix ? 'ready' : 'empty', i < prefix ? names[i] : '·'));
        refill.textContent = step === 5 ? 'Slot 1 refills: A1 leaves → request A5' : step === 9 ? 'Slot 2 refills: A2 leaves → request A6' : 'A freed slot admits the next reference';
        return captions[step];
      },
    };
  }

  function repair(svg) {
    svg.classList.add('log-spatial');
    label(svg, 18, 24, 'Follow exact parents backward', { 'font-weight': 'bold' });
    label(svg, 18, 44, 'Each returned header must match its child', { class: 'log-small log-muted' });
    const paths = ['M278 126 V173 m-4 -5 l4 5 l4 -5', 'M222 204 H138 m5 -4 l-5 4 l5 4', 'M82 173 V126 m-4 5 l4 -5 l4 5'];
    paths.forEach(d => draw(svg, 'path', { d, class: 'log-space-missing' }));
    const links = paths.map(d => draw(svg, 'path', { d, class: 'log-space-link', pathLength: 1 }));
    label(svg, 289, 152, 'parent', { class: 'log-space-tiny log-muted' });
    label(svg, 180, 194, 'parent', { 'text-anchor': 'middle', class: 'log-space-tiny log-muted' });
    label(svg, 26, 152, 'parent', { class: 'log-space-tiny log-muted' });
    const positions = [[30, 68], [30, 175], [226, 175], [226, 68]];
    const headers = positions.map(() => spatialCard(svg, 104, 58));
    const phase = label(svg, 180, 264, 'Two missing headers', { 'text-anchor': 'middle', 'font-weight': 'bold' });
    const detail = label(svg, 180, 284, 'A tip certificate does not carry every ancestor', { 'text-anchor': 'middle', class: 'log-small log-muted' });
    draw(svg, 'path', { d: 'M18 303 H342', class: 'log-wire' });
    label(svg, 18, 330, 'Then acquire bodies forward', { 'font-weight': 'bold' });
    const bodyCards = [spatialCard(svg, 104, 58), spatialCard(svg, 104, 58)];
    const bodyNote = label(svg, 180, 431, 'Header repair comes first', { 'text-anchor': 'middle', class: 'log-small log-muted' });
    draw(svg, 'path', { d: 'M30 475 H330 m-5 -4 l5 4 l-5 4', class: 'log-wire' });
    const consumed = [cell(svg, 98, 455, 64, 'A3'), cell(svg, 198, 455, 64, 'A4')];
    label(svg, 180, 505, 'Consumed by marshal · A3 before A4', { 'text-anchor': 'middle', class: 'log-small log-muted' });
    const captions = [
      'Marshal knows headers A2 and A5. The headers connecting them are missing. A5’s certificate does not contain every ancestor.',
      'A5 names its exact parent commitment. Request the matching header from a peer.',
      'The returned A4 header matches A5’s parent commitment. One link closes. A4 names the next parent.',
      'Request the exact parent header named by A4.',
      'The returned A3 header matches A4’s parent commitment. A3 now points toward the known A2 anchor.',
      'A3’s parent matches A2. The repaired chain joins the known history exactly.',
      'Now request the bodies of A3 and A4 concurrently, within marshal’s bounded acquisition window.',
      'A4’s body arrives first. It waits while A3 is still missing.',
      'A3’s body arrives. Both bodies are ready for consumption in chain order.',
      'Consume A3 first. Repair followed parent commitments backward. Body consumption moves forward.',
      'Consume A4 next. The repaired stretch has been consumed in order.',
    ];
    return {
      height: 522, steps: captions.length,
      render(step) {
        headers.forEach((set, i) => {
          const known = i === 0 || i === 3;
          const found = (i === 2 && step >= 2) || (i === 1 && step >= 4);
          const requesting = (i === 2 && step === 1) || (i === 1 && step === 3);
          const [x, y] = positions[i];
          set(x, y, known ? 'known' : found ? 'ready' : requesting ? 'pending' : 'empty', known || found ? `A${i + 2}` : '?', i === 0 ? 'Known anchor' : i === 3 ? 'Known tip' : found ? 'Verified header' : requesting ? 'From peer…' : 'Missing header');
        });
        links.forEach((link, i) => {
          const verified = step >= [2, 4, 5][i];
          const active = step >= [1, 3, 5][i];
          link.style.strokeDashoffset = active ? 0 : 1;
          link.dataset.state = verified ? 'ready' : 'pending';
        });
        phase.textContent = step === 0 ? 'Two missing headers' : step === 1 ? 'Request A5’s exact parent' : step === 2 ? 'A4 verified against A5' : step === 3 ? 'Request A4’s exact parent' : step === 4 ? 'A3 verified against A4' : 'Connected to the known anchor';
        detail.textContent = step === 0 ? 'A tip certificate does not carry every ancestor' : step < 5 ? 'A matching parent commitment closes each link' : 'A2 ← A3 ← A4 ← A5';
        bodyCards.forEach((set, i) => {
          const done = step >= 9 + i;
          const ready = step >= (i ? 7 : 8);
          set(48 + i * 160, done ? 448 : 351, ready ? 'ready' : step >= 6 ? 'pending' : 'empty', `A${i + 3}`, ready ? 'Body ready' : step >= 6 ? 'Requesting…' : 'Body needed', !done);
        });
        bodyNote.textContent = step < 6 ? 'Header repair comes first' : step === 6 ? 'Two concurrent requests · window limit 4' : step === 7 ? 'A4 waits behind missing A3' : step === 8 ? 'Gap closed · ready to consume' : step === 9 ? 'A3 consumed · A4 is next' : 'Both bodies consumed';
        consumed.forEach((set, i) => set(step >= 9 + i ? 'ready' : 'empty', step >= 9 + i ? `A${i + 3}` : '·'));
        return captions[step];
      },
    };
  }

  const FIGURES = {
    forward: { title: 'Start with what consensus knows', build: forward, description: 'Consensus supplies authenticated references A1 through A6 to marshal, then continues independently. A rolling four-slot window acquires bodies concurrently and refills as marshal consumes them. Responses arrive out of order, but marshal consumes A1 through A6 in order.' },
    repair: { title: 'Fill in the missing history', build: repair, description: 'Marshal knows headers A2 and A5. It requests A4 by the exact parent commitment in A5, verifies A4, then requests and verifies A3 using A4’s parent commitment. A3’s parent matches A2, joining the known history. Forward body acquisition can then resume within the bounded window.' },
    order: { title: 'Histories become positions', build: order, description: 'One settled pass over frontier [3, 2, 3] sweeps segment offsets, then producers, into A1 B1 C1 A2 B2 C2 A3 C3. The gold cursor selects a source row. A blue path connects its reference to an output position.' },
    fetch: { title: 'Ready, then durable publication', build: fetch, description: 'Broadcast bodies reach durable custody out of order. A five-position output window tracks their readiness. The ready prefix advances from 1 to 3 to 6. The output index and consensus history sync first, then the checkpoint syncs, then references are published for delivery.' },
    recovery: { title: 'Received is not yet durable', build: recovery, description: 'Application acks 1 and 2 become durable only after cursor sync. Acks 4 and 5 remain volatile behind missing 3. A crash discards them. Recovery reads persisted output positions 3 through 6, replays them, obtains fresh acks, and syncs cursor 6.' },
  };

  function mountFigure(mount, config, index) {
    if (mount.logDispose) mount.logDispose();
    const id = `log-${mount.dataset.logFigure}-${index}`;
    const heading = element('div', { class: 'log-heading' });
    heading.append(element('strong', {}, config.title));
    const svg = element('svg', { class: 'log-svg', role: 'img', 'aria-labelledby': `${id}-title ${id}-desc` }, '', true);
    draw(svg, 'title', { id: `${id}-title` }, config.title);
    draw(svg, 'desc', { id: `${id}-desc` }, config.description);
    const scene = config.build(svg);
    svg.setAttribute('viewBox', `0 0 360 ${scene.height}`);
    const caption = element('p', { class: 'log-caption', id: `${id}-caption` });
    const controls = element('div', { class: 'log-controls', role: 'group', 'aria-label': `${config.title}: playback` });
    const play = element('button', { type: 'button' });
    const replay = element('button', { type: 'button', 'aria-label': `Replay ${config.title}` }, 'Replay');
    const scrubLabel = element('label', { class: 'log-scrub' }, 'Time');
    const scrub = element('input', { type: 'range', min: 0, max: scene.steps, step: 0.01, 'aria-label': `Timeline: ${config.title}`, 'aria-describedby': `${id}-caption` });
    const counter = element('span', { class: 'log-step', 'aria-hidden': 'true' });
    scrubLabel.append(scrub);
    controls.append(play, replay, scrubLabel, counter);
    mount.replaceChildren(heading, svg, caption, controls);
    mount.classList.add('log-figure');

    let time = 0;
    let playing = !reduced.matches;
    let visible = false;
    let frame = 0;
    let last = 0;
    let step = -1;
    let disposed = false;

    function render() {
      const next = Math.min(scene.steps - 1, Math.floor(time));
      if (next !== step) {
        step = next;
        caption.textContent = scene.render(step);
        counter.textContent = `${step}/${scene.steps - 1}`;
        scrub.setAttribute('aria-valuetext', `Step ${step} of ${scene.steps - 1}. ${caption.textContent}`);
      }
      scrub.value = time;
      play.textContent = playing ? 'Pause' : 'Play';
      play.setAttribute('aria-label', `${playing ? 'Pause' : 'Play'} ${config.title}`);
    }

    function tick(now) {
      frame = 0;
      if (!mount.isConnected) { dispose(); return; }
      time = Math.min(scene.steps, time + (last ? (now - last) / 750 : 0));
      last = now;
      if (time >= scene.steps) playing = false;
      render();
      schedule();
    }

    function schedule() {
      if (frame) cancelAnimationFrame(frame);
      frame = 0;
      if (!disposed && playing && visible && !document.hidden) frame = requestAnimationFrame(tick);
      else last = 0;
    }

    play.addEventListener('click', () => {
      playing = !playing;
      if (playing && time >= scene.steps) time = 0;
      render();
      schedule();
    });
    replay.addEventListener('click', () => {
      time = 0;
      last = 0;
      playing = true;
      render();
      schedule();
    });
    scrub.addEventListener('input', () => {
      playing = false;
      time = clamp(Number(scrub.value) / scene.steps) * scene.steps;
      render();
      schedule();
    });
    function motionChanged() {
      if (reduced.matches) {
        playing = false;
        render();
        schedule();
      }
    }
    const observer = new IntersectionObserver(entries => {
      visible = entries[0].isIntersecting;
      schedule();
    });
    observer.observe(mount);
    document.addEventListener('visibilitychange', schedule);
    reduced.addEventListener('change', motionChanged);
    function dispose() {
      disposed = true;
      cancelAnimationFrame(frame);
      observer.disconnect();
      document.removeEventListener('visibilitychange', schedule);
      reduced.removeEventListener('change', motionChanged);
    }
    mount.logDispose = dispose;
    render();
  }

  function init() {
    document.querySelectorAll('[data-log-figure]').forEach((mount, index) => {
      const config = FIGURES[mount.dataset.logFigure];
      if (config) mountFigure(mount, config, index);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();

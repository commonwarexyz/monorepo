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

  function forward(svg) {
    const names = Array.from({ length: 6 }, (_, i) => `A${i + 1}`);
    const x = i => 23 + i * 54;
    const lane = y => names.map((name, i) => cell(svg, x(i), y, 44, name));
    label(svg, 18, 23, 'Consensus', { 'font-weight': 'bold' });
    const live = label(svg, 342, 23, 'Selected history', { 'text-anchor': 'end', class: 'log-small log-muted' });
    const known = lane(39);
    const handoff = draw(svg, 'g', { opacity: 0 });
    [0, 1, 2, 3, 4, 5].forEach(i => draw(handoff, 'path', {
      d: `M ${x(i) + 22} 73 V 96 m -4 -5 l 4 5 l 4 -5`, class: 'log-route',
    }));
    label(svg, 18, 119, 'Marshal: blocks to recover', { 'font-weight': 'bold' });
    const headers = lane(131);
    label(svg, 18, 193, 'Body acquisition', { 'font-weight': 'bold' });
    const bodies = lane(205);
    const windowLine = draw(svg, 'path', { class: 'log-window' });
    const windowText = label(svg, 18, 265, 'Four slots, including waiting bodies', { class: 'log-small' });
    label(svg, 18, 297, 'Consumed by marshal', { 'font-weight': 'bold' });
    const consumed = lane(309);
    draw(svg, 'path', { d: 'M 23 355 H 337 m -5 -4 l 5 4 l -5 4', class: 'log-wire' });
    label(svg, 180, 376, 'Oldest to newest', { 'text-anchor': 'middle', class: 'log-small log-muted' });
    const arrival = [4, 8, 3, 6, 7, 10];
    const consumption = [5, 9, 11, 12, 13, 14];
    const captions = [
      'Consensus already knows the complete authenticated stretch A1 through A6. Marshal still needs the bodies.',
      'Consensus hands its known history to marshal and keeps running. Marshal reuses the authenticated commitments.',
      'Request bodies A1 through A4 together. The window holds at most four outstanding requests or waiting bodies.',
      'Body A3 arrives first. It occupies a slot while consumption waits for A1.',
      'Body A1 arrives. A2 and A4 are still in flight, and A3 is waiting in the same bounded window.',
      'Marshal consumes A1 and uses the freed slot to request A5. Ready A3 still waits for A2.',
      'Body A4 arrives ahead of A2. Ready bodies occupy slots just as outstanding requests do.',
      'Body A5 arrives too. The four slots hold missing A2 and ready A3, A4, and A5.',
      'Body A2 arrives and closes the gap. Marshal can now consume the ready prefix.',
      'Consume A2 and use its freed slot to request A6. A3, A4, and A5 are already available.',
      'Body A6 arrives. All four bodies in the window are ready.',
      'Consume A3 next, following the selected chain.',
      'Consume A4. Response order has no effect on chain order.',
      'Consume A5 before A6.',
      'Consume A6. All six bodies followed the selected chain order.',
      'Marshal reused the known history. Body acquisition stayed within four slots, and consumption advanced in order.',
    ];
    return {
      height: 392, steps: captions.length,
      render(step) {
        known.forEach(set => set('produced'));
        live.textContent = step ? 'Keeps running →' : 'Selected history';
        handoff.setAttribute('opacity', step === 1 ? 1 : 0);
        headers.forEach((set, i) => set(step >= 1 ? 'produced' : 'empty', step >= 1 ? names[i] : '·'));
        bodies.forEach((set, i) => {
          const requested = step >= (i < 4 ? 2 : i === 4 ? 5 : 9);
          const done = step >= consumption[i];
          set(done ? 'empty' : step >= arrival[i] ? 'ready' : requested ? 'pending' : 'empty', done ? '✓' : names[i]);
        });
        const prefix = consumption.filter(at => step >= at).length;
        const end = Math.min(6, prefix + 4);
        windowLine.setAttribute('d', step >= 2 && prefix < 6 ? `M ${x(prefix)} 238 v 6 H ${x(end - 1) + 44} v -6` : '');
        windowText.textContent = step < 2 ? 'Four slots, including waiting bodies'
          : prefix < 6 ? `Window A${prefix + 1}–A${end} · limit 4` : 'All six consumed · limit 4';
        consumed.forEach((set, i) => set(step >= consumption[i] ? 'committed' : 'empty', step >= consumption[i] ? names[i] : '·'));
        return captions[step];
      },
    };
  }

  function repair(svg) {
    label(svg, 18, 25, 'Marshal: selected history', { 'font-weight': 'bold' });
    const headers = ['A2', 'A3', 'A4', 'A5'].map((name, i) => cell(svg, 28 + i * 80, 48, 64, name));
    const route = draw(svg, 'path', { class: 'log-route', opacity: 0 });
    const phase = label(svg, 180, 125, 'A3 and A4 headers are unknown', { 'text-anchor': 'middle', class: 'log-small' });
    const peer = cell(svg, 100, 150, 160, 'Peer header repair');
    const bodyPhase = label(svg, 18, 216, 'Bodies still missing', { 'font-weight': 'bold' });
    const bodies = ['A3', 'A4'].map((name, i) => cell(svg, 108 + i * 80, 234, 64, name));
    const forward = draw(svg, 'path', { d: 'M 108 282 H 252 m -5 -4 l 5 4 l -5 4', class: 'log-route', opacity: 0 });
    const captions = [
      'Marshal knows A2 and A5, but lacks the headers for A3 and A4. A tip certificate does not contain every ancestor.',
      'A5 names its exact parent commitment. Request that header from a peer.',
      'The returned A4 header matches A5’s parent commitment. A4 supplies the next parent commitment.',
      'Request the exact parent header named by A4.',
      'The returned A3 header matches A4’s parent commitment. A3 points back to A2.',
      'A3’s parent matches the known A2 anchor. The repaired chain joins the known history exactly.',
      'With A3 and A4 identified, marshal can acquire their bodies concurrently within its bounded window.',
      'Body A4 arrives first. It waits for A3 before marshal can consume this stretch in order.',
      'Body A3 arrives. Forward consumption can resume from A3 to A4.',
    ];
    return {
      height: 300, steps: captions.length,
      render(step) {
        headers.forEach((set, i) => {
          const known = i === 0 || i === 3;
          const found = (i === 2 && step >= 2) || (i === 1 && step >= 4);
          set(known ? 'produced' : found ? 'acked' : 'empty', known || found ? `A${i + 2}` : '?');
        });
        const source = step < 3 ? 3 : step < 5 ? 2 : 1;
        const from = 60 + source * 80;
        route.setAttribute('d', `M ${from} 79 V 100 H ${from - 80} V 79 m -4 5 l 4 -5 l 4 5`);
        route.setAttribute('opacity', step >= 1 && step <= 5 ? 1 : 0);
        phase.textContent = step === 0 ? 'A3 and A4 headers are unknown'
          : step < 3 ? 'A5.parent → A4'
          : step < 5 ? 'A4.parent → A3' : 'A3.parent matches A2';
        peer(step === 1 || step === 3 ? 'pending' : step >= 2 ? 'acked' : 'empty',
          step === 1 ? 'Request A4 header' : step === 2 ? 'A4 header verified'
          : step === 3 ? 'Request A3 header' : step === 4 ? 'A3 header verified'
          : step >= 5 ? 'Gap repaired' : 'Peer header repair');
        bodyPhase.textContent = step >= 6 ? 'Acquire the missing bodies' : 'Bodies still missing';
        bodies.forEach((set, i) => set(step >= (i ? 7 : 8) ? 'ready' : step >= 6 ? 'pending' : 'empty'));
        forward.setAttribute('opacity', step >= 8 ? 1 : 0);
        return captions[step];
      },
    };
  }

  const FIGURES = {
    forward: { title: 'Start with what consensus knows', build: forward, description: 'Consensus hands the complete authenticated stretch A1 through A6 to marshal, then continues independently. A rolling four-slot window acquires bodies concurrently and refills as marshal consumes them. Responses arrive out of order, but marshal consumes A1 through A6 in order.' },
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

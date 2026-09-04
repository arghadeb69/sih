(function () {

      /* ============================================================
         SAMPLE .EML DATA
         ============================================================ */
      const SAMPLE_PHISH = `Return-Path: <bounce@micros0ft-security.example>
Received: from mail-relay-09.suspicious-host.example (185.220.101.47) by mx.recipientcorp.example with ESMTPS id a1b2c3; Fri, 04 Sep 2026 10:31:04 +0000
Received: from smtp-out.micros0ft-security.example (203.0.113.19) by mail-relay-09.suspicious-host.example with SMTP id x9y8z7; Fri, 04 Sep 2026 10:31:08 +0000
Received: by mx.recipientcorp.example id d4e5f6; Fri, 04 Sep 2026 10:31:12 +0000
From: "Microsoft Support" <support@micros0ft-security.example>
To: employee@recipientcorp.example
Reply-To: security-alert@example-mail.com
Subject: URGENT: Your account will be suspended
Date: Fri, 04 Sep 2026 10:31:00 +0000
Message-ID: <a1b2c3d4e5f6@micros0ft-security.example>
Authentication-Results: mx.recipientcorp.example; spf=fail smtp.mailfrom=micros0ft-security.example; dkim=fail header.d=micros0ft-security.example; dmarc=fail (p=REJECT) header.from=micros0ft-security.example
Content-Type: multipart/mixed; boundary="BOUNDARY_X1"

--BOUNDARY_X1
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Dear User,

Your account requires immediate verification. Failure to confirm your identity within 24 hours will result in permanent suspension of your account.

Click the link below to verify your account and prevent suspension:

http://secure-login-example.com/verify?acct=employee@recipientcorp.example&session=8841

If you do not act now, access will be revoked. Please reset your password immediately using the link above.

Microsoft Account Team

--BOUNDARY_X1
Content-Type: application/octet-stream; name="Invoice_Details.exe"
Content-Disposition: attachment; filename="Invoice_Details.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAgAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBy
dW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAAA=
--BOUNDARY_X1--
`;

      const SAMPLE_CLEAN = `Return-Path: <no-reply@billing.cloudservice.example>
Received: from mta7.cloudservice.example (198.51.100.22) by mx.recipientcorp.example with ESMTPS id p9q8r7; Fri, 04 Sep 2026 09:02:11 +0000
Received: by mta7.cloudservice.example id m3n4o5; Fri, 04 Sep 2026 09:02:05 +0000
From: "CloudService Billing" <no-reply@billing.cloudservice.example>
To: employee@recipientcorp.example
Reply-To: no-reply@billing.cloudservice.example
Subject: Your September invoice is ready
Date: Fri, 04 Sep 2026 09:02:00 +0000
Message-ID: <inv-2026-09-0043@billing.cloudservice.example>
Authentication-Results: mx.recipientcorp.example; spf=pass smtp.mailfrom=billing.cloudservice.example; dkim=pass header.d=cloudservice.example; dmarc=pass (p=REJECT) header.from=billing.cloudservice.example
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hi there,

Your invoice for September is now available in your account dashboard.

View your invoice: https://billing.cloudservice.example/account/invoices/2026-09

Amount due: $42.00, payable by Sep 20, 2026. No action is required if you're on autopay.

Thanks,
CloudService Billing Team
`;

      /* ============================================================
         REFERENCE / HEURISTIC DATA
         ============================================================ */
      const SUSPICIOUS_TLDS = ['zip', 'top', 'xyz', 'click', 'link', 'support', 'gq', 'tk', 'ml', 'work', 'country', 'fit'];
      const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'];
      const BRAND_WATCHLIST = ['microsoft', 'google', 'paypal', 'apple', 'amazon', 'netflix', 'bankofamerica', 'chase', 'facebook', 'instagram'];
      const SUSPICIOUS_EXT = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.js', '.vbs', '.iso', '.img', '.lnk'];
      const URGENCY_WORDS = ['urgent', 'immediately', 'suspend', 'suspension', 'verify your account', 'act now', '24 hours', 'final notice', 'locked', 'restricted'];
      const CREDENTIAL_WORDS = ['password', 'reset your password', 'confirm your identity', 'login', 'verify your account', 'click the link', 'security alert'];

      // deterministic mock GeoIP enrichment (demo-safe, no external calls)
      const GEO_TABLE = {
        '185.220.101.47': { country: 'Germany', city: 'Frankfurt', lat: 50.1109, lon: 8.6821, asn: 'AS60729', isp: 'Unverified Relay Network', flagged: true },
        '203.0.113.19': { country: 'Singapore', city: 'Singapore', lat: 1.3521, lon: 103.8198, asn: 'AS4761', isp: 'Obscura Hosting Ltd.', flagged: true },
        '198.51.100.22': { country: 'United States', city: 'Ashburn, VA', lat: 39.0438, lon: -77.4874, asn: 'AS16509', isp: 'Cloudservice Infra (verified sender)', flagged: false },
      };
      function mockGeo(ip) {
        if (GEO_TABLE[ip]) return GEO_TABLE[ip];
        const fallback = [
          { country: 'Netherlands', city: 'Amsterdam', lat: 52.3676, lon: 4.9041 },
          { country: 'India', city: 'Mumbai', lat: 19.076, lon: 72.8777 },
          { country: 'Brazil', city: 'Sao Paulo', lat: -23.5505, lon: -46.6333 },
          { country: 'Japan', city: 'Tokyo', lat: 35.6762, lon: 139.6503 },
          { country: 'South Africa', city: 'Johannesburg', lat: -26.2041, lon: 28.0473 },
        ];
        let h = 0; for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0;
        const pick = fallback[h % fallback.length];
        return { ...pick, asn: 'AS' + (10000 + (h % 80000)), isp: 'Unattributed (approximate)', flagged: true };
      }

      /* ============================================================
         EMAIL PARSER
         ============================================================ */
      function parseEmail(raw) {
        raw = raw.replace(/\r\n/g, '\n');
        const splitIdx = raw.indexOf('\n\n');
        const rawHeaders = splitIdx >= 0 ? raw.slice(0, splitIdx) : raw;
        let rawBody = splitIdx >= 0 ? raw.slice(splitIdx + 2) : '';

        // unfold headers (lines starting with whitespace continue previous header)
        const lines = rawHeaders.split('\n');
        const unfolded = [];
        for (const line of lines) {
          if (/^[ \t]/.test(line) && unfolded.length) {
            unfolded[unfolded.length - 1] += ' ' + line.trim();
          } else if (line.trim() !== '') {
            unfolded.push(line);
          }
        }

        const headers = {};
        const received = [];
        for (const line of unfolded) {
          const m = line.match(/^([A-Za-z\-]+):\s*(.*)$/);
          if (!m) continue;
          const key = m[1].toLowerCase();
          const val = m[2];
          if (key === 'received') { received.push(val); continue; }
          headers[key] = headers[key] ? headers[key] + ' ' + val : val;
        }

        const getAddr = (s) => {
          if (!s) return null;
          const m = s.match(/<([^>]+)>/) || s.match(/([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/);
          return m ? m[1].toLowerCase() : null;
        };
        const getName = (s) => {
          if (!s) return null;
          const m = s.match(/^"?([^"<]+?)"?\s*</);
          return m ? m[1].trim() : null;
        };
        const domainOf = (addr) => addr ? addr.split('@')[1] : null;

        // attachments via naive MIME split
        let attachments = [];
        let bodyText = rawBody;
        const ctHeader = headers['content-type'] || '';
        const boundaryMatch = ctHeader.match(/boundary="?([^";]+)"?/i);
        if (boundaryMatch) {
          const boundary = boundaryMatch[1];
          const parts = rawBody.split('--' + boundary).slice(1, -1);
          let firstText = null;
          for (const part of parts) {
            const pSplit = part.indexOf('\n\n');
            const pHead = pSplit >= 0 ? part.slice(0, pSplit) : part;
            const pBody = pSplit >= 0 ? part.slice(pSplit + 2) : '';
            const disp = (pHead.match(/Content-Disposition:\s*([^\n]*)/i) || [])[1] || '';
            const ctype = (pHead.match(/Content-Type:\s*([^\n;]*)/i) || [])[1] || '';
            const fname = (pHead.match(/filename="?([^";\n]+)"?/i) || [])[1];
            const encoding = (pHead.match(/Content-Transfer-Encoding:\s*([^\n]*)/i) || [])[1] || '';
            if (fname && /attachment/i.test(disp)) {
              const ext = (fname.match(/\.[a-z0-9]+$/i) || [''])[0].toLowerCase();
              attachments.push({ filename: fname.trim(), ext, contentType: ctype.trim(), encoding: encoding.trim(), raw: pBody });
            } else if (!firstText && /text\/plain/i.test(ctype)) {
              firstText = pBody.trim();
            } else if (!firstText && ctype.trim() === '') {
              firstText = pBody.trim();
            }
          }
          bodyText = firstText || parts.map(p => p).join('\n');
        }

        // URLs from body
        const urlRe = /(https?:\/\/[^\s<>"')\]]+)/gi;
        const urls = Array.from(new Set((bodyText.match(urlRe) || []).map(u => u.replace(/[.,]+$/, ''))));

        // IPs from Received headers
        const ipRe = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
        const isPrivate = (ip) => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|0\.|169\.254\.)/.test(ip);
        let ips = [];
        for (const r of received) {
          const found = r.match(ipRe) || [];
          for (const ip of found) if (!isPrivate(ip)) ips.push(ip);
        }
        ips = Array.from(new Set(ips));

        // Received timestamps (best-effort)
        const hopTimeRe = /;\s*([A-Za-z]{3},\s*\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+[\d:]{5,8}(?:\s*[+\-]\d{4})?)/;
        const hops = received.map(r => {
          const ip = (r.match(ipRe) || []).find(x => !isPrivate(x));
          const tm = r.match(hopTimeRe);
          const hostM = r.match(/from\s+([^\s(]+)/i);
          return { raw: r, ip: ip || null, time: tm ? tm[1] : null, host: hostM ? hostM[1] : null };
        }).reverse(); // chronological: earliest hop first

        const from = headers['from'];
        const replyTo = headers['reply-to'];
        const fromAddr = getAddr(from);
        const replyToAddr = getAddr(replyTo);

        const auth = headers['authentication-results'] || '';
        const authStatus = (proto) => {
          const m = auth.match(new RegExp(proto + '=(\\w+)', 'i'));
          return m ? m[1].toLowerCase() : 'not present';
        };

        return {
          headers,
          from, fromName: getName(from), fromAddr, fromDomain: domainOf(fromAddr),
          replyTo, replyToAddr, replyToDomain: domainOf(replyToAddr),
          to: headers['to'], subject: headers['subject'] || '(no subject)',
          date: headers['date'], messageId: headers['message-id'], returnPath: headers['return-path'],
          spf: authStatus('spf'), dkim: authStatus('dkim'), dmarc: authStatus('dmarc'),
          urls, ips, hops, attachments, bodyText
        };
      }

      /* ============================================================
         THREAT / RISK ENGINE
         ============================================================ */
      function domainLooksLikeLookalike(domain) {
        if (!domain) return false;
        const d = domain.toLowerCase();
        for (const brand of BRAND_WATCHLIST) {
          if (d.includes(brand)) continue; // exact brand substring handled by mismatch checks elsewhere
          // char-substitution style: o->0, l->1, i->1 etc against brand name
          const swapped = d.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/@/g, 'a');
          if (swapped.includes(brand) && !d.includes(brand)) return true;
        }
        return false;
      }
      function urlSuspicionReasons(url) {
        const reasons = [];
        try {
          const u = new URL(url);
          if (u.protocol === 'http:') reasons.push('unencrypted http://');
          if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(u.hostname)) reasons.push('IP-address host');
          if (url.length > 90) reasons.push('unusually long URL');
          if ((u.hostname.match(/\./g) || []).length >= 4) reasons.push('excessive subdomains');
          if (SHORTENERS.some(s => u.hostname.includes(s))) reasons.push('URL shortener');
          const tld = u.hostname.split('.').pop();
          if (SUSPICIOUS_TLDS.includes(tld)) reasons.push('suspicious TLD (.' + tld + ')');
          if (/%[0-9a-f]{2}/i.test(url)) reasons.push('encoded parameters');
          if (/login|verify|secure|account|confirm|reset/i.test(u.pathname + u.search)) reasons.push('credential-related path');
          if (domainLooksLikeLookalike(u.hostname)) reasons.push('look-alike brand domain');
        } catch (e) { /* ignore malformed */ }
        return reasons;
      }

      function computeAnalysis(p) {
        const indicators = []; // {label, detail, points, hit}
        let score = 0;
        const add = (label, detail, points, hit) => { indicators.push({ label, detail, points, hit }); if (hit) score += points; };

        add('SPF failure', 'SPF=' + p.spf.toUpperCase(), 10, p.spf === 'fail');
        add('DKIM failure', 'DKIM=' + p.dkim.toUpperCase(), 10, p.dkim === 'fail');
        add('DMARC failure', 'DMARC=' + p.dmarc.toUpperCase(), 15, p.dmarc === 'fail');

        const replyMismatch = p.replyToDomain && p.fromDomain && p.replyToDomain !== p.fromDomain;
        add('Reply-To mismatch', replyMismatch ? (p.replyToDomain + ' ≠ ' + p.fromDomain) : 'Reply-To domain matches sender', 15, !!replyMismatch);

        const lookalike = domainLooksLikeLookalike(p.fromDomain);
        add('Look-alike sender domain', lookalike ? p.fromDomain + ' mimics a known brand' : 'No brand impersonation pattern found', 20, lookalike);

        let urlFlag = false, urlDetail = 'No suspicious URL patterns found';
        let allUrlReasons = {};
        for (const u of p.urls) {
          const r = urlSuspicionReasons(u);
          if (r.length) { urlFlag = true; allUrlReasons[u] = r; }
        }
        if (urlFlag) {
          const first = Object.entries(allUrlReasons)[0];
          urlDetail = first[1].join(', ') + ' — ' + first[0];
        }
        add('Suspicious URL characteristics', urlDetail, 20, urlFlag);

        const suspAttachments = p.attachments.filter(a => SUSPICIOUS_EXT.includes(a.ext));
        add('Malicious attachment indicator', suspAttachments.length ? suspAttachments.map(a => a.filename).join(', ') + ' — executable/script extension' : 'No high-risk attachment extensions', 25, suspAttachments.length > 0);

        const flaggedIps = p.ips.filter(ip => mockGeo(ip).flagged);
        add('Suspicious IP infrastructure', flaggedIps.length ? flaggedIps.join(', ') + ' — unverified / non-reputable infrastructure' : 'Sending infrastructure appears verified', 15, flaggedIps.length > 0);

        const bodyLower = p.bodyText.toLowerCase();
        const urgencyHits = URGENCY_WORDS.filter(w => bodyLower.includes(w));
        const credHits = CREDENTIAL_WORDS.filter(w => bodyLower.includes(w));
        const langHit = (urgencyHits.length + credHits.length) >= 2;
        add('Social-engineering / urgency language', langHit ? 'Matched: ' + [...new Set([...urgencyHits, ...credHits])].slice(0, 4).join(', ') : 'No strong urgency/credential language detected', 10, langHit);

        score = Math.max(0, Math.min(100, score));

        let severity, sevColor;
        if (score >= 85) { severity = 'CRITICAL'; sevColor = 'var(--critical)'; }
        else if (score >= 70) { severity = 'HIGH'; sevColor = 'var(--high)'; }
        else if (score >= 50) { severity = 'MEDIUM'; sevColor = 'var(--medium)'; }
        else if (score >= 25) { severity = 'LOW'; sevColor = 'var(--low)'; }
        else { severity = 'SAFE'; sevColor = 'var(--safe)'; }

        const hitCount = indicators.filter(i => i.hit).length;
        let classification;
        if (suspAttachments.length && score >= 70) classification = 'MALICIOUS';
        else if (score >= 50) classification = 'PHISHING';
        else if (score >= 25) classification = 'SUSPICIOUS';
        else classification = 'SAFE';

        const confidence = Math.min(98, 55 + hitCount * 7);

        return { indicators, score, severity, sevColor, classification, confidence, hitCount, flaggedIps, suspAttachments, urgencyHits, credHits };
      }

      /* ============================================================
         RENDERING
         ============================================================ */
      let leafletMap = null;
      let currentCase = null;

      function el(tag, cls, html) { const e = document.createElement(tag); if (cls) e.className = cls; if (html !== undefined) e.innerHTML = html; return e; }

      function renderAll(p, a) {
        document.getElementById('emptyState').style.display = 'none';
        document.getElementById('results').style.display = 'block';
        const caseId = 'INV-2026-' + String(Math.floor(1000 + Math.random() * 8999));
        document.getElementById('caseId').textContent = 'CASE ' + caseId;
        currentCase = { caseId, p, a };

        document.getElementById('rClass').textContent = a.classification;
        document.getElementById('rClass').style.color = a.sevColor;
        const sevBadge = document.getElementById('rSeverity');
        sevBadge.innerHTML = '<span class="sev-dot' + (a.severity === 'CRITICAL' ? ' pulse' : '') + '" style="background:' + a.sevColor + '"></span>' + a.severity;
        sevBadge.style.color = a.sevColor;
        document.getElementById('rScore').innerHTML = a.score + '<span style="font-size:12px;color:var(--text-faint);">/100</span>';
        document.getElementById('rScore').style.color = a.sevColor;
        document.getElementById('rConfidence').textContent = a.confidence + '%';

        // sender intelligence
        const senderKv = document.getElementById('senderKv');
        senderKv.innerHTML = '';
        const kvPairs = [
          ['Sender', (p.fromName ? p.fromName + ' ' : '') + '<' + (p.fromAddr || 'unknown') + '>'],
          ['Domain', p.fromDomain || '—'],
          ['Reply-To', p.replyToAddr || '(none)'],
          ['To', p.to || '—'],
          ['Subject', p.subject],
          ['Date', p.date || '—'],
          ['Message-ID', p.messageId || '—'],
          ['Return-Path', p.returnPath || '—'],
        ];
        for (const [k, v] of kvPairs) {
          const dt = el('dt', null, k); const dd = el('dd', (k === 'Reply-To' && p.replyToDomain && p.replyToDomain !== p.fromDomain) ? 'warn' : null, escapeHtml(v));
          senderKv.appendChild(dt); senderKv.appendChild(dd);
        }

        // auth
        const authBody = document.getElementById('authBody');
        authBody.innerHTML = '';
        [['SPF', p.spf], ['DKIM', p.dkim], ['DMARC', p.dmarc]].forEach(([name, val]) => {
          const row = el('div', 'auth-row');
          const st = val === 'pass' ? 'pass' : (val === 'fail' ? 'fail' : 'na');
          row.innerHTML = '<span class="auth-name">' + name + '</span><span class="auth-status ' + st + '">' + val.toUpperCase() + '</span>';
          authBody.appendChild(row);
        });

        // indicators
        const indBody = document.getElementById('indicatorsBody');
        indBody.innerHTML = '';
        a.indicators.forEach(ind => {
          const row = el('div', 'indicator' + (ind.hit ? '' : ' clean'));
          row.innerHTML = '<span class="w' + (ind.hit ? ' hit' : '') + '">' + (ind.hit ? '+' + ind.points : '·') + '</span><span class="body"><b>' + ind.label + '</b><br><span>' + escapeHtml(ind.detail) + '</span></span>';
          indBody.appendChild(row);
        });
        document.getElementById('indCount').textContent = a.hitCount + ' of ' + a.indicators.length + ' triggered';

        // graph
        renderGraph(p, a);

        // map
        renderMap(p);

        // IOCs
        renderIOCs(p, a);

        // explanation
        renderExplanation(p, a);

        // timeline
        renderTimeline(p, a);

        // assistant
        renderAssistant(p, a);
      }

      function escapeHtml(s) { return (s == null ? '' : String(s)).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

      function renderGraph(p, a) {
        const svg = document.getElementById('graph');
        const NS = 'http://www.w3.org/2000/svg';
        svg.innerHTML = '';
        const nodes = [{ id: 'email', x: 70, y: 135, label: 'Email', main: true }];
        nodes.push({ id: 'sender', x: 200, y: 45, label: p.fromDomain || 'sender' });
        nodes.push({ id: 'domain', x: 340, y: 45, label: p.fromDomain || 'domain' });
        let y = 100;
        p.ips.slice(0, 2).forEach((ip, i) => { nodes.push({ id: 'ip' + i, x: 340, y: y + i * 40, label: ip }); });
        y = 190;
        p.urls.slice(0, 2).forEach((u, i) => { let host = ''; try { host = new URL(u).hostname; } catch (e) { host = u.slice(0, 20); } nodes.push({ id: 'url' + i, x: 200, y: y + i * 35, label: host }); });
        if (a.suspAttachments.length) { nodes.push({ id: 'att', x: 70, y: 230, label: a.suspAttachments[0].filename }); }

        const links = [['email', 'sender']];
        nodes.forEach(n => { if (n.id.startsWith('ip')) links.push(['sender', n.id]); });
        nodes.forEach(n => { if (n.id.startsWith('url')) links.push(['email', n.id]); });
        if (a.suspAttachments.length) links.push(['email', 'att']);
        links.push(['sender', 'domain']);

        const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
        links.forEach(([a1, b1]) => {
          const A = nodeById[a1], B = nodeById[b1]; if (!A || !B) return;
          const line = document.createElementNS(NS, 'line');
          line.setAttribute('x1', A.x); line.setAttribute('y1', A.y); line.setAttribute('x2', B.x); line.setAttribute('y2', B.y);
          line.setAttribute('stroke', '#233240'); line.setAttribute('stroke-width', '1.3');
          svg.appendChild(line);
        });
        nodes.forEach(n => {
          const g = document.createElementNS(NS, 'g');
          const circle = document.createElementNS(NS, 'circle');
          circle.setAttribute('cx', n.x); circle.setAttribute('cy', n.y); circle.setAttribute('r', n.main ? 12 : 8);
          circle.setAttribute('fill', n.main ? '#39c9c0' : '#121c26');
          circle.setAttribute('stroke', n.main ? '#39c9c0' : '#e0562b');
          circle.setAttribute('stroke-width', '1.6');
          g.appendChild(circle);
          const text = document.createElementNS(NS, 'text');
          text.setAttribute('x', n.x); text.setAttribute('y', n.y + (n.main ? 26 : 22));
          text.setAttribute('text-anchor', 'middle');
          if (n.main) text.setAttribute('class', 'lbl-main');
          text.textContent = n.label.length > 18 ? n.label.slice(0, 16) + '…' : n.label;
          g.appendChild(text);
          svg.appendChild(g);
        });
      }

      function renderMap(p) {
        if (leafletMap) { leafletMap.remove(); leafletMap = null; }
        leafletMap = L.map('map', { zoomControl: true, attributionControl: false }).setView([20, 10], 2);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 }).addTo(leafletMap);
        const pts = [];
        p.ips.forEach(ip => {
          const g = mockGeo(ip);
          const color = g.flagged ? '#e23b3b' : '#33c17c';
          const marker = L.circleMarker([g.lat, g.lon], { radius: 7, color, fillColor: color, fillOpacity: .55, weight: 1.5 }).addTo(leafletMap);
          marker.bindPopup('<b>' + ip + '</b><br>' + g.city + ', ' + g.country + '<br>' + g.asn + ' — ' + g.isp);
          pts.push([g.lat, g.lon]);
        });
        if (pts.length) {
          leafletMap.fitBounds(pts, { padding: [30, 30], maxZoom: 5 });
        }
      }

      function renderIOCs(p, a) {
        const groups = {
          IPs: p.ips,
          Domains: Array.from(new Set([p.fromDomain, p.replyToDomain, ...p.urls.map(u => { try { return new URL(u).hostname } catch (e) { return null } })].filter(Boolean))),
          URLs: p.urls,
          Hashes: a.suspAttachments.map(x => x.filename + ' (hash pending)').concat(p.attachments.filter(x => !SUSPICIOUS_EXT.includes(x.ext)).map(x => x.filename))
        };
        computeAttachmentHashes(p).then(hashList => {
          if (hashList.length) groups.Hashes = hashList;
          paintIOCs(groups);
        });
        paintIOCs(groups);
      }
      async function computeAttachmentHashes(p) {
        const out = [];
        for (const att of p.attachments) {
          try {
            const clean = att.raw.replace(/[^A-Za-z0-9+/=]/g, '');
            const bin = atob(clean);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            const digest = await crypto.subtle.digest('SHA-256', bytes);
            const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
            out.push(att.filename + '  sha256:' + hex.slice(0, 16) + '…');
          } catch (e) { out.push(att.filename + ' (hash unavailable)'); }
        }
        return out;
      }
      let activeTab = 'IPs';
      function paintIOCs(groups) {
        const tabs = document.getElementById('iocTabs');
        tabs.innerHTML = '';
        Object.keys(groups).forEach(name => {
          const t = el('div', 'ioc-tab' + (name === activeTab ? ' active' : ''), name + ' <span class="n">(' + groups[name].length + ')</span>');
          t.addEventListener('click', () => { activeTab = name; paintIOCs(groups); });
          tabs.appendChild(t);
        });
        const list = document.getElementById('iocList');
        list.innerHTML = '';
        const items = groups[activeTab] || [];
        if (!items.length) { list.appendChild(el('div', 'ioc-empty', 'No ' + activeTab.toLowerCase() + ' extracted.')); return; }
        items.forEach(v => {
          const row = el('div', 'ioc-item');
          row.innerHTML = '<span class="val">' + escapeHtml(v) + '</span><button class="copy">copy</button>';
          row.querySelector('.copy').addEventListener('click', () => { navigator.clipboard && navigator.clipboard.writeText(v); });
          list.appendChild(row);
        });
      }

      function renderExplanation(p, a) {
        const box = document.getElementById('explainBody');
        box.innerHTML = '';
        const summary = el('div', 'explain-summary',
          'The message shows ' + (a.hitCount) + ' of ' + a.indicators.length + ' evaluated threat characteristics, producing a risk score of ' + a.score + '/100 (' + a.severity + '). ' +
          (a.classification === 'SAFE' ? 'No strong evidence of malicious intent was found.' : 'This combination of signals is consistent with ' + (a.classification === 'MALICIOUS' ? 'a malicious payload delivery attempt.' : a.classification === 'PHISHING' ? 'a credential-phishing / impersonation attack.' : 'a potentially unwanted or suspicious message.'))
        );
        box.appendChild(summary);
        const hits = a.indicators.filter(i => i.hit);
        if (!hits.length) {
          box.appendChild(el('div', 'explain-line', '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg><span>No indicators were triggered during analysis.</span>'));
        }
        hits.forEach(h => {
          const line = el('div', 'explain-line');
          line.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="var(--high)" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg><span><b>' + h.label + '</b> — ' + escapeHtml(h.detail) + '</span>';
          box.appendChild(line);
        });
      }

      function renderTimeline(p, a) {
        const box = document.getElementById('timelineBody');
        box.innerHTML = '';
        const events = [];
        p.hops.forEach((h, i) => {
          events.push({ time: h.time || ('Hop ' + (i + 1)), label: (i === 0 ? 'Email sent / originated' : 'Relayed via ' + (h.host || h.ip || 'mail server')) + (h.ip ? ' (' + h.ip + ')' : ''), risk: false });
        });
        events.push({ time: 'Analysis', label: 'Content, header and infrastructure analysis performed', risk: false });
        events.push({ time: 'Result', label: 'Risk score ' + a.score + '/100 — ' + a.severity, risk: a.severity === 'CRITICAL' || a.severity === 'HIGH' });
        events.forEach(ev => {
          const item = el('div', 't-item');
          item.innerHTML = '<span class="t-dot' + (ev.risk ? ' risk' : '') + '"></span><div class="t-time">' + escapeHtml(ev.time) + '</div><div class="t-label">' + escapeHtml(ev.label) + '</div>';
          box.appendChild(item);
        });
      }

      function renderAssistant(p, a) {
        const presets = document.getElementById('qaPresets');
        const log = document.getElementById('qaLog');
        presets.innerHTML = ''; log.innerHTML = '';
        const questions = [
          'Why is this email suspicious?',
          'What indicators should I investigate?',
          'Which IPs are associated with this email?',
          'Summarize this incident.'
        ];
        const answer = (q) => {
          if (q === questions[0]) {
            const hits = a.indicators.filter(i => i.hit).map(i => i.label);
            return hits.length ? 'Flagged primarily due to: <b>' + hits.join('</b>, <b>') + '</b>. Combined, these contributed ' + a.score + ' of a possible 100 risk points.' : 'No indicators were triggered — this message currently shows no evidence of malicious characteristics.';
          }
          if (q === questions[1]) {
            const hits = a.indicators.filter(i => i.hit);
            return hits.length ? 'Prioritize: ' + hits.map(h => h.label + ' (' + h.detail + ')').join('; ') + '.' : 'No specific indicators require follow-up based on current evidence.';
          }
          if (q === questions[2]) {
            return p.ips.length ? p.ips.map(ip => { const g = mockGeo(ip); return ip + ' — ' + g.city + ', ' + g.country + ' (' + g.asn + ', ' + g.isp + ')'; }).join('<br>') : 'No external IP addresses were extracted from the Received chain.';
          }
          if (q === questions[3]) {
            return 'Sender <b>' + (p.fromAddr || 'unknown') + '</b> (' + p.fromDomain + ') sent a message classified as <b>' + a.classification + '</b> with severity <b>' + a.severity + '</b> and a risk score of <b>' + a.score + '/100</b> (' + a.confidence + '% confidence). ' + a.indicators.filter(i => i.hit).length + ' of ' + a.indicators.length + ' indicators were triggered' + (p.ips.length ? ', spanning infrastructure in ' + Array.from(new Set(p.ips.map(ip => mockGeo(ip).country))).join(', ') : '') + '.';
          }
          return 'No answer available.';
        };
        questions.forEach(q => {
          const chip = el('button', 'qa-chip', q);
          chip.addEventListener('click', () => {
            const qEl = el('div', 'qa-q', '› ' + q);
            const aEl = el('div', 'qa-a', answer(q));
            log.appendChild(qEl); log.appendChild(aEl);
            log.scrollTop = log.scrollHeight;
          });
          presets.appendChild(chip);
        });
      }

      /* ============================================================
         EXPORTS
         ============================================================ */
      function exportJSON() {
        if (!currentCase) return;
        const { caseId, p, a } = currentCase;
        const report = {
          investigation_id: caseId,
          classification: a.classification.toLowerCase(),
          risk_score: a.score,
          severity: a.severity.toLowerCase(),
          confidence: a.confidence / 100,
          sender: p.fromAddr, reply_to: p.replyToAddr,
          subject: p.subject, date: p.date,
          authentication: { spf: p.spf, dkim: p.dkim, dmarc: p.dmarc },
          iocs: {
            ips: p.ips,
            domains: Array.from(new Set([p.fromDomain, p.replyToDomain].filter(Boolean))),
            urls: p.urls,
            attachments: p.attachments.map(x => x.filename)
          },
          indicators: a.indicators.filter(i => i.hit).map(i => ({ label: i.label, detail: i.detail, points: i.points }))
        };
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url; link.download = caseId + '.json'; link.click();
        URL.revokeObjectURL(url);
      }

      /* ============================================================
         WIRING
         ============================================================ */
      const analyzeBtn = document.getElementById('analyzeBtn');
      const fileInput = document.getElementById('fileInput');
      const dropzone = document.getElementById('dropzone');
      const pasteArea = document.getElementById('pasteArea');
      const fnameEl = document.getElementById('fname');
      let loadedRaw = null;

      dropzone.addEventListener('click', () => fileInput.click());
      dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('drag'); });
      dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'));
      dropzone.addEventListener('drop', e => {
        e.preventDefault(); dropzone.classList.remove('drag');
        const f = e.dataTransfer.files[0]; if (f) handleFile(f);
      });
      fileInput.addEventListener('change', e => { if (e.target.files[0]) handleFile(e.target.files[0]); });
      function handleFile(f) {
        fnameEl.textContent = f.name;
        const reader = new FileReader();
        reader.onload = () => { loadedRaw = reader.result; pasteArea.value = ''; };
        reader.readAsText(f);
      }
      pasteArea.addEventListener('input', () => { if (pasteArea.value.trim()) loadedRaw = null; });

      document.querySelectorAll('.sample-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const sample = btn.dataset.sample === 'phish' ? SAMPLE_PHISH : SAMPLE_CLEAN;
          pasteArea.value = sample; loadedRaw = null; fnameEl.textContent = '';
          runAnalysis(sample);
        });
      });

      analyzeBtn.addEventListener('click', () => {
        const raw = loadedRaw || pasteArea.value;
        if (!raw || !raw.trim()) { pasteArea.focus(); pasteArea.style.borderColor = 'var(--critical)'; setTimeout(() => pasteArea.style.borderColor = '', 900); return; }
        runAnalysis(raw);
      });

      function runAnalysis(raw) {
        const p = parseEmail(raw);
        const a = computeAnalysis(p);
        renderAll(p, a);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }

      document.getElementById('resetBtn').addEventListener('click', () => {
        document.getElementById('results').style.display = 'none';
        document.getElementById('emptyState').style.display = 'flex';
        document.getElementById('caseId').textContent = 'NO ACTIVE CASE';
        pasteArea.value = ''; fnameEl.textContent = ''; loadedRaw = null; currentCase = null;
      });

      document.getElementById('exportJson').addEventListener('click', exportJSON);
      document.getElementById('exportReport').addEventListener('click', () => window.print());

    })();
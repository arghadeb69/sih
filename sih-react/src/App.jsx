import React, { useState } from 'react';
import './index.css';
import { supabase } from './supabaseClient';

function App() {
  const [caseId, setCaseId] = useState("NO ACTIVE CASE");
  const [hasResults, setHasResults] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState("");

  const saveInvestigation = async () => {
    setIsSaving(true);
    setSaveMessage("");

    // Test data insertion into a hypothetical 'investigations' table
    const { data, error } = await supabase
      .from('investigations')
      .insert([
        {
          case_id: 'CASE-TEST-1234',
          risk_score: 92,
          classification: 'PHISHING',
          severity: 'CRITICAL',
          sender_email: 'accounts@paypaI.com'
        },
      ]);

    setIsSaving(false);

    if (error) {
      console.error("Error saving to Supabase:", error);
      setSaveMessage("Error saving data. Check console.");
    } else {
      setSaveMessage("Successfully saved to database!");
    }
  };

  return (
    <div className="shell">
      {/* ============ SIDEBAR ============ */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <svg viewBox="0 0 30 30" fill="none">
              <path d="M4 8 L15 15 L26 8" stroke="currentColor" strokeWidth="1.6" fill="none" />
              <rect x="4" y="8" width="22" height="16" rx="1.5" stroke="currentColor" strokeWidth="1.6" />
              <circle cx="22" cy="20" r="4.5" fill="#030712" stroke="currentColor" strokeWidth="1.4" />
              <path d="M20.3 20 l1.3 1.3 l2.4 -2.6" stroke="currentColor" strokeWidth="1.2" fill="none" />
            </svg>
          </div>
          <div>
            <div className="brand-name">TRACEMAIL</div>
            <div className="brand-sub">SIH26106 · FORENSIC INTEL</div>
          </div>
        </div>

        <div className="side-block">
          <div className="side-label">UPLOAD EMAIL</div>
          <div className="dropzone" id="dropzone">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v12m0-12l-4 4m4-4l4 4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" />
            </svg>
            <p>Drop a <span className="mono">.eml</span> file or click to browse</p>
            <div className="fname" id="fname"></div>
          </div>
          <input type="file" id="fileInput" accept=".eml,.txt,message/rfc822" />
        </div>

        <div className="side-block">
          <div className="side-label">OR PASTE RAW SOURCE</div>
          <textarea className="pasteArea" id="pasteArea" placeholder="Paste full raw email headers + body (View Source / Show Original)..."></textarea>
        </div>

        <button className="btn btn-primary" id="analyzeBtn" onClick={() => setHasResults(true)}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4.3-4.3" />
          </svg>
          Analyze Email
        </button>

        <div className="side-divider"></div>

        <div className="side-block">
          <div className="side-label">DEMO SAMPLES</div>
          <button className="btn sample-btn" onClick={() => setHasResults(true)}>
            <span className="dot" style={{ background: 'var(--critical)' }}></span>Impersonation / phishing.eml
          </button>
          <button className="btn sample-btn" onClick={() => setHasResults(true)}>
            <span className="dot" style={{ background: 'var(--safe)' }}></span>Legitimate / receipt.eml
          </button>
        </div>

        <button className="btn btn-ghost" id="resetBtn" style={{ marginTop: '-8px' }} onClick={() => setHasResults(false)}>
          ↺ Start new investigation
        </button>

        <div className="side-foot">
          <b>MVP scope</b><br />
          Parsing, SPF/DKIM/DMARC, URL &amp; IP extraction, hybrid AI+rules scoring, IOC extraction, GeoLocation (approximate), forensic report export. All analysis runs locally in this browser — no attachment is ever executed.
        </div>
      </aside>

      {/* ============ MAIN ============ */}
      <main className="main">
        <div className="topbar">
          <h1>Investigation Console</h1>
          <div className="case-id" id="caseId">{caseId}</div>
        </div>

        {!hasResults && (
          <div id="emptyState" className="empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.3">
              <rect x="3" y="5" width="18" height="14" rx="1" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 6l9 7 9-7" />
            </svg>
            <h2>No email loaded</h2>
            <p>Upload a <span className="mono">.eml</span> file, paste raw source, or load a demo sample from the left panel to begin a threat &amp; forensic investigation.</p>
          </div>
        )}

        {hasResults && (
          <div id="results">
            {/* result strip */}
            <div className="result-strip">
              <div className="rs-cell" style={{ minWidth: '150px' }}>
                <div className="rs-label">CLASSIFICATION</div>
                <div className="class-tag" id="rClass">PHISHING</div>
              </div>
              <div className="rs-cell">
                <div className="rs-label">SEVERITY</div>
                <div className="sev-badge" id="rSeverity"><span className="sev-dot pulse" style={{ background: 'var(--critical)' }}></span>CRITICAL</div>
              </div>
              <div className="rs-cell" style={{ textAlign: 'right' }}>
                <div className="rs-label">RISK SCORE</div>
                <div className="rs-value" id="rScore">92<span style={{ fontSize: '12px', color: 'var(--text-faint)' }}>/100</span></div>
              </div>
              <div className="rs-cell" style={{ textAlign: 'right', borderRight: 'none' }}>
                <div className="rs-label">CONFIDENCE</div>
                <div className="rs-value small" id="rConfidence">HIGH</div>
              </div>
            </div>

            <div className="grid cols-2">
              {/* Sender intelligence */}
              <div className="panel">
                <div className="panel-head">
                  <h3>SENDER INTELLIGENCE</h3>
                </div>
                <div className="panel-body">
                  <dl className="kv" id="senderKv">
                    <dt>From</dt><dd>accounts@paypaI.com</dd>
                    <dt>Reply-To</dt><dd className="warn">scammer@temp.mail</dd>
                    <dt>Date</dt><dd>2026-09-04 10:32 UTC</dd>
                  </dl>
                </div>
              </div>

              {/* Authentication */}
              <div className="panel">
                <div className="panel-head">
                  <h3>EMAIL AUTHENTICATION</h3>
                </div>
                <div className="panel-body" id="authBody">
                  <div className="auth-row"><span className="auth-name">SPF</span><span className="auth-status fail">FAIL</span></div>
                  <div className="auth-row"><span className="auth-name">DKIM</span><span className="auth-status fail">FAIL</span></div>
                  <div className="auth-row"><span className="auth-name">DMARC</span><span className="auth-status pass">PASS</span></div>
                </div>
              </div>
            </div>

            <div className="grid cols-2" style={{ marginTop: '20px' }}>
              {/* Indicators */}
              <div className="panel">
                <div className="panel-head">
                  <h3>THREAT INDICATORS</h3><span className="hint" id="indCount">3 Hits</span>
                </div>
                <div className="panel-body" id="indicatorsBody">
                  <div className="indicator">
                    <span className="w hit">1.0</span>
                    <div className="body"><b>Lookalike Domain Detected</b> <br /><span>paypaI.com (Uppercase I) impersonates paypal.com</span></div>
                  </div>
                </div>
              </div>

              {/* Attack graph */}
              <div className="panel">
                <div className="panel-head">
                  <h3>ATTACK INFRASTRUCTURE GRAPH</h3>
                </div>
                <div className="panel-body"><svg id="graph" viewBox="0 0 560 270"></svg></div>
              </div>
            </div>

            <div className="actions">
              <button className="btn" id="exportJson">⭳ Export JSON</button>
              <button className="btn" id="exportReport">🖶 Export / Print Report</button>
              <button className="btn btn-primary" onClick={saveInvestigation} disabled={isSaving}>
                {isSaving ? "Saving..." : "💾 Save to Database"}
              </button>
            </div>

            {saveMessage && (
              <div style={{ marginTop: '12px', fontSize: '13px', color: saveMessage.includes('Error') ? 'var(--critical)' : 'var(--safe)' }}>
                {saveMessage}
              </div>
            )}

            <div className="disclaimer">
              Prototype build for SIH26106. Threat scoring uses a transparent hybrid of rule-based indicators...
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;

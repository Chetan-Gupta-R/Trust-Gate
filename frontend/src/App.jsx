import { useEffect, useMemo, useState } from "react";

const API_BASE = "http://localhost:8000/api";

function formatINR(amount) {
  return new Intl.NumberFormat("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  }).format(amount);
}

function formatDate(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    timeZone: "Asia/Kolkata",
  }).format(new Date(value));
}

function Icon({ name }) {
  const paths = {
    shield: <><path d="M12 3 19 6v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3Z" /><path d="m9 12 2 2 4-4" /></>,
    file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" /><path d="M14 2v6h6M8 13h8M8 17h8" /></>,
    bank: <><path d="m3 10 9-7 9 7" /><path d="M5 10v9M9 10v9M15 10v9M19 10v9M3 21h18M2 19h20" /></>,
    arrow: <><path d="M5 12h14M13 6l6 6-6 6" /></>,
    check: <path d="m5 12 4 4L19 6" />,
    alert: <><path d="M10.3 3.9 2.2 18a2 2 0 0 0 1.7 3h16.2a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /><path d="M12 9v4M12 17h.01" /></>,
    clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
    bolt: <path d="m13 2-3 8h7l-6 12 2-9H6l7-11Z" />,
    mail: <><rect x="3" y="5" width="18" height="14" rx="2" /><path d="m3 7 9 6 9-6" /></>,
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

function getRequestPayload(demoCase) {
  return {
    case_id: demoCase.case_id,
    request_id: `demo-${demoCase.case_id.toLowerCase()}-${Date.now()}`,
    agent_id: "trustgate-demo-agent",
    source: demoCase.source,
    trusted_context: demoCase.trusted_context,
    proposed_action: demoCase.proposed_action,
    policy: demoCase.policy,
  };
}

async function loadFallbackCase(caseId) {
  const response = await fetch("/mock_data.json");
  if (!response.ok) throw new Error("Unable to load local demo data.");
  const samples = await response.json();
  const demoCase = samples.cases.find((entry) => entry.case_id === caseId);
  if (!demoCase) throw new Error(`Local demo case ${caseId} was not found.`);
  return demoCase;
}

function getPolicyRows(policyChecks) {
  if (Array.isArray(policyChecks)) return policyChecks;
  if (!policyChecks || typeof policyChecks !== "object") return [];

  const labels = {
    vendor_verified: "Vendor verification",
    vendor_name_match: "Vendor name match",
    source_text_present: "Invoice document content",
    beneficiary_match: "Beneficiary match",
    amount_valid: "Payment amount",
    currency_supported: "Payment currency",
    amount_within_limit: "Automatic payment limit",
    action_supported: "Action type",
    trusted_bank_available: "Trusted beneficiary record",
    policy_valid: "Policy configuration",
    prompt_injection_detected: "Prompt injection",
  };
  return Object.entries(labels).map(([key, name]) => {
    const passed = key === "prompt_injection_detected"
      ? !policyChecks[key]
      : policyChecks[key] === true;
    return {
      name,
      status: passed ? "PASS" : "FAIL",
      detail: passed
        ? "Passed deterministic backend check."
        : key === "prompt_injection_detected"
          ? "Suspicious instruction detected in untrusted document text."
          : "Failed deterministic backend authorization check.",
    };
  });
}

function App() {
  const [samples, setSamples] = useState(null);
  const [selectedId, setSelectedId] = useState("");
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [usingFallback, setUsingFallback] = useState(false);
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    let active = true;
    async function initialize() {
      try {
        const response = await fetch(`${API_BASE}/samples`);
        if (!response.ok) throw new Error("Samples endpoint unavailable.");
        const data = await response.json();
        if (active) {
          setSamples(data);
          setSelectedId(data.cases[0]?.case_id ?? "");
        }
      } catch {
        try {
          const response = await fetch("/mock_data.json");
          if (!response.ok) throw new Error("Unable to load local demo data.");
          const data = await response.json();
          if (active) {
            setSamples(data);
            setSelectedId(data.cases[0]?.case_id ?? "");
            setUsingFallback(true);
          }
        } catch (error) {
          if (active) setLoadError(error.message);
        }
      }
    }
    initialize();
    return () => { active = false; };
  }, []);

  const selectedCase = useMemo(
    () => samples?.cases.find((entry) => entry.case_id === selectedId) ?? null,
    [samples, selectedId],
  );

  function chooseCase(demoCase) {
    setSelectedId(demoCase.case_id);
    setResult(null);
    setUsingFallback(false);
  }

  async function analyzeCase() {
    if (!selectedCase || isLoading) return;
    setIsLoading(true);
    setLoadingStep(0);
    setResult(null);
    const timer = window.setInterval(() => {
      setLoadingStep((step) => Math.min(step + 1, 2));
    }, 500);
    const payload = getRequestPayload(selectedCase);
    try {
      const response = await fetch(`${API_BASE}/process`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error(`Backend returned ${response.status}.`);
      setResult(await response.json());
      setUsingFallback(false);
    } catch {
      try {
        const localCase = await loadFallbackCase(selectedCase.case_id);
        setResult({
          ...localCase.expected_response,
          case_id: localCase.case_id,
          request_id: payload.request_id,
        });
        setUsingFallback(true);
      } catch (error) {
        setLoadError(error.message);
      }
    } finally {
      window.clearInterval(timer);
      setIsLoading(false);
    }
  }

  if (loadError && !samples) {
    return <main className="fatal-state"><Icon name="alert" /><h1>TrustGate demo data unavailable</h1><p>{loadError}</p><button className="button button-primary" onClick={() => window.location.reload()}>Retry</button></main>;
  }

  const blocked = result?.decision === "BLOCK";
  const policyRows = result ? getPolicyRows(result.policy_checks) : [];
  const patternLabels = {
    instruction_override: "Instruction override attempt",
    system_instruction_override: "System instruction override",
    beneficiary_change: "Beneficiary change instruction",
    concealment: "Concealment request",
    unauthorized_urgent_action: "Unapproved urgent payment",
    confidential_data_request: "Confidential data request",
    privilege_escalation: "Privilege escalation attempt",
    verification_bypass: "Verification bypass attempt",
  };
  const threatIndicators = result ? [
    ...(result.threat_analysis?.prompt_injection_detected ? ["Prompt injection detected"] : []),
    ...(result.threat_analysis?.concealment_detected || result.threat_analysis?.concealment_instruction ? ["Concealment instruction"] : []),
    ...(result.threat_analysis?.beneficiary_mismatch || result.policy_checks?.beneficiary_match === false ? ["Beneficiary mismatch"] : []),
    ...(result.threat_analysis?.matched_patterns ?? [])
      .filter((pattern) => pattern !== "concealment")
      .map((pattern) => patternLabels[pattern] ?? pattern),
  ] : [];

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark"><Icon name="shield" /></div>
          <div><div className="brand-name">TrustGate</div><div className="brand-tagline">Don’t let strangers give your AI orders.</div></div>
        </div>
        <div className="persona-pill"><span className="persona-dot" />{samples?.persona?.role ?? "Accounts Payable Executive"} <span className="persona-divider">·</span> Demo Persona</div>
      </header>

      <main className="page-content">
        <section className="welcome-row">
          <div>
            <div className="eyebrow"><span className="eyebrow-line" />AI ACTION SECURITY GATEWAY</div>
            <h1>Payment authorization review</h1>
            <p className="subtitle">Verify every proposed payment against trusted vendor records and business policy.</p>
          </div>
          <div className="demo-controls">
            <span className="demo-label">DEMO CASES</span>
            <div className="sample-buttons">
              {(samples?.cases ?? []).map((demoCase, index) => (
                <button key={demoCase.case_id} className={`sample-button ${selectedId === demoCase.case_id ? "selected" : ""} ${index === 1 ? "sample-danger" : ""}`} onClick={() => chooseCase(demoCase)}>
                  <span className="sample-number">0{index + 1}</span>Load Sample {index + 1} <span className="sample-suffix">{index === 0 ? "Normal" : index === 1 ? "Critical Attack" : "Instant Win"}</span>
                </button>
              ))}
            </div>
          </div>
        </section>

        <div className="workflow">
          <div className="workflow-step active"><span>1</span>Invoice intake</div>
          <div className="workflow-rule" />
          <div className={`workflow-step ${isLoading ? "active" : result ? "complete" : ""}`}><span>{result ? <Icon name="check" /> : "2"}</span>Security analysis</div>
          <div className="workflow-rule" />
          <div className={`workflow-step ${result ? "active" : ""}`}><span>{result ? <Icon name="check" /> : "3"}</span>Security decision</div>
        </div>

        <div className="dashboard-grid">
          <section className="panel intake-panel">
            <div className="panel-heading">
              <div className="heading-icon blue"><Icon name="file" /></div>
              <div><div className="step-kicker">STEP 1</div><h2>Invoice intake</h2></div>
              {selectedCase && <span className="case-id">{selectedCase.case_id}</span>}
            </div>
            {selectedCase ? (
              <>
                <div className="invoice-summary">
                  <div><div className="field-label">VENDOR</div><strong>{selectedCase.vendor.name}</strong><span className="verified-label"><Icon name="check" /> Verified vendor</span></div>
                  <div className="invoice-amount"><div className="field-label">INVOICE AMOUNT</div><strong>{formatINR(selectedCase.invoice.amount)}</strong><span>{selectedCase.invoice.currency} · {selectedCase.invoice.invoice_id}</span></div>
                </div>
                <div className="metadata-grid">
                  <div className="meta-item"><span>Invoice date</span><strong>{formatDate(selectedCase.invoice.invoice_date)}</strong></div>
                  <div className="meta-item"><span>GSTIN</span><strong>{selectedCase.vendor.gstin}</strong></div>
                  <div className="meta-item"><span>Email sender</span><strong className="truncate"><Icon name="mail" />{selectedCase.email.sender}</strong></div>
                  <div className="meta-item"><span>Received (IST)</span><strong>{new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Kolkata" }).format(new Date(selectedCase.invoice.received_at))}</strong></div>
                </div>
                <div className="bank-comparison">
                  <div className="bank-title"><Icon name="bank" /> BENEFICIARY VERIFICATION</div>
                  <div className="bank-columns">
                    <div className="bank-detail"><span>TRUSTED BANK</span><strong>{selectedCase.vendor.trusted_bank}</strong><small>Account ending <b>•••• {selectedCase.vendor.trusted_account_last4}</b></small></div>
                    <div className="bank-arrow"><Icon name="arrow" /></div>
                    <div className={`bank-detail ${selectedCase.trusted_context.bank_name !== selectedCase.proposed_action.beneficiary_bank || selectedCase.trusted_context.account_last4 !== selectedCase.proposed_action.beneficiary_account_last4 ? "bank-mismatch" : ""}`}><span>PROPOSED BENEFICIARY</span><strong>{selectedCase.proposed_action.beneficiary_bank}</strong><small>Account ending <b>•••• {selectedCase.proposed_action.beneficiary_account_last4}</b></small></div>
                  </div>
                </div>
                <div className="document-block">
                  <div className="document-heading"><span><Icon name="file" /> DOCUMENT CONTENT</span><span className="file-name">{selectedCase.invoice.filename}</span></div>
                  <p>{selectedCase.source.document_text}</p>
                </div>
                <button className="button button-primary analyze-button" onClick={analyzeCase} disabled={isLoading}>
                  {isLoading ? <><span className="button-spinner" />Analyzing invoice…</> : <>Analyze with TrustGate <Icon name="arrow" /></>}
                </button>
              </>
            ) : <div className="loading-placeholder">Loading demo cases…</div>}
          </section>

          <section className="panel decision-panel">
            <div className="panel-heading">
              <div className="heading-icon navy"><Icon name="shield" /></div>
              <div><div className="step-kicker">STEP 2 &amp; 3</div><h2>Security decision</h2></div>
              {result && <span className={`decision-chip ${blocked ? "chip-block" : "chip-allow"}`}>{result.decision}</span>}
            </div>
            {isLoading ? (
              <div className="analysis-progress">
                <div className="progress-orbit"><Icon name="shield" /></div>
                <h3>Analyzing proposed action</h3>
                <p>TrustGate is checking the request against your trusted records.</p>
                <div className="analysis-steps">
                  {["Inspecting untrusted instructions…", "Verifying vendor and beneficiary…", "Checking business policy…"].map((step, index) => (
                    <div key={step} className={`analysis-step ${loadingStep >= index ? "step-done" : ""} ${loadingStep === index ? "step-current" : ""}`}><span>{loadingStep > index ? <Icon name="check" /> : loadingStep === index ? <span className="mini-spinner" /> : ""}</span>{step}</div>
                  ))}
                </div>
              </div>
            ) : result ? (
              <div className="decision-result">
                <div className={`result-banner ${blocked ? "result-block" : "result-allow"}`}>
                  <div className="result-symbol"><Icon name={blocked ? "alert" : "check"} /></div>
                  <div className="result-copy"><span>TRUSTGATE DECISION</span><strong>{result.decision}</strong><small>{blocked ? "Action blocked by security policy" : "Proposed action satisfies demo policy"}</small></div>
                  <div className="risk-score"><span>RISK SCORE</span><strong>{result.risk_score}<small>/100</small></strong></div>
                </div>
                <div className={`risk-strip ${blocked ? "risk-critical" : "risk-low"}`}><span><Icon name={blocked ? "alert" : "shield"} />{result.risk} RISK</span><span>{result.threat_analysis?.summary ?? "No threat summary was provided."}</span></div>
                {blocked && <div className="threat-callout"><div className="threat-icon"><Icon name="alert" /></div><div><strong>Why this invoice was blocked</strong><p>{threatIndicators.length ? [...new Set(threatIndicators)].join(" · ") : result.threat_analysis?.summary}</p></div></div>}
                <div className="checks-section">
                  <div className="result-section-title">POLICY CHECKS</div>
                  {policyRows.map((check) => <div className="check-row" key={check.name}><span className={`check-status ${check.status === "PASS" ? "pass" : "fail"}`}><Icon name={check.status === "PASS" ? "check" : "alert"} /></span><span className="check-name">{check.name}</span><span className="check-detail">{check.detail}</span></div>)}
                </div>
                <div className="evidence-section">
                  <div className="result-section-title">EVIDENCE</div>
                  <ul>{result.evidence.map((item, index) => <li key={index}>{item}</li>)}</ul>
                </div>
                <div className="execution-notice"><span><Icon name="shield" />PAYMENT EXECUTION: NOT EXECUTED</span><small>TrustGate evaluates authorization only. No money was transferred.</small></div>
                <div className="result-meta">Request ID <code>{result.request_id}</code>{usingFallback && <span className="fallback-tag">LOCAL DEMO FALLBACK</span>}</div>
              </div>
            ) : (
              <div className="empty-decision">
                <div className="empty-shield"><Icon name="shield" /></div>
                <h3>Ready to review</h3>
                <p>Select a sample invoice and run a security analysis to see TrustGate’s decision.</p>
                <div className="empty-checks"><span><Icon name="check" />Vendor records</span><span><Icon name="check" />Beneficiary details</span><span><Icon name="check" />Payment policy</span></div>
              </div>
            )}
          </section>
        </div>

        <section className="impact-card">
          <div className="impact-icon"><Icon name="bolt" /></div>
          <div className="impact-intro"><strong>First-pass review, faster.</strong><span>Illustrative estimates — not measured production results.</span></div>
          <div className="impact-metric"><span>MANUAL REVIEW</span><strong>4 <small>min</small></strong></div>
          <div className="impact-arrow"><Icon name="arrow" /></div>
          <div className="impact-metric"><span>AUTOMATED REVIEW TARGET</span><strong>20 <small>sec</small></strong></div>
          <div className="impact-saved"><span>EST. TIME SAVED</span><strong>3.7 <small>min / invoice</small></strong></div>
        </section>
      </main>
      <footer className="footer"><div><div className="footer-mark"><Icon name="shield" /></div><strong>TrustGate</strong><span>AI Agent Action Security Gateway</span></div><p>Demo environment only · No real payments are executed.</p></footer>
    </div>
  );
}

export default App;

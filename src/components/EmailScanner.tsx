import React, { useState } from 'react';
import {
  Inbox,
  Mail,
  CheckCircle2,
  AlertCircle,
  FileText,
  Upload,
  ArrowRight,
  ShieldAlert,
  Loader2,
  ExternalLink,
  ShieldCheck,
  Send,
  UserCheck,
  AlertTriangle
} from 'lucide-react';
import { EMAIL_PRESETS, PresetItem } from '../utils/presets';
import { EmailScanResponse, UserAlertProfile, AlertRecord } from '../types';
import { ScanResultCard } from './ScanResultCard';

interface EmailScannerProps {
  alertProfile: UserAlertProfile;
  onAlertTriggered: (alert: AlertRecord) => void;
}

export const EmailScanner: React.FC<EmailScannerProps> = ({ alertProfile, onAlertTriggered }) => {
  const [sender, setSender] = useState('');
  const [replyTo, setReplyTo] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');

  const [inputMode, setInputMode] = useState<'structured' | 'raw'>('structured');
  const [rawEml, setRawEml] = useState('');

  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [scanResult, setScanResult] = useState<EmailScanResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSelectPreset = (preset: PresetItem) => {
    setErrorMessage(null);
    setScanResult(null);
    setInputMode('structured');
    setSender(preset.data.sender || '');
    setReplyTo(preset.data.replyTo || '');
    setSubject(preset.data.subject || '');
    setBody(preset.data.body || '');
  };

  const handleEmlFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setRawEml(content);
      setInputMode('raw');

      // Attempt parsing standard headers
      const fromMatch = content.match(/^From:\s*(.+)$/im);
      const replyMatch = content.match(/^Reply-To:\s*(.+)$/im);
      const subjectMatch = content.match(/^Subject:\s*(.+)$/im);

      if (fromMatch) setSender(fromMatch[1].trim());
      if (replyMatch) setReplyTo(replyMatch[1].trim());
      if (subjectMatch) setSubject(subjectMatch[1].trim());

      const bodyPart = content.split(/\r?\n\r?\n/)[1] || content;
      setBody(bodyPart);
    };
    reader.readAsText(file);
  };

  const runEmailScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!body.trim() && !rawEml.trim()) return;

    setIsScanning(true);
    setErrorMessage(null);
    setScanResult(null);

    try {
      setScanStep('Auditing SPF/DKIM/DMARC headers & sender domain alignment...');
      await new Promise((r) => setTimeout(r, 400));

      setScanStep('Extracting embedded URLs & analyzing urgency social engineering triggers...');
      await new Promise((r) => setTimeout(r, 400));

      setScanStep('Running Business Email Compromise (BEC) & phishing heuristics...');

      const payload =
        inputMode === 'raw'
          ? {
              rawEmail: rawEml,
              sender,
              replyTo,
              subject,
              body,
              recipientEmail: alertProfile.email,
              recipientPhone: alertProfile.phone,
            }
          : {
              sender,
              replyTo,
              subject,
              body,
              recipientEmail: alertProfile.email,
              recipientPhone: alertProfile.phone,
            };

      const response = await fetch('/api/scan/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errJson = await response.json();
        throw new Error(errJson.error || 'Server rejected email forensic scan');
      }

      const data: EmailScanResponse = await response.json();
      setScanResult(data);

      if (data.alertDispatched) {
        onAlertTriggered(data.alertDispatched);
      }
    } catch (err: any) {
      console.error(err);
      setErrorMessage(err.message || 'Email inspection failed.');
    } finally {
      setIsScanning(false);
      setScanStep('');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Preset Area */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <div className="mb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Inbox className="w-5 h-5 text-amber-400" />
              Email & Phishing Threat Scanner
            </h2>
            <p className="text-xs text-slate-400">
              Detect Business Email Compromise (BEC), CEO fraud, lookalike spoofing, and credential harvest lures
            </p>
          </div>

          {/* Quick Presets */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[11px] text-slate-500 font-medium">Test Presets:</span>
            {EMAIL_PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => handleSelectPreset(p)}
                className={`text-[11px] px-2.5 py-1 rounded-lg border font-medium transition-colors ${
                  subject === p.data.subject
                    ? 'bg-slate-800 border-slate-600 text-slate-100'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200'
                }`}
                title={p.description}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full inline-block mr-1.5 ${
                    p.badge === 'Malicious'
                      ? 'bg-rose-500'
                      : p.badge === 'Suspicious'
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                />
                {p.name.split(' ')[0]}
              </button>
            ))}
          </div>
        </div>

        {/* Input Format Selector & EML Upload */}
        <div className="flex items-center justify-between gap-2 mb-4 pb-3 border-b border-slate-800">
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              type="button"
              onClick={() => setInputMode('structured')}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                inputMode === 'structured'
                  ? 'bg-slate-800 text-slate-100 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Structured Fields
            </button>
            <button
              type="button"
              onClick={() => setInputMode('raw')}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                inputMode === 'raw'
                  ? 'bg-slate-800 text-slate-100 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Raw Header / EML
            </button>
          </div>

          <label className="cursor-pointer text-xs font-medium text-slate-300 hover:text-emerald-400 flex items-center gap-1.5 bg-slate-800/80 hover:bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700 transition-colors">
            <Upload className="w-3.5 h-3.5" />
            <span>Upload .EML File</span>
            <input type="file" accept=".eml,.txt,.msg" onChange={handleEmlFileUpload} className="hidden" />
          </label>
        </div>

        {/* Structured Form */}
        {inputMode === 'structured' ? (
          <form onSubmit={runEmailScan} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  From (Sender Header)
                </label>
                <input
                  type="text"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  placeholder="e.g. CEO John Doe <john@company-direct.xyz>"
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-600 text-xs focus:outline-none focus:border-amber-500 font-mono transition-colors"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Reply-To (Optional Divergent Return)
                </label>
                <input
                  type="text"
                  value={replyTo}
                  onChange={(e) => setReplyTo(e.target.value)}
                  placeholder="e.g. secure.forwarder@mail-relay.top"
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-600 text-xs focus:outline-none focus:border-amber-500 font-mono transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Subject Line
              </label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="e.g. URGENT: Wire Transfer Authorization Required Today"
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-600 text-xs focus:outline-none focus:border-amber-500 transition-colors font-medium"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Email Body & Embedded Content
              </label>
              <textarea
                rows={5}
                required
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="Paste the full email text, greetings, signature, and any embedded links..."
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-600 text-xs focus:outline-none focus:border-amber-500 transition-colors font-mono leading-relaxed"
              />
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
              <div className="text-xs text-slate-400">
                {isScanning ? (
                  <span className="flex items-center gap-2 text-amber-400 animate-pulse font-mono">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    {scanStep}
                  </span>
                ) : (
                  <span className="text-slate-500">
                    Engine assesses impersonation, urgency triggers, and embedded links.
                  </span>
                )}
              </div>

              <button
                type="submit"
                disabled={!body.trim() || isScanning}
                className="px-6 py-2.5 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs rounded-xl shadow-lg shadow-amber-950/60 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Evaluating Phishing Risk...
                  </>
                ) : (
                  <>
                    <Inbox className="w-4 h-4" />
                    Scan Email Now
                  </>
                )}
              </button>
            </div>
          </form>
        ) : (
          /* Raw EML Input */
          <form onSubmit={runEmailScan} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Raw RFC-822 Message / EML Source
              </label>
              <textarea
                rows={9}
                required
                value={rawEml}
                onChange={(e) => {
                  setRawEml(e.target.value);
                  setBody(e.target.value);
                }}
                placeholder="Received: from mail.relay.top...&#10;From: sender@domain.com&#10;Reply-To: divergent@other.com&#10;Subject: Action required...&#10;&#10;Body message content..."
                className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-600 text-xs focus:outline-none focus:border-amber-500 font-mono transition-colors"
              />
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="text-xs text-slate-400">
                {isScanning && (
                  <span className="flex items-center gap-2 text-amber-400 animate-pulse font-mono">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    {scanStep}
                  </span>
                )}
              </div>

              <button
                type="submit"
                disabled={!rawEml.trim() || isScanning}
                className="px-6 py-2.5 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs rounded-xl shadow-lg shadow-amber-950/60 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Scanning Raw Email...
                  </>
                ) : (
                  <>
                    <Inbox className="w-4 h-4" />
                    Scan Raw Email
                  </>
                )}
              </button>
            </div>
          </form>
        )}

        {errorMessage && (
          <div className="mt-4 p-3.5 bg-rose-950/40 border border-rose-900 rounded-xl text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>

      {/* Forensic Telemetry & Result */}
      {scanResult && (
        <div className="space-y-6">
          {/* Email Forensic Header Strip */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Authentication Alignment
              </span>
              <div className="flex flex-col gap-0.5 text-[11px] font-mono">
                <span className="text-slate-300">
                  SPF: <span className="text-slate-400">{scanResult.assessment.spfDkimStatus.spfVerdict}</span>
                </span>
                <span className="text-slate-300">
                  DMARC: <span className="text-slate-400">{scanResult.assessment.spfDkimStatus.dmarcVerdict}</span>
                </span>
              </div>
            </div>

            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Sender vs Reply-To Divergence
              </span>
              <div className="flex items-center gap-2">
                <span
                  className={`text-xs font-semibold ${
                    scanResult.emailDetails.hasDivergentReplyTo ? 'text-rose-400' : 'text-emerald-400'
                  }`}
                >
                  {scanResult.emailDetails.hasDivergentReplyTo
                    ? 'Divergence Flagged'
                    : 'Matched / Standard'}
                </span>
              </div>
            </div>

            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Urgency Pressure Keywords
              </span>
              <span className="text-xs font-mono text-slate-200">
                {scanResult.emailDetails.matchedUrgency.length > 0
                  ? `${scanResult.emailDetails.matchedUrgency.length} Triggers detected`
                  : 'Neutral Tone'}
              </span>
            </div>

            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Extracted Links
              </span>
              <span className="text-xs font-mono text-slate-200">
                {scanResult.emailDetails.extractedUrls.length} Hyperlinks discovered
              </span>
            </div>
          </div>

          {/* Verdict Card with Automated Alert Notification */}
          <ScanResultCard
            threatLevel={scanResult.assessment.threatLevel}
            threatScore={scanResult.assessment.threatScore}
            threatName={scanResult.assessment.threatName}
            summary={scanResult.assessment.summary}
            iocs={scanResult.assessment.extractedIocs}
            remediation={scanResult.assessment.remediation}
            categoriesOrTactics={[
              `Type: ${scanResult.assessment.phishingType}`,
              ...scanResult.assessment.deceptionTactics,
            ]}
            alertDispatched={scanResult.alertDispatched}
            targetDetails={{
              type: 'Email',
              title: scanResult.emailDetails.subject || 'Untitled Email Message',
              subtitle: scanResult.emailDetails.sender
                ? `From: ${scanResult.emailDetails.sender}`
                : undefined,
            }}
          />
        </div>
      )}
    </div>
  );
};

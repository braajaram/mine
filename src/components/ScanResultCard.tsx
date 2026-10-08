import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Mail,
  Smartphone,
  Copy,
  Check,
  Download,
  Terminal,
  ExternalLink,
  ChevronRight,
  ListChecks,
  Network
} from 'lucide-react';
import { ThreatLevel, AlertRecord } from '../types';

interface ScanResultCardProps {
  threatLevel: ThreatLevel;
  threatScore: number;
  threatName: string;
  summary: string;
  iocs: string[];
  remediation: string[];
  mitreTechniques?: string[];
  categoriesOrTactics?: string[];
  alertDispatched: AlertRecord | null;
  targetDetails: {
    type: 'File' | 'URL' | 'Email';
    title: string;
    subtitle?: string;
  };
}

export const ScanResultCard: React.FC<ScanResultCardProps> = ({
  threatLevel,
  threatScore,
  threatName,
  summary,
  iocs,
  remediation,
  mitreTechniques,
  categoriesOrTactics,
  alertDispatched,
  targetDetails,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'iocs' | 'remediation' | 'notification'>(
    'overview'
  );
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);

  const handleCopyIoc = (ioc: string) => {
    navigator.clipboard.writeText(ioc);
    setCopiedIoc(ioc);
    setTimeout(() => setCopiedIoc(null), 2000);
  };

  const downloadReport = () => {
    const reportData = {
      targetType: targetDetails.type,
      targetIdentifier: targetDetails.title,
      threatLevel,
      threatScore,
      threatName,
      summary,
      iocs,
      remediation,
      mitreTechniques,
      categoriesOrTactics,
      alertDispatched,
      generatedAt: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threatshield-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getVerdictStyle = () => {
    switch (threatLevel) {
      case 'malicious':
        return {
          border: 'border-rose-800/80',
          bg: 'bg-rose-950/20',
          text: 'text-rose-400',
          badgeBg: 'bg-rose-950 text-rose-300 border-rose-800',
          progressColor: 'bg-rose-500',
          icon: <ShieldAlert className="w-6 h-6 text-rose-400" />,
        };
      case 'suspicious':
        return {
          border: 'border-amber-800/80',
          bg: 'bg-amber-950/20',
          text: 'text-amber-400',
          badgeBg: 'bg-amber-950 text-amber-300 border-amber-800',
          progressColor: 'bg-amber-500',
          icon: <AlertTriangle className="w-6 h-6 text-amber-400" />,
        };
      default:
        return {
          border: 'border-emerald-800/80',
          bg: 'bg-emerald-950/20',
          text: 'text-emerald-400',
          badgeBg: 'bg-emerald-950 text-emerald-300 border-emerald-800',
          progressColor: 'bg-emerald-500',
          icon: <ShieldCheck className="w-6 h-6 text-emerald-400" />,
        };
    }
  };

  const style = getVerdictStyle();

  return (
    <div className={`rounded-2xl border ${style.border} ${style.bg} p-6 shadow-xl space-y-6 transition-all`}>
      {/* Top Banner Row */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
        <div className="flex items-start gap-3.5">
          <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 shrink-0">
            {style.icon}
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className={`text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded border ${style.badgeBg}`}>
                {threatLevel}
              </span>
              <h3 className="text-lg font-bold text-slate-100">{threatName}</h3>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-1 truncate max-w-xl">
              {targetDetails.title} {targetDetails.subtitle && `· ${targetDetails.subtitle}`}
            </p>
          </div>
        </div>

        {/* Threat Score Dial */}
        <div className="flex items-center gap-4 self-start md:self-auto bg-slate-900/90 border border-slate-800 px-4 py-2.5 rounded-xl shrink-0">
          <div>
            <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
              Threat Score
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight text-slate-100">
              {threatScore}
              <span className="text-xs text-slate-500 font-normal"> / 100</span>
            </div>
          </div>
          <div className="w-20 bg-slate-800 h-2.5 rounded-full overflow-hidden">
            <div
              className={`h-full ${style.progressColor} transition-all duration-700`}
              style={{ width: `${Math.max(5, threatScore)}%` }}
            />
          </div>
          <button
            onClick={downloadReport}
            className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition-colors"
            title="Download JSON Report"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Automated Alert Notification Banner */}
      {alertDispatched && (
        <div className="bg-slate-950/90 border border-rose-900/80 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-rose-900/40 border border-rose-700/60 flex items-center justify-center text-rose-400 shrink-0">
              <ShieldAlert className="w-4 h-4 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-rose-300">
                  Automated Security Alert Triggered
                </span>
                <span className="text-[10px] bg-rose-950 text-rose-400 px-1.5 py-0.5 rounded border border-rose-900">
                  Delivered
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Dispatched immediately to{' '}
                <span className="text-slate-200 font-mono font-medium">
                  {alertDispatched.recipientEmail}
                </span>{' '}
                and SMS to{' '}
                <span className="text-slate-200 font-mono font-medium">
                  {alertDispatched.recipientPhone}
                </span>
              </p>
            </div>
          </div>
          <button
            onClick={() => setActiveTab('notification')}
            className="px-3 py-1.5 bg-rose-950/80 hover:bg-rose-900/80 border border-rose-800 rounded-lg text-xs font-medium text-rose-200 transition-colors shrink-0 flex items-center gap-1.5 self-start sm:self-auto"
          >
            <span>View Dispatched Alert</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-slate-800/80 pb-2">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeTab === 'overview'
              ? 'bg-slate-800 text-slate-100 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Overview & Intel
        </button>
        <button
          onClick={() => setActiveTab('iocs')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeTab === 'iocs'
              ? 'bg-slate-800 text-slate-100 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          IOCs ({iocs.length})
        </button>
        <button
          onClick={() => setActiveTab('remediation')}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            activeTab === 'remediation'
              ? 'bg-slate-800 text-slate-100 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Remediation ({remediation.length})
        </button>
        {alertDispatched && (
          <button
            onClick={() => setActiveTab('notification')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              activeTab === 'notification'
                ? 'bg-slate-800 text-rose-300 border border-slate-700'
                : 'text-slate-400 hover:text-rose-300'
            }`}
          >
            Notification Logs
          </button>
        )}
      </div>

      {/* Tab 1: Overview */}
      {activeTab === 'overview' && (
        <div className="space-y-4">
          <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
              Executive Threat Summary
            </h4>
            <p className="text-sm text-slate-200 leading-relaxed">{summary}</p>
          </div>

          {/* MITRE ATT&CK or Tactical Heuristics */}
          {((mitreTechniques && mitreTechniques.length > 0) ||
            (categoriesOrTactics && categoriesOrTactics.length > 0)) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {mitreTechniques && mitreTechniques.length > 0 && (
                <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-3.5">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 mb-2">
                    <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                    <span>MITRE ATT&CK Techniques</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {mitreTechniques.map((tech, i) => (
                      <span
                        key={i}
                        className="text-[11px] font-mono bg-slate-900 border border-slate-800 text-slate-300 px-2 py-0.5 rounded"
                      >
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {categoriesOrTactics && categoriesOrTactics.length > 0 && (
                <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-3.5">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300 mb-2">
                    <Network className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Observed Tactics & Risk Vectors</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {categoriesOrTactics.map((tac, i) => (
                      <span
                        key={i}
                        className="text-[11px] bg-slate-900 border border-slate-800 text-slate-300 px-2 py-0.5 rounded"
                      >
                        {tac}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: IOCs */}
      {activeTab === 'iocs' && (
        <div className="space-y-3">
          <div className="text-xs text-slate-400">
            Indicators of Compromise (IOCs) identified during inspection:
          </div>
          <div className="space-y-2">
            {iocs.map((ioc, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-slate-200"
              >
                <span className="truncate pr-4">{ioc}</span>
                <button
                  onClick={() => handleCopyIoc(ioc)}
                  className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-850 rounded-lg text-slate-400 hover:text-slate-200 text-[11px] flex items-center gap-1 transition-colors shrink-0"
                >
                  {copiedIoc === ioc ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Remediation */}
      {activeTab === 'remediation' && (
        <div className="space-y-3">
          <div className="text-xs text-slate-400">
            Prescribed actions to contain and eliminate this threat:
          </div>
          <div className="space-y-2">
            {remediation.map((step, idx) => (
              <div
                key={idx}
                className="flex items-start gap-3 p-3 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200"
              >
                <span className="w-5 h-5 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center text-[10px] font-bold text-slate-400 shrink-0 mt-0.5">
                  {idx + 1}
                </span>
                <p className="leading-relaxed">{step}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Notification Logs */}
      {activeTab === 'notification' && alertDispatched && (
        <div className="space-y-4">
          <div className="text-xs text-slate-400">
            Automated notifications sent upon threat detection:
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Email Dispatch Payload */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
                  <Mail className="w-4 h-4" />
                  <span>Email Security Alert</span>
                </div>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950 border border-emerald-900 px-2 py-0.5 rounded">
                  DISPATCHED
                </span>
              </div>
              <div className="text-xs text-slate-300 space-y-1 font-mono">
                <p className="text-slate-400 text-[11px]">
                  Recipient: <span className="text-slate-200">{alertDispatched.recipientEmail}</span>
                </p>
                <p className="text-slate-400 text-[11px]">
                  Subject: <span className="text-slate-200">{alertDispatched.channels.email.subject}</span>
                </p>
              </div>
              <div className="p-3 bg-slate-900/70 border border-slate-800 rounded-lg text-xs text-slate-300 italic">
                "{alertDispatched.channels.email.preview}"
              </div>
            </div>

            {/* SMS Dispatch Payload */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-semibold text-cyan-400">
                  <Smartphone className="w-4 h-4" />
                  <span>SMS Mobile Alert</span>
                </div>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950 border border-cyan-900 px-2 py-0.5 rounded">
                  DELIVERED
                </span>
              </div>
              <div className="text-xs text-slate-300 space-y-1 font-mono">
                <p className="text-slate-400 text-[11px]">
                  Mobile: <span className="text-slate-200">{alertDispatched.recipientPhone}</span>
                </p>
                <p className="text-slate-400 text-[11px]">
                  Route: <span className="text-slate-200">Priority Security Gateway</span>
                </p>
              </div>
              <div className="p-3 bg-slate-900/70 border border-slate-800 rounded-lg text-xs font-mono text-slate-200">
                {alertDispatched.channels.sms.body}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

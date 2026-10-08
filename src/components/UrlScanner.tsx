import React, { useState } from 'react';
import {
  Globe,
  Search,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Loader2,
  Lock,
  Unlock,
  Repeat
} from 'lucide-react';
import { URL_PRESETS, PresetItem } from '../utils/presets';
import { UrlScanResponse, UserAlertProfile, AlertRecord } from '../types';
import { ScanResultCard } from './ScanResultCard';

interface UrlScannerProps {
  alertProfile: UserAlertProfile;
  onAlertTriggered: (alert: AlertRecord) => void;
}

export const UrlScanner: React.FC<UrlScannerProps> = ({ alertProfile, onAlertTriggered }) => {
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [scanResult, setScanResult] = useState<UrlScanResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSelectPreset = (preset: PresetItem) => {
    setErrorMessage(null);
    setScanResult(null);
    setTargetUrl(preset.data.url);
  };

  const runUrlScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetUrl.trim()) return;

    setIsScanning(true);
    setErrorMessage(null);
    setScanResult(null);

    try {
      setScanStep('Resolving host & crawling endpoint...');
      await new Promise((r) => setTimeout(r, 400));

      setScanStep('Auditing TLS/SSL certificate & HTTP redirect chain...');
      await new Promise((r) => setTimeout(r, 400));

      setScanStep('Evaluating brand typosquatting, phishing heuristics & C2 signals...');

      const response = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: targetUrl.trim(),
          recipientEmail: alertProfile.email,
          recipientPhone: alertProfile.phone,
        }),
      });

      if (!response.ok) {
        const errJson = await response.json();
        throw new Error(errJson.error || 'Server rejected URL scan');
      }

      const data: UrlScanResponse = await response.json();
      setScanResult(data);

      if (data.alertDispatched) {
        onAlertTriggered(data.alertDispatched);
      }
    } catch (err: any) {
      console.error(err);
      setErrorMessage(err.message || 'URL inspection failed.');
    } finally {
      setIsScanning(false);
      setScanStep('');
    }
  };

  return (
    <div className="space-y-6">
      {/* Input Box & Presets */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <div className="mb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Globe className="w-5 h-5 text-cyan-400" />
              URL & Web Threat Scanner
            </h2>
            <p className="text-xs text-slate-400">
              Inspect websites for credential harvesting, typosquatting domains, open redirects, and phishing kits
            </p>
          </div>

          {/* Quick Presets */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[11px] text-slate-500 font-medium">Test Presets:</span>
            {URL_PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => handleSelectPreset(p)}
                className={`text-[11px] px-2.5 py-1 rounded-lg border font-medium transition-colors ${
                  targetUrl === p.data.url
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

        {/* URL Form */}
        <form onSubmit={runUrlScan} className="space-y-4">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Search className="w-4 h-4" />
            </div>
            <input
              type="text"
              required
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="e.g. https://login.microsoftonline.com-authportal.top/oauth or any target domain"
              className="w-full pl-10 pr-4 py-3 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-600 text-sm focus:outline-none focus:border-cyan-500 font-mono transition-colors"
            />
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="text-xs text-slate-400">
              {isScanning ? (
                <span className="flex items-center gap-2 text-cyan-400 animate-pulse font-mono">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  {scanStep}
                </span>
              ) : (
                <span className="text-slate-500">
                  Live crawler evaluates headers, SSL, redirects, and threat reputation.
                </span>
              )}
            </div>

            <button
              type="submit"
              disabled={!targetUrl.trim() || isScanning}
              className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-xl shadow-lg shadow-cyan-950/60 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Inspecting Web Target...
                </>
              ) : (
                <>
                  <Globe className="w-4 h-4" />
                  Scan URL Now
                </>
              )}
            </button>
          </div>
        </form>

        {errorMessage && (
          <div className="mt-4 p-3.5 bg-rose-950/40 border border-rose-900 rounded-xl text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>

      {/* Crawl Telemetry & Scan Result */}
      {scanResult && (
        <div className="space-y-6">
          {/* Live Crawler Telemetry Strip */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Reachability & Status
              </span>
              <div className="flex items-center gap-2">
                <span
                  className={`w-2 h-2 rounded-full ${
                    scanResult.liveInspection.reachable ? 'bg-emerald-500' : 'bg-rose-500'
                  }`}
                />
                <span className="font-mono text-xs text-slate-200">
                  {scanResult.liveInspection.statusCode
                    ? `HTTP ${scanResult.liveInspection.statusCode}`
                    : scanResult.liveInspection.reachable
                    ? 'Reachable'
                    : 'Unreachable / Blocked'}
                </span>
              </div>
            </div>

            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Transport Layer Security
              </span>
              <div className="flex items-center gap-1.5 text-xs">
                {scanResult.liveInspection.sslSecured ? (
                  <>
                    <Lock className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400 font-medium">HTTPS Active</span>
                  </>
                ) : (
                  <>
                    <Unlock className="w-3.5 h-3.5 text-rose-400" />
                    <span className="text-rose-400 font-medium">Insecure HTTP</span>
                  </>
                )}
              </div>
            </div>

            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Redirect Hops
              </span>
              <div className="flex items-center gap-1.5 text-xs text-slate-200 font-mono">
                <Repeat className="w-3.5 h-3.5 text-slate-400" />
                <span>
                  {scanResult.liveInspection.redirects.length === 0
                    ? 'Direct (0 Hops)'
                    : `${scanResult.liveInspection.redirects.length} Hops recorded`}
                </span>
              </div>
            </div>

            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Extracted Title
              </span>
              <span className="text-xs text-slate-200 truncate block font-mono">
                {scanResult.liveInspection.pageTitle || 'No HTML Title Tag'}
              </span>
            </div>
          </div>

          {/* Verdict Card with Automated Alert Notification */}
          <ScanResultCard
            threatLevel={scanResult.assessment.threatLevel}
            threatScore={scanResult.assessment.threatScore}
            threatName={scanResult.assessment.threatName}
            summary={scanResult.assessment.summary}
            iocs={scanResult.assessment.iocs}
            remediation={scanResult.assessment.remediation}
            categoriesOrTactics={[
              ...scanResult.assessment.categories,
              ...scanResult.assessment.riskFactors,
            ]}
            alertDispatched={scanResult.alertDispatched}
            targetDetails={{
              type: 'URL',
              title: scanResult.url,
              subtitle: scanResult.assessment.brandImpersonationTarget
                ? `Impersonates: ${scanResult.assessment.brandImpersonationTarget}`
                : undefined,
            }}
          />
        </div>
      )}
    </div>
  );
};

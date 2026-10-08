import React, { useState } from 'react';
import {
  Bell,
  Trash2,
  Mail,
  Smartphone,
  ShieldAlert,
  AlertTriangle,
  Clock,
  ExternalLink,
  CheckCircle,
  Copy,
  Check,
  FileText,
  Globe,
  Inbox
} from 'lucide-react';
import { AlertRecord, TargetType } from '../types';

interface AlertsCenterProps {
  alerts: AlertRecord[];
  onDismissAlert: (id: string) => void;
  onClearAllAlerts: () => void;
  onSendTestAlert: () => void;
  isSendingTestAlert: boolean;
}

export const AlertsCenter: React.FC<AlertsCenterProps> = ({
  alerts,
  onDismissAlert,
  onClearAllAlerts,
  onSendTestAlert,
  isSendingTestAlert,
}) => {
  const [filterType, setFilterType] = useState<'all' | TargetType>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredAlerts = alerts.filter((a) => {
    if (filterType === 'all') return true;
    return a.targetType === filterType;
  });

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getTargetIcon = (type: TargetType) => {
    switch (type) {
      case 'file':
        return <FileText className="w-4 h-4 text-emerald-400" />;
      case 'url':
        return <Globe className="w-4 h-4 text-cyan-400" />;
      case 'email':
        return <Inbox className="w-4 h-4 text-amber-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-rose-950/80 border border-rose-800/80 flex items-center justify-center text-rose-400 shrink-0">
              <Bell className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100">Dispatched Incident Alerts Log</h2>
              <p className="text-xs text-slate-400">
                Audited notifications dispatched to registered login email and phone
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onSendTestAlert}
              disabled={isSendingTestAlert}
              className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-xs font-medium text-slate-200 transition-colors flex items-center gap-2 disabled:opacity-50"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              {isSendingTestAlert ? 'Dispatching...' : 'Dispatch Test Alert'}
            </button>
            {alerts.length > 0 && (
              <button
                onClick={onClearAllAlerts}
                className="px-3.5 py-2 bg-rose-950/40 hover:bg-rose-950/70 border border-rose-900/60 rounded-xl text-xs font-medium text-rose-300 transition-colors flex items-center gap-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Clear Log
              </button>
            )}
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex items-center gap-2 mt-6 pt-5 border-t border-slate-800/80">
          <span className="text-xs text-slate-400 mr-1">Filter Vector:</span>
          {(['all', 'file', 'url', 'email'] as const).map((type) => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors capitalize ${
                filterType === type
                  ? 'bg-slate-800 text-emerald-400 border border-slate-700 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-850'
              }`}
            >
              {type === 'all' ? 'All Incidents' : `${type} Scans`}
            </button>
          ))}
          <span className="ml-auto text-xs font-mono text-slate-500 tabular-nums">
            {filteredAlerts.length} {filteredAlerts.length === 1 ? 'record' : 'records'}
          </span>
        </div>
      </div>

      {/* Alerts List */}
      {filteredAlerts.length === 0 ? (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center">
          <div className="w-12 h-12 rounded-full bg-slate-800/80 flex items-center justify-center mx-auto text-slate-500 mb-4">
            <CheckCircle className="w-6 h-6 text-emerald-400" />
          </div>
          <h3 className="text-sm font-semibold text-slate-200 mb-1">No Active Incident Alerts</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto mb-5">
            When the File, URL, or Email scanner detects a threat with score &ge; 40, real-time alerts are automatically dispatched and logged here.
          </p>
          <button
            onClick={onSendTestAlert}
            disabled={isSendingTestAlert}
            className="px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/40 text-emerald-300 rounded-xl text-xs font-medium transition-colors inline-flex items-center gap-2"
          >
            <ShieldAlert className="w-4 h-4" />
            Send Sample Test Alert to Verify
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className={`bg-slate-900 border rounded-2xl p-5 transition-all ${
                alert.threatLevel === 'malicious'
                  ? 'border-rose-900/50 hover:border-rose-800/80 shadow-lg shadow-rose-950/20'
                  : 'border-amber-900/50 hover:border-amber-800/80'
              }`}
            >
              {/* Alert Header Row */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-slate-800/80 border border-slate-700/80">
                    {getTargetIcon(alert.targetType)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-slate-100 text-sm">
                        {alert.threatName}
                      </span>
                      <span
                        className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                          alert.threatLevel === 'malicious'
                            ? 'bg-rose-950 text-rose-400 border border-rose-800'
                            : 'bg-amber-950 text-amber-400 border border-amber-800'
                        }`}
                      >
                        {alert.threatLevel} ({alert.threatScore}/100)
                      </span>
                      <span className="text-[11px] font-mono text-slate-500">
                        {alert.id}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-slate-400 mt-0.5">
                      <span className="font-mono text-slate-300 truncate max-w-sm">
                        {alert.targetIdentifier}
                      </span>
                      <span>·</span>
                      <span className="flex items-center gap-1 font-mono text-[11px] text-slate-500">
                        <Clock className="w-3 h-3" />
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-auto">
                  <button
                    onClick={() => handleCopy(JSON.stringify(alert, null, 2), alert.id)}
                    className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg text-xs flex items-center gap-1 transition-colors"
                    title="Copy Alert JSON"
                  >
                    {copiedId === alert.id ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                    <span className="text-[11px]">Copy</span>
                  </button>
                  <button
                    onClick={() => onDismissAlert(alert.id)}
                    className="p-1.5 text-slate-500 hover:text-rose-400 hover:bg-rose-950/40 rounded-lg transition-colors"
                    title="Dismiss Alert"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Alert Summary */}
              <p className="text-xs text-slate-300 mb-4 bg-slate-950/60 p-3 rounded-xl border border-slate-850">
                {alert.summary}
              </p>

              {/* Notification Dispatch Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
                {/* Email Dispatch Card */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between text-xs mb-2">
                      <div className="flex items-center gap-1.5 font-medium text-emerald-400">
                        <Mail className="w-3.5 h-3.5" />
                        <span>Email Alert Dispatched</span>
                      </div>
                      <span className="text-[10px] font-mono text-emerald-500 bg-emerald-950/60 border border-emerald-900 px-1.5 py-0.2 rounded flex items-center gap-1">
                        <Check className="w-2.5 h-2.5" /> Delivered
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 space-y-1">
                      <p>
                        <span className="text-slate-500">To:</span>{' '}
                        <span className="font-mono text-slate-200 font-medium">
                          {alert.channels.email.recipient}
                        </span>
                      </p>
                      <p className="font-medium text-slate-300 truncate">
                        <span className="text-slate-500">Subject:</span>{' '}
                        {alert.channels.email.subject}
                      </p>
                    </div>
                  </div>
                  <div className="mt-3 pt-2 border-t border-slate-850 text-[11px] text-slate-400 italic">
                    "{alert.channels.email.preview}"
                  </div>
                </div>

                {/* SMS Dispatch Card */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between text-xs mb-2">
                      <div className="flex items-center gap-1.5 font-medium text-cyan-400">
                        <Smartphone className="w-3.5 h-3.5" />
                        <span>SMS / Phone Alert Dispatched</span>
                      </div>
                      <span className="text-[10px] font-mono text-cyan-500 bg-cyan-950/60 border border-cyan-900 px-1.5 py-0.2 rounded flex items-center gap-1">
                        <Check className="w-2.5 h-2.5" /> Sent
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 space-y-1">
                      <p>
                        <span className="text-slate-500">Phone:</span>{' '}
                        <span className="font-mono text-slate-200 font-medium">
                          {alert.channels.sms.recipient}
                        </span>
                      </p>
                      <p>
                        <span className="text-slate-500">Carrier Gateway:</span>{' '}
                        <span className="text-slate-300">Direct Route</span>
                      </p>
                    </div>
                  </div>
                  <div className="mt-3 pt-2 border-t border-slate-850 text-[11px] font-mono text-slate-300 bg-slate-900/60 p-2 rounded">
                    {alert.channels.sms.body}
                  </div>
                </div>
              </div>

              {/* IOCs & Remediation Footer */}
              {alert.iocs && alert.iocs.length > 0 && (
                <div className="text-[11px] text-slate-400 flex items-center gap-2 flex-wrap">
                  <span className="text-slate-500 font-medium">Extracted IOCs:</span>
                  {alert.iocs.slice(0, 3).map((ioc, i) => (
                    <span
                      key={i}
                      className="font-mono text-[10px] bg-slate-950 border border-slate-800 px-2 py-0.5 rounded text-slate-300 truncate max-w-[200px]"
                    >
                      {ioc}
                    </span>
                  ))}
                  {alert.iocs.length > 3 && (
                    <span className="text-slate-500 text-[10px]">
                      +{alert.iocs.length - 3} more
                    </span>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

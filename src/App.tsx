/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  Shield,
  FileCode,
  Globe,
  Inbox,
  Bell,
  Activity,
  CheckCircle,
  AlertTriangle,
  Send,
  ExternalLink,
  ShieldAlert,
  Info,
  Phone,
  Mail,
  Zap
} from 'lucide-react';
import { Header } from './components/Header';
import { AlertSettingsModal } from './components/AlertSettingsModal';
import { AlertsCenter } from './components/AlertsCenter';
import { FileScanner } from './components/FileScanner';
import { UrlScanner } from './components/UrlScanner';
import { EmailScanner } from './components/EmailScanner';
import { UserAlertProfile, AlertRecord, TargetType } from './types';
import { playSecurityAlertSound } from './utils/audioAlert';

export default function App() {
  const [activeTab, setActiveTab] = useState<'file' | 'url' | 'email' | 'alerts'>('file');
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  // User Alert Profile (Login email and mobile)
  const [alertProfile, setAlertProfile] = useState<UserAlertProfile>(() => {
    const saved = localStorage.getItem('threatshield_profile');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        // Ignored
      }
    }
    return {
      email: 'raajaram0728@gmail.com',
      phone: '+1 (555) 234-5678',
      notifyOnMedium: true,
      notifyOnHigh: true,
      soundEnabled: true,
      browserNotificationsEnabled: true,
    };
  });

  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [isSendingTestAlert, setIsSendingTestAlert] = useState(false);
  const [toastMessage, setToastMessage] = useState<{
    title: string;
    description: string;
    type: 'critical' | 'success' | 'info';
  } | null>(null);

  // Fetch alerts from backend on mount
  useEffect(() => {
    fetchAlerts();
  }, []);

  const fetchAlerts = async () => {
    try {
      const res = await fetch('/api/alerts');
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.alerts || []);
      }
    } catch (err) {
      console.warn('Could not fetch alerts log:', err);
    }
  };

  const handleSaveProfile = (updated: UserAlertProfile) => {
    setAlertProfile(updated);
    localStorage.setItem('threatshield_profile', JSON.stringify(updated));
    showToast('Preferences Saved', 'Alert contact numbers & thresholds updated.', 'success');
  };

  const showToast = (title: string, description: string, type: 'critical' | 'success' | 'info') => {
    setToastMessage({ title, description, type });
    setTimeout(() => {
      setToastMessage(null);
    }, 5000);
  };

  const handleAlertTriggered = (newAlert: AlertRecord) => {
    // Add to alerts list
    setAlerts((prev) => [newAlert, ...prev]);

    // Sound chime if enabled
    if (alertProfile.soundEnabled) {
      if (newAlert.threatLevel === 'malicious') {
        playSecurityAlertSound('critical');
      } else {
        playSecurityAlertSound('warning');
      }
    }

    // Web Notification if permitted
    if (alertProfile.browserNotificationsEnabled && 'Notification' in window) {
      if (Notification.permission === 'granted') {
        new Notification(`[THREATSHIELD ALERT] ${newAlert.threatName}`, {
          body: `${newAlert.threatLevel.toUpperCase()} threat detected! Dispatched to ${alertProfile.email}`,
          icon: '/favicon.ico',
        });
      } else if (Notification.permission !== 'denied') {
        Notification.requestPermission();
      }
    }

    // Interactive Toast Banner
    showToast(
      `🚨 ${newAlert.threatLevel.toUpperCase()} Threat Detected!`,
      `Incident notification dispatched to ${alertProfile.email} and SMS to ${alertProfile.phone}.`,
      'critical'
    );
  };

  const handleSendTestAlert = async () => {
    setIsSendingTestAlert(true);
    try {
      const res = await fetch('/api/alerts/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipientEmail: alertProfile.email,
          recipientPhone: alertProfile.phone,
        }),
      });

      if (!res.ok) throw new Error('Failed to dispatch test notification');

      const data = await res.json();
      if (data.alert) {
        handleAlertTriggered(data.alert);
      } else {
        showToast('Test Alert Dispatched', `Verified delivery to ${alertProfile.email} & ${alertProfile.phone}`, 'success');
      }
    } catch (err: any) {
      console.error(err);
      showToast('Dispatch Error', err.message || 'Failed to dispatch test alert', 'critical');
    } finally {
      setIsSendingTestAlert(false);
    }
  };

  const handleDismissAlert = async (id: string) => {
    try {
      await fetch('/api/alerts/dismiss', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });
      setAlerts((prev) => prev.filter((a) => a.id !== id));
    } catch (err) {
      console.error(err);
    }
  };

  const handleClearAllAlerts = async () => {
    try {
      await fetch('/api/alerts/clear', { method: 'DELETE' });
      setAlerts([]);
      showToast('Log Cleared', 'All incident alert records have been purged.', 'info');
    } catch (err) {
      console.error(err);
    }
  };

  const activeAlertCount = alerts.filter((a) => a.threatScore >= 40).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Header */}
      <Header
        alertProfile={alertProfile}
        activeAlertCount={activeAlertCount}
        totalAlertCount={alerts.length}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenAlertsCenter={() => setActiveTab('alerts')}
        onToggleSound={() =>
          handleSaveProfile({ ...alertProfile, soundEnabled: !alertProfile.soundEnabled })
        }
        onSendTestAlert={handleSendTestAlert}
        isSendingTestAlert={isSendingTestAlert}
      />

      {/* Floating Incident Notification Toast */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 max-w-md animate-in slide-in-from-bottom duration-300">
          <div
            className={`p-4 rounded-2xl border shadow-2xl flex items-start gap-3 backdrop-blur ${
              toastMessage.type === 'critical'
                ? 'bg-slate-900/95 border-rose-600 text-slate-100 shadow-rose-950/50'
                : toastMessage.type === 'success'
                ? 'bg-slate-900/95 border-emerald-600 text-slate-100 shadow-emerald-950/50'
                : 'bg-slate-900/95 border-slate-700 text-slate-100'
            }`}
          >
            <div className="p-2 rounded-xl bg-slate-800 shrink-0">
              {toastMessage.type === 'critical' ? (
                <ShieldAlert className="w-5 h-5 text-rose-400 animate-pulse" />
              ) : toastMessage.type === 'success' ? (
                <CheckCircle className="w-5 h-5 text-emerald-400" />
              ) : (
                <Info className="w-5 h-5 text-cyan-400" />
              )}
            </div>
            <div className="flex-1">
              <h4 className="text-xs font-bold text-slate-100">{toastMessage.title}</h4>
              <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">
                {toastMessage.description}
              </p>
            </div>
            <button
              onClick={() => setToastMessage(null)}
              className="text-slate-400 hover:text-slate-100 text-xs px-1.5 py-0.5 rounded hover:bg-slate-800"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Top Hero Overview Banner */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-2">
          <div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100 tracking-tight">
              Cyber Threat Intelligence Scanner
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Deep real-time forensic scanning for suspicious files, phishing URLs, and deceptive emails with automated incident alert dispatching to your registered email & phone.
            </p>
          </div>

          {/* Quick Status / Registered Target Strip */}
          <div className="flex items-center gap-3 bg-slate-900/80 border border-slate-800 p-3 rounded-2xl shrink-0 self-start lg:self-auto">
            <div className="flex flex-col">
              <span className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">
                Automated Alert Recipient
              </span>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="font-mono text-xs text-emerald-400 font-medium">
                  {alertProfile.email}
                </span>
                <span className="text-slate-600">·</span>
                <span className="font-mono text-xs text-cyan-400 font-medium">
                  {alertProfile.phone}
                </span>
              </div>
            </div>
            <button
              onClick={() => setIsSettingsOpen(true)}
              className="ml-2 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition-colors"
            >
              Edit
            </button>
          </div>
        </div>

        {/* Tab Navigation Controls */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-1.5 p-1 bg-slate-900 rounded-xl border border-slate-800/80 overflow-x-auto max-w-full">
            <button
              onClick={() => setActiveTab('file')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
                activeTab === 'file'
                  ? 'bg-emerald-600 text-slate-950 shadow-md shadow-emerald-950/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <FileCode className="w-4 h-4" />
              <span>File Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('url')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
                activeTab === 'url'
                  ? 'bg-cyan-600 text-slate-950 shadow-md shadow-cyan-950/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Globe className="w-4 h-4" />
              <span>URL Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('email')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
                activeTab === 'email'
                  ? 'bg-amber-500 text-slate-950 shadow-md shadow-amber-950/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Inbox className="w-4 h-4" />
              <span>Email Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('alerts')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all shrink-0 ${
                activeTab === 'alerts'
                  ? 'bg-rose-600 text-slate-100 shadow-md shadow-rose-950/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Bell className="w-4 h-4" />
              <span>Alerts & Notifications</span>
              {activeAlertCount > 0 && (
                <span className="bg-rose-950 text-rose-300 border border-rose-800 px-1.5 py-0.2 rounded text-[10px] font-bold">
                  {activeAlertCount}
                </span>
              )}
            </button>
          </div>

          <div className="hidden sm:flex items-center gap-2 text-xs text-slate-500 font-mono">
            <Zap className="w-3.5 h-3.5 text-emerald-400" />
            <span>Gemini Threat Intelligence Active</span>
          </div>
        </div>

        {/* Tab View Container */}
        <div>
          {activeTab === 'file' && (
            <FileScanner
              alertProfile={alertProfile}
              onAlertTriggered={handleAlertTriggered}
            />
          )}

          {activeTab === 'url' && (
            <UrlScanner
              alertProfile={alertProfile}
              onAlertTriggered={handleAlertTriggered}
            />
          )}

          {activeTab === 'email' && (
            <EmailScanner
              alertProfile={alertProfile}
              onAlertTriggered={handleAlertTriggered}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsCenter
              alerts={alerts}
              onDismissAlert={handleDismissAlert}
              onClearAllAlerts={handleClearAllAlerts}
              onSendTestAlert={handleSendTestAlert}
              isSendingTestAlert={isSendingTestAlert}
            />
          )}
        </div>
      </main>

      {/* Settings Modal */}
      <AlertSettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        profile={alertProfile}
        onSave={handleSaveProfile}
        onSendTestAlert={handleSendTestAlert}
        isSendingTestAlert={isSendingTestAlert}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-6 mt-12 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-500" />
            <span className="text-slate-400 font-medium">ThreatShield Security Engine</span>
            <span>·</span>
            <span>Real Data Threat Heuristics & Multi-Channel Alert Dispatch</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400">
            <span>Configured for: {alertProfile.email}</span>
            <span>·</span>
            <button
              onClick={() => setIsSettingsOpen(true)}
              className="text-emerald-400 hover:underline"
            >
              Alert Preferences
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}

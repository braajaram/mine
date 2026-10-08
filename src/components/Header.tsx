import React from 'react';
import { Shield, Bell, Volume2, VolumeX, Phone, Mail, Settings, Send } from 'lucide-react';
import { UserAlertProfile } from '../types';

interface HeaderProps {
  alertProfile: UserAlertProfile;
  activeAlertCount: number;
  totalAlertCount: number;
  onOpenSettings: () => void;
  onOpenAlertsCenter: () => void;
  onToggleSound: () => void;
  onSendTestAlert: () => void;
  isSendingTestAlert: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  alertProfile,
  activeAlertCount,
  onOpenSettings,
  onOpenAlertsCenter,
  onToggleSound,
  onSendTestAlert,
  isSendingTestAlert,
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-emerald-600 to-teal-400 flex items-center justify-center shadow-lg shadow-emerald-950/40 text-slate-950 font-bold">
            <Shield className="w-5 h-5 text-slate-950" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-100 text-lg tracking-tight">ThreatShield</span>
              <span className="text-[10px] tracking-wider font-semibold uppercase text-emerald-400 bg-emerald-950/80 border border-emerald-800/60 px-1.5 py-0.5 rounded">
                Live Engine
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Multi-Vector Threat Intelligence & Alert Dispatcher
            </p>
          </div>
        </div>

        {/* User Alert Contact & Controls */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Notification Target Info */}
          <button
            onClick={onOpenSettings}
            className="hidden md:flex items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/80 hover:bg-slate-800 text-xs text-slate-300 transition-colors text-left"
            title="Configure Alert Recipients"
          >
            <div className="flex flex-col gap-0.5">
              <div className="flex items-center gap-1.5 text-slate-400">
                <Mail className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span className="font-mono text-[11px] text-slate-200 truncate max-w-[170px]">
                  {alertProfile.email}
                </span>
              </div>
              <div className="flex items-center gap-1.5 text-slate-400">
                <Phone className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="font-mono text-[11px] text-slate-200">
                  {alertProfile.phone}
                </span>
              </div>
            </div>
            <Settings className="w-3.5 h-3.5 text-slate-400 hover:text-slate-200" />
          </button>

          {/* Test Alert Dispatch Button */}
          <button
            onClick={onSendTestAlert}
            disabled={isSendingTestAlert}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/40 text-emerald-300 text-xs font-medium transition-colors disabled:opacity-50"
            title="Dispatch a live test alert to your email and phone"
          >
            <Send className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">
              {isSendingTestAlert ? 'Dispatching...' : 'Test Alert'}
            </span>
          </button>

          {/* Audio Chime Toggle */}
          <button
            onClick={onToggleSound}
            className={`p-2 rounded-lg border text-xs transition-colors ${
              alertProfile.soundEnabled
                ? 'bg-slate-800 text-emerald-400 border-slate-700 hover:bg-slate-700/80'
                : 'bg-slate-900 text-slate-500 border-slate-800 hover:bg-slate-800'
            }`}
            title={alertProfile.soundEnabled ? 'Audio Alerts: ON' : 'Audio Alerts: OFF'}
            aria-label="Toggle alert chime"
          >
            {alertProfile.soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
          </button>

          {/* Alerts Center Bell Button */}
          <button
            onClick={onOpenAlertsCenter}
            className="relative p-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition-colors"
            title="View Incident Alerts Log"
            aria-label="Open alerts log"
          >
            <Bell className="w-4 h-4 text-slate-300" />
            {activeAlertCount > 0 && (
              <span className="absolute -top-1 -right-1 w-5 h-5 bg-rose-600 text-white rounded-full text-[10px] font-bold flex items-center justify-center animate-pulse shadow-md shadow-rose-900">
                {activeAlertCount}
              </span>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};

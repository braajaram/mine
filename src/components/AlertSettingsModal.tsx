import React, { useState } from 'react';
import { X, Mail, Phone, BellRing, Volume2, Send, CheckCircle2, ShieldAlert } from 'lucide-react';
import { UserAlertProfile } from '../types';

interface AlertSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  profile: UserAlertProfile;
  onSave: (updated: UserAlertProfile) => void;
  onSendTestAlert: () => void;
  isSendingTestAlert: boolean;
}

export const AlertSettingsModal: React.FC<AlertSettingsModalProps> = ({
  isOpen,
  onClose,
  profile,
  onSave,
  onSendTestAlert,
  isSendingTestAlert,
}) => {
  const [formData, setFormData] = useState<UserAlertProfile>(profile);
  const [savedSuccess, setSavedSuccess] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      onClose();
    }, 900);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-emerald-950/80 border border-emerald-800/80 rounded-lg text-emerald-400">
              <BellRing className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-slate-100">Alert Notification Settings</h2>
              <p className="text-xs text-slate-400">
                Configure your login email & phone number to receive real-time threat alerts
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {/* Email Recipient */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
              <Mail className="w-3.5 h-3.5 text-emerald-400" />
              Login / Alert Notification Email
            </label>
            <input
              type="email"
              required
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              placeholder="e.g. your-security-officer@domain.com"
              className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-600 text-sm focus:outline-none focus:border-emerald-500 font-mono transition-colors"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Malicious scan reports and remediation guides will be dispatched to this email.
            </p>
          </div>

          {/* Phone Recipient */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
              <Phone className="w-3.5 h-3.5 text-cyan-400" />
              Login / SMS Alert Phone Number
            </label>
            <input
              type="tel"
              required
              value={formData.phone}
              onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
              placeholder="+1 (555) 000-0000 or international format"
              className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-600 text-sm focus:outline-none focus:border-cyan-500 font-mono transition-colors"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Urgent SMS alert text notifications will be dispatched immediately on threat detection.
            </p>
          </div>

          {/* Toggles */}
          <div className="space-y-3 pt-2 border-t border-slate-800/80">
            <span className="text-xs font-semibold text-slate-300 block">Notification Triggers</span>

            <label className="flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={formData.notifyOnHigh}
                onChange={(e) => setFormData({ ...formData, notifyOnHigh: e.target.checked })}
                className="mt-0.5 rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500"
              />
              <div className="text-xs">
                <span className="text-slate-200 font-medium group-hover:text-emerald-300 transition-colors">
                  Notify on Malicious Threats (Score &ge; 70)
                </span>
                <p className="text-slate-400 text-[11px]">
                  Ransomware, trojans, credential harvesting URLs, BEC fraud.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={formData.notifyOnMedium}
                onChange={(e) => setFormData({ ...formData, notifyOnMedium: e.target.checked })}
                className="mt-0.5 rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500"
              />
              <div className="text-xs">
                <span className="text-slate-200 font-medium group-hover:text-emerald-300 transition-colors">
                  Notify on Suspicious Risks (Score &ge; 40)
                </span>
                <p className="text-slate-400 text-[11px]">
                  Unusual obfuscation, typosquatting domains, urgency keywords.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                checked={formData.soundEnabled}
                onChange={(e) => setFormData({ ...formData, soundEnabled: e.target.checked })}
                className="mt-0.5 rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500"
              />
              <div className="text-xs">
                <span className="text-slate-200 font-medium group-hover:text-emerald-300 transition-colors">
                  Audio Alert Siren Chime
                </span>
                <p className="text-slate-400 text-[11px]">
                  Plays instant Web Audio alert tone when a scan flags a critical threat.
                </p>
              </div>
            </label>
          </div>

          {/* Test Alert Dispatch Box */}
          <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-xl flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
              <div className="text-xs">
                <p className="text-slate-200 font-medium">Verify Delivery Channels</p>
                <p className="text-slate-500 text-[11px]">Dispatch a test incident to your email & phone</p>
              </div>
            </div>
            <button
              type="button"
              onClick={onSendTestAlert}
              disabled={isSendingTestAlert}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-medium text-slate-200 flex items-center gap-1.5 transition-colors disabled:opacity-50 shrink-0"
            >
              <Send className="w-3 h-3" />
              {isSendingTestAlert ? 'Sending...' : 'Test Now'}
            </button>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs transition-colors flex items-center gap-1.5 shadow-lg shadow-emerald-950/50"
            >
              {savedSuccess ? (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  Saved
                </>
              ) : (
                'Save Preferences'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

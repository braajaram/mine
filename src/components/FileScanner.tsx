import React, { useState, useRef } from 'react';
import {
  Upload,
  FileCode,
  CheckCircle2,
  AlertCircle,
  FileText,
  Hash,
  Activity,
  Layers,
  ArrowRight,
  Shield,
  Loader2
} from 'lucide-react';
import { FILE_PRESETS, PresetItem } from '../utils/presets';
import { FileScanResponse, UserAlertProfile, AlertRecord } from '../types';
import { ScanResultCard } from './ScanResultCard';

interface FileScannerProps {
  alertProfile: UserAlertProfile;
  onAlertTriggered: (alert: AlertRecord) => void;
}

export const FileScanner: React.FC<FileScannerProps> = ({ alertProfile, onAlertTriggered }) => {
  const [selectedFile, setSelectedFile] = useState<{
    name: string;
    size: number;
    type: string;
    content: string; // base64 or text
  } | null>(null);

  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [scanResult, setScanResult] = useState<FileScanResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileProcess = (file: File) => {
    setErrorMessage(null);
    setScanResult(null);

    const reader = new FileReader();
    reader.onload = (e) => {
      const result = e.target?.result as string;
      setSelectedFile({
        name: file.name,
        size: file.size,
        type: file.type || 'application/octet-stream',
        content: result,
      });
    };
    reader.onerror = () => {
      setErrorMessage('Failed to read file from local filesystem.');
    };

    // Read as Data URL so binary files and text both work cleanly
    reader.readAsDataURL(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileProcess(e.dataTransfer.files[0]);
    }
  };

  const handleSelectPreset = (preset: PresetItem) => {
    setErrorMessage(null);
    setScanResult(null);
    setSelectedFile({
      name: preset.data.filename,
      size: preset.data.content.length,
      type: preset.data.mimeType,
      content: preset.data.content,
    });
  };

  const runFileScan = async () => {
    if (!selectedFile) return;

    setIsScanning(true);
    setErrorMessage(null);
    setScanResult(null);

    try {
      setScanStep('Hashing binary payload (SHA-256, MD5, SHA-1)...');
      await new Promise((r) => setTimeout(r, 400));

      setScanStep('Computing Shannon entropy & extracting executable strings...');
      await new Promise((r) => setTimeout(r, 400));

      setScanStep('Executing threat intelligence & MITRE heuristics...');

      const response = await fetch('/api/scan/file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: selectedFile.name,
          fileContent: selectedFile.content,
          mimeType: selectedFile.type,
          recipientEmail: alertProfile.email,
          recipientPhone: alertProfile.phone,
        }),
      });

      if (!response.ok) {
        const errJson = await response.json();
        throw new Error(errJson.error || 'Server rejected file inspection');
      }

      const data: FileScanResponse = await response.json();
      setScanResult(data);

      if (data.alertDispatched) {
        onAlertTriggered(data.alertDispatched);
      }
    } catch (err: any) {
      console.error(err);
      setErrorMessage(err.message || 'File inspection encountered an error.');
    } finally {
      setIsScanning(false);
      setScanStep('');
    }
  };

  return (
    <div className="space-y-6">
      {/* Upload & Preset Area */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <div className="mb-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <FileCode className="w-5 h-5 text-emerald-400" />
              File Threat Scanner
            </h2>
            <p className="text-xs text-slate-400">
              Upload binaries, scripts, or macro documents for cryptographic hash, entropy, and threat evaluation
            </p>
          </div>

          {/* Quick Presets */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[11px] text-slate-500 font-medium">Test Presets:</span>
            {FILE_PRESETS.map((p) => (
              <button
                key={p.id}
                onClick={() => handleSelectPreset(p)}
                className={`text-[11px] px-2.5 py-1 rounded-lg border font-medium transition-colors ${
                  selectedFile?.name === p.data.filename
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
                {p.name.split('.')[0]}
              </button>
            ))}
          </div>
        </div>

        {/* Dropzone */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
            isDragging
              ? 'border-emerald-500 bg-emerald-950/20'
              : selectedFile
              ? 'border-slate-700 bg-slate-950/40 hover:border-slate-600'
              : 'border-slate-800 hover:border-slate-700 bg-slate-950/20'
          }`}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleFileProcess(e.target.files[0]);
              }
            }}
            className="hidden"
          />

          <div className="flex flex-col items-center justify-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-300">
              <Upload className="w-5 h-5 text-emerald-400" />
            </div>

            {selectedFile ? (
              <div>
                <div className="flex items-center gap-2 justify-center">
                  <span className="font-semibold text-sm text-slate-200">
                    {selectedFile.name}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    ({(selectedFile.size / 1024).toFixed(1)} KB)
                  </span>
                </div>
                <p className="text-xs text-slate-500 font-mono mt-0.5">{selectedFile.type}</p>
                <p className="text-[11px] text-emerald-400 mt-2">
                  File loaded and staged. Click "Scan File" below.
                </p>
              </div>
            ) : (
              <div>
                <p className="text-sm font-medium text-slate-300">
                  Drop files here or click to browse
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  Supports binaries (.exe, .dll), scripts (.bat, .ps1, .sh), documents (.docm, .pdf), or text
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Scan Button & Step */}
        <div className="mt-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="text-xs text-slate-400">
            {isScanning && (
              <span className="flex items-center gap-2 text-emerald-400 animate-pulse font-mono">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                {scanStep}
              </span>
            )}
            {!isScanning && selectedFile && (
              <span className="text-slate-500">Ready to initiate file forensic inspection.</span>
            )}
          </div>

          <button
            onClick={runFileScan}
            disabled={!selectedFile || isScanning}
            className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs rounded-xl shadow-lg shadow-emerald-950/60 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Analyzing File...
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                Scan File Now
              </>
            )}
          </button>
        </div>

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
          {/* File Cryptographic Details Strip */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                SHA-256 Hash
              </span>
              <span className="font-mono text-xs text-slate-200 break-all select-all">
                {scanResult.fileInfo.hashes.sha256}
              </span>
            </div>
            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                MD5 Hash
              </span>
              <span className="font-mono text-xs text-slate-200 break-all select-all">
                {scanResult.fileInfo.hashes.md5}
              </span>
            </div>
            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Shannon Entropy
              </span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-bold text-slate-200">
                  {scanResult.fileInfo.entropy} / 8.0
                </span>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded font-medium ${
                    scanResult.fileInfo.entropy > 7.1
                      ? 'bg-rose-950 text-rose-400 border border-rose-900'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {scanResult.fileInfo.entropy > 7.1 ? 'High (Packed)' : 'Normal'}
                </span>
              </div>
            </div>
            <div>
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">
                Indicators Found
              </span>
              <span className="font-mono text-sm font-bold text-slate-200">
                {scanResult.fileInfo.matchedIndicators.length} pattern matches
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
            mitreTechniques={scanResult.assessment.mitreTechniques}
            alertDispatched={scanResult.alertDispatched}
            targetDetails={{
              type: 'File',
              title: scanResult.fileInfo.filename,
              subtitle: `${(scanResult.fileInfo.sizeBytes / 1024).toFixed(1)} KB · ${
                scanResult.fileInfo.mimeType
              }`,
            }}
          />
        </div>
      )}
    </div>
  );
};

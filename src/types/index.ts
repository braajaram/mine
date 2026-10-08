export type TargetType = 'file' | 'url' | 'email';
export type ThreatLevel = 'clean' | 'low' | 'suspicious' | 'malicious';

export interface AlertChannelInfo {
  sent: boolean;
  recipient: string;
  subject?: string;
  preview?: string;
  body?: string;
  deliveredAt: string;
}

export interface AlertRecord {
  id: string;
  timestamp: string;
  targetType: TargetType;
  targetIdentifier: string;
  threatLevel: ThreatLevel;
  threatScore: number;
  threatName: string;
  summary: string;
  recipientEmail: string;
  recipientPhone: string;
  channels: {
    email: AlertChannelInfo;
    sms: AlertChannelInfo;
  };
  iocs: string[];
  remediation: string[];
}

export interface UserAlertProfile {
  email: string;
  phone: string;
  notifyOnMedium: boolean; // >= 40
  notifyOnHigh: boolean;   // >= 70
  soundEnabled: boolean;
  browserNotificationsEnabled: boolean;
}

export interface FileScanResponse {
  success: boolean;
  fileInfo: {
    filename: string;
    sizeBytes: number;
    mimeType: string;
    hashes: {
      sha256: string;
      md5: string;
      sha1: string;
    };
    entropy: number;
    matchedIndicators: string[];
  };
  assessment: {
    threatLevel: ThreatLevel;
    threatScore: number;
    threatName: string;
    summary: string;
    mitreTechniques: string[];
    iocs: string[];
    remediation: string[];
    details?: {
      fileTypeDescription: string;
      packerOrObfuscationDetected: boolean;
      maliciousCapabilities: string[];
    };
  };
  alertDispatched: AlertRecord | null;
}

export interface UrlScanResponse {
  success: boolean;
  url: string;
  liveInspection: {
    statusCode?: number;
    finalUrl?: string;
    redirects: string[];
    headers: Record<string, string>;
    sslSecured: boolean;
    pageTitle?: string;
    reachable: boolean;
    errorMessage?: string;
  };
  assessment: {
    threatLevel: ThreatLevel;
    threatScore: number;
    threatName: string;
    summary: string;
    categories: string[];
    riskFactors: string[];
    iocs: string[];
    remediation: string[];
    brandImpersonationTarget?: string | null;
  };
  alertDispatched: AlertRecord | null;
}

export interface EmailScanResponse {
  success: boolean;
  emailDetails: {
    sender: string;
    replyTo: string;
    subject: string;
    extractedUrls: string[];
    hasDivergentReplyTo: boolean;
    matchedUrgency: string[];
  };
  assessment: {
    threatLevel: ThreatLevel;
    threatScore: number;
    threatName: string;
    summary: string;
    phishingType: string;
    deceptionTactics: string[];
    extractedIocs: string[];
    spfDkimStatus: {
      spfVerdict: string;
      dkimVerdict: string;
      dmarcVerdict: string;
    };
    remediation: string[];
  };
  alertDispatched: AlertRecord | null;
}

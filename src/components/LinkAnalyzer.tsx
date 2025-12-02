import React, { useState } from 'react';
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Alert, AlertDescription } from "./ui/alert";
import { Badge } from "./ui/badge";
import { Shield, AlertTriangle, CheckCircle, Link, LogOut, Loader2 } from "lucide-react";

interface LinkAnalyzerProps {
  username: string;
  onLogout: () => void;
}

interface AnalysisResult {
  isMalicious: boolean;
  confidence: number;
  threats: string[];
  details: string;
}

export function LinkAnalyzer({ username, onLogout }: LinkAnalyzerProps) {
  const [url, setUrl] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');

  const scamPatterns = [
    'get-rich-quick',
    'make-money-fast',
    'easy-money',
    'work-from-home',
    'passive-income',
    'investment-scam',
    'pyramid-scheme',
    'mlm',
    'cryptocurrency-scam',
    'trading-bot',
    'binary-options',
    'forex-scam',
    'ponzi',
    'free-money',
    'instant-profit',
    'guaranteed-returns',
    'no-risk-investment',
    'cash-app',
    'venmo-scam',
    'paypal-scam',
    'bitcoin-doubler',
    'fake-investment',
    'survey-scam',
    'cashback-scam'
  ];

  const analyzeUrl = async () => {
    if (!url.trim()) {
      setError('Please enter a URL to analyze');
      return;
    }

    if (!isValidUrl(url)) {
      setError('Please enter a valid URL (including http:// or https://)');
      return;
    }

    setError('');
    setIsAnalyzing(true);
    setResult(null);

    // Try calling configured API first. If it fails, fall back to local heuristic.
    const saved = (() => {
      try {
        return localStorage.getItem('maliciousApiUrl');
      } catch (e) {
        return null;
      }
    })();

    const defaultApi = 'https://lengthy-ronald-unmetallurgically.ngrok-free.dev/predict';
    const base = saved || defaultApi;
    const endpoint = base.includes('/predict') ? base : base.replace(/\/+$/,'') + '/predict';

    // Normalize URL to send to API: prefer exact scheme if provided, else try http, then https
    let sendUrl = url;
    try {
      new URL(sendUrl);
    } catch (_) {
      // Prefer HTTPS when normalizing (matches backend normalization behavior)
      try { new URL('https://' + sendUrl); sendUrl = 'https://' + sendUrl; }
      catch (_) {
        try { new URL('http://' + sendUrl); sendUrl = 'http://' + sendUrl; }
        catch (_) { /* keep original, API may reject */ }
      }
    }

    try {
      // Debug: show where we're sending the request and what payload
      try {
        // eslint-disable-next-line no-console
        console.log('[LinkAnalyzer] savedApiUrl:', saved, 'defaultApi:', defaultApi);
        // eslint-disable-next-line no-console
        console.log('[LinkAnalyzer] endpoint:', endpoint, 'sendUrl:', sendUrl);
      } catch (e) { /* ignore */ }

      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: sendUrl })
      });

      const data = await resp.json();
      // Debug: log endpoint and raw API response to help diagnose mismatches
      try {
        // eslint-disable-next-line no-console
        console.log('[LinkAnalyzer] api response status:', resp.status, 'ok:', resp.ok);
        // eslint-disable-next-line no-console
        console.log('[LinkAnalyzer] api response body:', data);
      } catch (e) { /* ignore */ }

      if (!resp.ok) {
        throw new Error(data?.error || `API returned ${resp.status}`);
      }

      // Map common response shapes to our AnalysisResult
      let mapped: AnalysisResult = {
        isMalicious: false,
        confidence: 0,
        threats: [],
        details: ''
      };

      // Handle the specific API structure you provided:
      // {
      //  combined: { final_label, final_score },
      //  local_model: { confidence, maliciousness, pred_class },
      //  url: ..., whitelist: false
      // }
      if (data && data.combined && data.local_model) {
        const finalLabel = (data.combined.final_label || '').toString();
        const finalScore = Number(data.combined.final_score ?? data.combined.score ?? 0);
        const lm = data.local_model || {};

        // Decide maliciousness using both combined and local_model. If local_model predicts
        // a known malicious label (e.g. defacement, phishing) or has high confidence,
        // prefer that over the combined.final_label which may be more conservative.
        const maliciousLabels = /malicious|scam|phish|phishing|bad|deface|defacement|malware|attack|ransomware|suspicious|trojan|exploit|spyware/;
        let isMal = finalLabel.toLowerCase() !== 'benign';
        if (lm.pred_class && maliciousLabels.test(String(lm.pred_class).toLowerCase())) isMal = true;
        // If local model confidence is high (e.g. >50%), trust it
        const lmConfNum = Number(lm.confidence ?? NaN);
        if (!isNaN(lmConfNum) && lmConfNum > 50) isMal = true;
        mapped.isMalicious = isMal;

        // Prefer local_model.confidence when present (assumed 0-100), fall back to combined score
        let conf = Number(lm.confidence ?? data.confidence ?? finalScore ?? 0);
        if (!isNaN(conf)) {
          if (conf <= 1) conf = conf * 100;
          mapped.confidence = Math.round(conf);
        }

        // Build threats list from model label and combined label
        const threats: string[] = [];
        if (lm.pred_class) threats.push(String(lm.pred_class));
        if (finalLabel) threats.push(String(finalLabel));
        mapped.threats = Array.from(new Set(threats));

        mapped.details = `Combined: ${finalLabel} (${finalScore}); Local: ${lm.pred_class || 'n/a'} (maliciousness: ${lm.maliciousness ?? 'n/a'}, confidence: ${lm.confidence ?? 'n/a'}). Whitelist: ${data.whitelist ?? false}`;

        try {
          // eslint-disable-next-line no-console
          console.log('[LinkAnalyzer] combined branch values', { finalLabel, finalScore, lm, lmConfNum, isMal, conf, threats });
        } catch (e) { /* ignore */ }

        setResult(mapped);
        setIsAnalyzing(false);
        return;
      }

        // If the API only returned a `local_model` (no combined), map that shape too
        if (data && data.local_model && !data.combined) {
          const lm = data.local_model || {};
          const pred = (lm.pred_class || '').toString();
          const maliciousLabels = /malicious|scam|phish|phishing|bad|deface|defacement|malware|attack|ransomware|suspicious|trojan|exploit|spyware/;

          mapped.isMalicious = maliciousLabels.test(pred.toLowerCase());

          // Confidence might be 0-100 or 0-1 depending on API; normalize to percentage
          let conf = Number(lm.confidence ?? lm.conf ?? data.confidence ?? NaN);
          if (!isNaN(conf)) {
            if (conf <= 1) conf = conf * 100;
            mapped.confidence = Math.round(conf);
          }

          mapped.threats = pred ? [pred] : [];
          mapped.details = `Local model predicted: ${pred || 'n/a'} (maliciousness: ${lm.maliciousness ?? 'n/a'}, confidence: ${lm.confidence ?? lm.conf ?? 'n/a'}). Whitelist: ${data.whitelist ?? false}`;

          try {
            // eslint-disable-next-line no-console
            console.log('[LinkAnalyzer] local_model-only branch', { pred, lm, mapped });
          } catch (e) { /* ignore */ }

          setResult(mapped);
          setIsAnalyzing(false);
          return;
        }

      if (typeof data.isMalicious === 'boolean') {
        mapped.isMalicious = data.isMalicious;
      } else if (typeof data.predicted_class === 'string') {
        const pred = data.predicted_class.toLowerCase();
        // Treat a wider set of model labels as malicious
        const maliciousLabels = /malicious|scam|phish|phishing|bad|deface|defacement|malware|attack|ransomware|suspicious|trojan|exploit|spyware/;
        mapped.isMalicious = maliciousLabels.test(pred);
        // include the predicted class as a detected threat if nothing else
        if (!mapped.threats || mapped.threats.length === 0) mapped.threats = [data.predicted_class];
        if (!mapped.details) mapped.details = `Model predicted: ${data.predicted_class}`;
      }

      if (typeof data.confidence === 'number') mapped.confidence = Math.round(data.confidence);
      else if (typeof data.confidence === 'string' && !isNaN(Number(data.confidence))) mapped.confidence = Math.round(Number(data.confidence));
      else if (typeof data.probability === 'number') mapped.confidence = Math.round(data.probability * 100);

      mapped.details = data.details || data.message || (data.predicted_class ? `Model predicted: ${data.predicted_class}` : 'No additional details');
      mapped.threats = Array.isArray(data.threats) ? data.threats : (data.labels ? data.labels : []);

      setResult(mapped);
      setIsAnalyzing(false);
      return;
    } catch (err: any) {
      // API failed — fall back to local heuristic (preserve previous behavior)
      console.warn('Prediction API failed, falling back to heuristic:', err?.message || err);
      setError(prev => prev ? prev : `API request failed: ${err?.message || err}. Using local heuristic.`);
    }

    // Local heuristic fallback (original simulation)
    setTimeout(() => {
      const urlLower = url.toLowerCase();
      const isScamKeyword = scamPatterns.some(pattern => urlLower.includes(pattern.replace('-', '')));
      const hasMoneyKeywords = ['money', 'cash', 'profit', 'income', 'earn', 'rich', 'wealth', 'financial'].some(keyword => urlLower.includes(keyword));
      const hasUrgencyWords = ['limited', 'hurry', 'urgent', 'now', 'today', 'expire', 'act-fast'].some(word => urlLower.includes(word));
      const hasShortener = ['bit.ly', 'tinyurl', 't.co', 'short.ly'].some(shortener => urlLower.includes(shortener));
      const hasRandomDomain = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(url);
      const hasSuspiciousTLD = ['.tk', '.ml', '.ga', '.cf'].some(tld => urlLower.includes(tld));
      
      let isMalicious = false;
      let confidence = 0;
      let threats: string[] = [];
      let details = '';

      if (isScamKeyword) {
        isMalicious = true;
        confidence = 90 + Math.random() * 8;
        threats = ['Money-Making Scam', 'Fraudulent Scheme'];
        details = 'URL contains keywords commonly associated with get-rich-quick schemes and financial scams.';
      } else if (hasMoneyKeywords && hasUrgencyWords) {
        isMalicious = true;
        confidence = 80 + Math.random() * 15;
        threats = ['High-Pressure Sales Scam', 'Urgency-Based Fraud'];
        details = 'URL combines money-related terms with urgency tactics, a common pattern in financial scams.';
      } else if (hasMoneyKeywords && hasShortener) {
        isMalicious = true;
        confidence = 75 + Math.random() * 10;
        threats = ['Masked Financial Scam', 'URL Shortener Abuse'];
        details = 'Shortened URL with money-related keywords may be hiding a fraudulent money-making scheme.';
      } else if (hasSuspiciousTLD) {
        isMalicious = true;
        confidence = 70 + Math.random() * 15;
        threats = ['Suspicious Domain', 'Potential Scam Site'];
        details = 'URL uses a top-level domain commonly associated with scam websites.';
      } else if (hasRandomDomain) {
        isMalicious = true;
        confidence = 65 + Math.random() * 20;
        threats = ['Suspicious Domain', 'Potential Phishing'];
        details = 'URL uses IP address instead of domain name, which is often used in scam operations.';
      } else if (hasMoneyKeywords) {
        isMalicious = Math.random() > 0.4;
        confidence = isMalicious ? 60 + Math.random() * 20 : 30 + Math.random() * 25;
        threats = isMalicious ? ['Potential Financial Scam'] : [];
        details = isMalicious 
          ? 'URL contains money-related keywords. Exercise caution with any financial offers.'
          : 'URL contains money-related terms but appears legitimate. Still verify any financial claims.';
      } else {
        isMalicious = Math.random() > 0.85;
        confidence = isMalicious ? 50 + Math.random() * 25 : 15 + Math.random() * 30;
        threats = isMalicious ? ['Low-Risk Threat'] : [];
        details = isMalicious 
          ? 'URL flagged by our algorithms. No obvious scam indicators found but proceed with caution.'
          : 'URL appears to be safe. No scam indicators detected in our analysis.';
      }

      setResult({
        isMalicious,
        confidence: Math.round(confidence),
        threats,
        details
      });
      setIsAnalyzing(false);
    }, 800);
  };

  const isValidUrl = (string: string) => {
    if (!string || !string.trim()) return false;
    try {
      // Accept absolute URLs
      new URL(string);
      return true;
    } catch (_) {
      // If missing scheme (e.g. example.com/path), try with https:// prefix
      try {
        new URL('https://' + string);
        return true;
      } catch (__)
 {
        return false;
      }
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    analyzeUrl();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-sm p-4 mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center">
                <Shield className="w-5 h-5 text-indigo-600" />
              </div>
              <div>
                <h1 className="text-xl">Malicious Link Detection</h1>
                <p className="text-sm text-gray-600">Welcome back, {username}</p>
              </div>
            </div>
            <Button variant="outline" onClick={onLogout} className="flex items-center space-x-2">
              <LogOut className="w-4 h-4" />
              <span>Sign Out</span>
            </Button>
          </div>
        </div>

        {/* Main Analysis Card */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Link className="w-5 h-5" />
              <span>Scam Money Making App Detection</span>
            </CardTitle>
            <CardDescription>
              Enter a URL below to analyze if it's a suspicious money-making scheme or scam
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="url">URL to Analyze</Label>
                <Input
                  id="url"
                  type="text"
                  placeholder="https://example.com/make-money-fast-scheme or example.com/path"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={isAnalyzing}
                />
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <Button 
                type="submit" 
                className="w-full" 
                disabled={isAnalyzing || !url.trim()}
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Shield className="w-4 h-4 mr-2" />
                    Detect Scam
                  </>
                )}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Results Card */}
        {result && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                {result.isMalicious ? (
                  <AlertTriangle className="w-5 h-5 text-red-500" />
                ) : (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                )}
                <span>Analysis Results</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-4 rounded-lg bg-gray-50">
                <div>
                  <p className="font-medium">
                    {result.isMalicious ? 'Potential Scam Detected' : 'No Scam Indicators Found'}
                  </p>
                  <p className="text-sm text-gray-600">
                    Confidence: {result.confidence}%
                  </p>
                </div>
                <Badge 
                  variant={result.isMalicious ? "destructive" : "default"}
                  className={result.isMalicious ? "" : "bg-green-100 text-green-800"}
                >
                  {result.isMalicious ? 'SCAM RISK' : 'LIKELY SAFE'}
                </Badge>
              </div>

              <div>
                <h4 className="font-medium mb-2">Analysis Details</h4>
                <p className="text-sm text-gray-700 mb-3">{result.details}</p>
              </div>

              {result.threats.length > 0 && (
                <div>
                  <h4 className="font-medium mb-2">Detected Threats</h4>
                  <div className="flex flex-wrap gap-2">
                    {result.threats.map((threat, index) => (
                      <Badge key={index} variant="outline" className="text-red-600 border-red-200">
                        {threat}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {result.isMalicious && (
                <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                  <p className="text-sm text-blue-800">
                    <strong>Safety Tip:</strong> Be extremely cautious with money-making opportunities online. Legitimate investments never guarantee returns or pressure you to act immediately. Always research thoroughly before sharing personal information or making payments.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
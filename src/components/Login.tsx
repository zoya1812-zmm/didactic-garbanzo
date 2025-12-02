import React, { useState } from 'react';
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Alert, AlertDescription } from "./ui/alert";
import { Shield, Lock, User } from "lucide-react";

interface LoginProps {
  onLogin: (username: string) => void;
}

export function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [apiUrl, setApiUrl] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  React.useEffect(() => {
    try {
      const saved = localStorage.getItem('maliciousApiUrl');
      if (saved) setApiUrl(saved);
    } catch (e) {
      // ignore
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    // Simulate API call
    setTimeout(() => {
      if (username.trim() && password.trim()) {
        if (password === 'password' || password === 'admin' || password === '123456') {
          onLogin(username);
        } else {
          setError('Invalid username or password. Try using "password", "admin", or "123456"');
        }
      } else {
        setError('Please enter both username and password');
      }
      setIsLoading(false);
    }, 1000);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center space-y-4">
          <div className="mx-auto w-16 h-16 bg-indigo-100 rounded-full flex items-center justify-center">
            <Shield className="w-8 h-8 text-indigo-600" />
          </div>
          <div>
            <CardTitle className="text-2xl">Malicious Link Detection</CardTitle>
            <CardDescription>
              Sign in to detect and analyze suspicious money-making schemes
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-600">
                <span className="font-medium">API:</span>{' '}
                <span className="italic">{apiUrl ?? 'default (preconfigured)'} </span>
              </div>
              <div>
                <Button
                  variant="ghost"
                  onClick={() => {
                    const input = window.prompt('Enter prediction API base URL or full endpoint (e.g. https://example.com or https://example.com/predict):', apiUrl ?? '');
                    if (!input) return;
                    try {
                      // validate URL
                      const trimmed = input.trim();
                      new URL(trimmed);
                      localStorage.setItem('maliciousApiUrl', trimmed);
                      setApiUrl(trimmed);
                      alert('API URL saved. It will be used for predictions after login.');
                    } catch (err) {
                      alert('Invalid URL. Please enter a valid absolute URL (including https://).');
                    }
                  }}
                >
                  Update API
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <Input
                  id="username"
                  type="text"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="pl-10"
                  disabled={isLoading}
                />
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10"
                  disabled={isLoading}
                />
              </div>
            </div>

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button 
              type="submit" 
              className="w-full" 
              disabled={isLoading}
            >
              {isLoading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
          
          <div className="mt-4 text-center">
            <p className="text-sm text-gray-600">
              Demo credentials: Use any username with password "password", "admin", or "123456"
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
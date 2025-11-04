import React, { useState } from 'react';
import { Login } from './components/Login';
import { LinkAnalyzer } from './components/LinkAnalyzer';

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [username, setUsername] = useState('');

  const handleLogin = (user: string) => {
    setUsername(user);
    setIsLoggedIn(true);
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setUsername('');
  };

  return (
    <div className="min-h-screen">
      {isLoggedIn ? (
        <LinkAnalyzer username={username} onLogout={handleLogout} />
      ) : (
        <Login onLogin={handleLogin} />
      )}
    </div>
  );
}
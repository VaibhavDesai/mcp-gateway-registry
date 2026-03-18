import React, { useEffect, useState, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { handleOAuthCallback } from '../services/webexAuth';

const OAuthCallback: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user, loading } = useAuth();
  const processingRef = useRef(false);
  const [callbackError, setCallbackError] = useState<string | null>(null);
  const [debugSteps, setDebugSteps] = useState<string[]>(['Callback page loaded']);

  const addStep = (step: string) => {
    console.log('[OAuthCallback]', step);
    setDebugSteps(prev => [...prev, step]);
  };

  useEffect(() => {
    const processCallback = async () => {
      // Check if there's an error parameter from the auth server
      const error = searchParams.get('error');
      const errorDescription = searchParams.get('error_description');
      const errorDetails = searchParams.get('details');

      if (error) {
        const errorMessage = errorDescription || errorDetails || error;
        addStep(`Provider error: ${errorMessage}`);
        navigate(`/login?error=${encodeURIComponent(errorMessage)}`, { replace: true });
        return;
      }

      // Check for authorization code (Webex PKCE flow)
      const code = searchParams.get('code');
      const state = searchParams.get('state');

      addStep(`code=${code ? 'present' : 'null'}, state=${state ? 'present' : 'null'}, loading=${loading}, user=${user ? 'present' : 'null'}`);

      if (code && state) {
        // Use ref to prevent double execution (state re-renders cause useEffect to re-run)
        if (processingRef.current) {
          addStep('Already processing, skipping duplicate');
          return;
        }
        processingRef.current = true;

        try {
          // Clear stale localStorage tokens from previous login attempts
          // (prevents AuthContext from racing with an old expired token)
          // NOTE: Only clear localStorage — do NOT touch sessionStorage (PKCE params needed for exchange)
          localStorage.removeItem('webex_access_token');
          localStorage.removeItem('webex_refresh_token');
          localStorage.removeItem('webex_token_expires_at');
          localStorage.removeItem('webex_user_profile');
          addStep('Cleared stale tokens from localStorage');

          // Log sessionStorage state for debugging
          const storedState = sessionStorage.getItem('webex_oauth_state');
          const storedVerifier = sessionStorage.getItem('webex_pkce_code_verifier');
          const storedRedirect = sessionStorage.getItem('webex_redirect_uri');
          addStep(`sessionStorage: state=${storedState ? 'present' : 'MISSING'}, verifier=${storedVerifier ? 'present' : 'MISSING'}, redirect=${storedRedirect || 'MISSING'}`);
          addStep(`URL state matches stored: ${state === storedState}`);

          addStep('Starting token exchange...');
          await handleOAuthCallback(code, state);
          addStep('Token exchange SUCCESS! Redirecting to dashboard...');
          // Force a full page reload to re-initialize AuthContext with the new token
          window.location.href = window.location.origin + (document.querySelector('base')?.getAttribute('href') || '/');
        } catch (err: any) {
          addStep(`Token exchange FAILED: ${err.message}`);
          // Do NOT reset processingRef — prevent re-entry loop from effect re-runs
          setCallbackError(err.message || 'Authentication failed');
        }
        return;
      }

      // No code param — fall back to cookie-based flow (existing behavior)
      if (!loading) {
        if (user) {
          addStep('Cookie auth: user found, redirecting to dashboard');
          navigate('/', { replace: true });
        } else {
          addStep('No code param and no user session — redirecting to login');
          navigate('/login?error=oauth2_session_invalid', { replace: true });
        }
      }
    };

    processCallback();
  }, [user, loading, navigate, searchParams]);

  // Show debug info with steps
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col justify-center items-center p-8">
      {callbackError ? (
        <div className="max-w-lg w-full">
          <div className="text-red-500 text-xl mb-4 text-center">Authentication Error</div>
          <p className="text-gray-600 dark:text-gray-400 text-center mb-4">{callbackError}</p>
          <button
            onClick={() => navigate('/login', { replace: true })}
            className="w-full px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700"
          >
            Back to Login
          </button>
        </div>
      ) : (
        <div className="max-w-lg w-full text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-600 mb-4 mx-auto"></div>
          <p className="text-gray-600 dark:text-gray-400 mb-4">Processing authentication...</p>
        </div>
      )}
      {/* Debug steps - visible to help diagnose */}
      <div className="mt-8 max-w-lg w-full bg-gray-100 dark:bg-gray-800 rounded p-4 text-xs font-mono">
        <p className="text-gray-500 dark:text-gray-400 mb-2 font-bold">Debug Log:</p>
        {debugSteps.map((step, i) => (
          <p key={i} className="text-gray-600 dark:text-gray-300">{i + 1}. {step}</p>
        ))}
      </div>
    </div>
  );
};

export default OAuthCallback; 
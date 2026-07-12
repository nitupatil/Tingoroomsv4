/*
 * TingoRooms shared authentication guard
 * Add after the page's Supabase client is created and expose it as window.tingoDb.
 * This validates the real Supabase Auth session, refreshes the public.users profile,
 * listens for account/session changes, and provides requireAuth() for protected actions.
 */
(function () {
  'use strict';

  if (window.TingoAuthGuard) return;

  const STORAGE_KEY = 'user';
  const AUTH_FUNCTION_NAME = window.TINGO_AUTH_FUNCTION_NAME || 'tingo-auth';
  const ACTIVE_CHECK_MS = 30000;
  const HIDDEN_CHECK_MS = 120000;

  const state = {
    started: false,
    ready: false,
    valid: false,
    user: null,
    session: null,
    reason: 'initialising',
    checking: null,
    realtimeChannel: null,
    realtimeUserId: null,
    pollTimer: null,
    authSubscription: null,
    lastValidatedAt: 0,
    stopped: false
  };

  function getDb() {
    return window.tingoDb || null;
  }

  function readStoredUser() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  function sanitiseUser(user) {
    const safe = { ...(user || {}) };
    delete safe.password;
    delete safe.otp;
    delete safe.otp_expiry;
    return safe;
  }

  function saveStoredUser(user) {
    if (!user) {
      localStorage.removeItem(STORAGE_KEY);
      return;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(sanitiseUser(user)));
  }

  function accountProblem(user) {
    if (!user) return 'Account profile was not found.';
    if (user.is_active === false) return 'Your account is inactive.';
    if (user.login_enabled === false) return 'Login is disabled for this account.';
    const health = String(user.account_health || 'healthy').toLowerCase();
    if (health !== 'healthy') {
      return user.block_reason || `Your account is ${health}.`;
    }
    if (user.auth_sync_status && String(user.auth_sync_status).toLowerCase() === 'error') {
      return user.auth_sync_error || 'Your login account is not linked correctly.';
    }
    return '';
  }

  function sessionProblem(localUser, freshUser) {
    const localToken = String(localUser?.active_session_token || '');
    const serverToken = String(freshUser?.active_session_token || '');

    if (serverToken && !localToken) return 'Your login session changed. Please sign in again.';
    if (serverToken && localToken && serverToken !== localToken) {
      return 'This account was logged in on another device. This device has been signed out.';
    }
    return '';
  }

  function decodeJwtPayload(token) {
    try {
      const part = String(token || '').split('.')[1];
      if (!part) return {};
      const normalized = part.replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
      return JSON.parse(decodeURIComponent(Array.from(atob(padded), c =>
        '%' + c.charCodeAt(0).toString(16).padStart(2, '0')
      ).join('')));
    } catch (_) {
      return {};
    }
  }

  function latestAuthSessionProblem(session, freshUser) {
    const activeSessionId = String(freshUser?.active_auth_session_id || '');
    if (!activeSessionId) return '';
    const claims = decodeJwtPayload(session?.access_token);
    const currentSessionId = String(claims?.session_id || '');
    if (!currentSessionId || currentSessionId !== activeSessionId) {
      return 'A newer login session is active on another device. This session cannot modify backend data.';
    }
    return '';
  }

  function dispatchState(extra = {}) {
    const detail = {
      ready: state.ready,
      valid: state.valid,
      user: state.user,
      session: state.session,
      reason: state.reason,
      lastValidatedAt: state.lastValidatedAt,
      ...extra
    };
    document.dispatchEvent(new CustomEvent('tingo:auth-state', { detail }));
    window.dispatchEvent(new CustomEvent('tingo:auth-state', { detail }));
  }

  function clearPoll() {
    if (state.pollTimer) {
      clearTimeout(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function schedulePoll() {
    clearPoll();
    if (state.stopped || !state.valid) return;
    const delay = document.hidden ? HIDDEN_CHECK_MS : ACTIVE_CHECK_MS;
    state.pollTimer = setTimeout(() => {
      validate({ reason: 'fallback-poll', silent: true, force: true });
    }, delay);
  }

  function removeRealtimeChannel() {
    const db = getDb();
    if (state.realtimeChannel && db) {
      try { db.removeChannel(state.realtimeChannel); } catch (_) {}
    }
    state.realtimeChannel = null;
    state.realtimeUserId = null;
  }

  function scheduleValidation(reason, delay = 80) {
    clearTimeout(window.__tingoAuthGuardValidationTimer);
    window.__tingoAuthGuardValidationTimer = setTimeout(() => {
      validate({ reason, silent: true, force: true });
    }, delay);
  }

  function subscribeToUser(user) {
    const db = getDb();
    if (!db || !user?.id) return;
    if (state.realtimeChannel && state.realtimeUserId === String(user.id)) return;

    removeRealtimeChannel();
    state.realtimeUserId = String(user.id);
    state.realtimeChannel = db
      .channel(`tingo-auth-user-${user.id}`)
      .on('postgres_changes', {
        event: 'UPDATE',
        schema: 'public',
        table: 'users',
        filter: `id=eq.${user.id}`
      }, () => scheduleValidation('account-updated', 30))
      .on('postgres_changes', {
        event: 'DELETE',
        schema: 'public',
        table: 'users',
        filter: `id=eq.${user.id}`
      }, () => invalidate('Account was removed.', { signOut: true }))
      .subscribe((status) => {
        if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
          // Polling remains active when Realtime is unavailable or the table is not published.
          schedulePoll();
        }
      });
  }

  async function fetchProfile(db, session) {
    const { data, error } = await db.functions.invoke(AUTH_FUNCTION_NAME, {
      body: { action: 'get_profile' },
      headers: { Authorization: `Bearer ${session.access_token}` }
    });

    if (error) throw error;
    if (!data?.ok || !data.user) {
      const err = new Error(data?.message || 'Unable to verify the current account.');
      err.code = 'PROFILE_INVALID';
      throw err;
    }
    return data.user;
  }

  async function invalidate(reason, options = {}) {
    const db = getDb();
    state.ready = true;
    state.valid = false;
    state.user = null;
    state.session = null;
    state.reason = reason || 'signed-out';
    state.lastValidatedAt = Date.now();
    clearPoll();
    removeRealtimeChannel();
    saveStoredUser(null);

    if (options.signOut !== false && db) {
      try { await db.auth.signOut({ scope: 'local' }); } catch (_) {}
    }

    dispatchState({ invalidated: true });
    return { valid: false, user: null, reason: state.reason };
  }

  async function validate(options = {}) {
    const db = getDb();
    const force = options.force === true;
    const reason = options.reason || 'manual';

    if (!db) {
      state.ready = true;
      state.valid = false;
      state.reason = 'Supabase client is unavailable.';
      dispatchState();
      return { valid: false, user: null, reason: state.reason };
    }

    if (!force && state.valid && Date.now() - state.lastValidatedAt < 5000) {
      return { valid: true, user: state.user, session: state.session, reason: state.reason };
    }

    if (state.checking) return state.checking;

    state.checking = (async () => {
      try {
        const localUser = readStoredUser();
        const { data, error } = await db.auth.getSession();
        if (error) throw error;

        const session = data?.session || null;
        if (!session?.access_token || !session?.user?.id) {
          return await invalidate('Your login session has expired.', { signOut: false });
        }

        const freshUser = await fetchProfile(db, session);
        const blocked = accountProblem(freshUser);
        if (blocked) return await invalidate(blocked, { signOut: true });

        if (freshUser.auth_user_id && String(freshUser.auth_user_id) !== String(session.user.id)) {
          return await invalidate('This profile does not belong to the active login session.', { signOut: true });
        }

        const changedSession = sessionProblem(localUser, freshUser);
        if (changedSession) return await invalidate(changedSession, { signOut: true });

        const latestSessionProblem = latestAuthSessionProblem(session, freshUser);
        if (latestSessionProblem) return await invalidate(latestSessionProblem, { signOut: true });

        const merged = sanitiseUser({ ...(localUser || {}), ...freshUser });
        saveStoredUser(merged);

        state.ready = true;
        state.valid = true;
        state.user = merged;
        state.session = session;
        state.reason = reason;
        state.lastValidatedAt = Date.now();
        subscribeToUser(merged);
        schedulePoll();
        dispatchState({ refreshed: true });

        return { valid: true, user: merged, session, reason };
      } catch (error) {
        console.warn('Tingo auth validation failed:', error);
        const message = error?.message || 'Unable to verify your login session.';

        // A temporary network failure must not destroy a known-good local session immediately.
        if (!navigator.onLine && state.valid && state.user) {
          state.reason = 'offline';
          schedulePoll();
          dispatchState({ offline: true, error: message });
          return { valid: true, user: state.user, session: state.session, reason: 'offline' };
        }

        return await invalidate(message, { signOut: true });
      } finally {
        state.checking = null;
      }
    })();

    return state.checking;
  }

  async function requireAuth(options = {}) {
    const result = await validate({ reason: options.reason || 'protected-action', force: true });
    if (result.valid) return result.user;

    if (options.redirect !== false) {
      const target = typeof options.redirect === 'string' ? options.redirect : 'user.html';
      const redirectBack = options.redirectBack || (location.pathname.split('/').pop() + location.search);
      const url = new URL(target, location.href);
      if (redirectBack) url.searchParams.set('redirect', redirectBack);
      location.href = url.href;
    }
    return null;
  }

  function bindLifecycle() {
    const db = getDb();
    if (!db) return;

    const authResult = db.auth.onAuthStateChange((event, session) => {
      if (event === 'SIGNED_OUT' || event === 'USER_DELETED') {
        invalidate('You have been signed out.', { signOut: false });
        return;
      }
      if (session && ['INITIAL_SESSION', 'SIGNED_IN', 'TOKEN_REFRESHED', 'PASSWORD_RECOVERY', 'USER_UPDATED'].includes(event)) {
        scheduleValidation(`auth-${String(event).toLowerCase()}`, 0);
      }
    });
    state.authSubscription = authResult?.data?.subscription || null;

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) scheduleValidation('page-visible', 0);
      else schedulePoll();
    }, { passive: true });

    window.addEventListener('focus', () => scheduleValidation('window-focus', 0), { passive: true });
    window.addEventListener('online', () => scheduleValidation('online', 0), { passive: true });
    window.addEventListener('storage', (event) => {
      if (event.key === STORAGE_KEY) scheduleValidation('cross-tab-user-change', 0);
    }, { passive: true });

    window.addEventListener('pagehide', () => clearPoll(), { passive: true });
  }

  function start() {
    if (state.started) return;
    state.started = true;
    state.stopped = false;
    bindLifecycle();
    validate({ reason: 'startup', silent: true, force: true });
  }

  function stop() {
    state.stopped = true;
    clearPoll();
    removeRealtimeChannel();
    try { state.authSubscription?.unsubscribe(); } catch (_) {}
    state.authSubscription = null;
  }

  window.TingoAuthGuard = {
    start,
    stop,
    validate,
    requireAuth,
    invalidate,
    getUser: () => state.user || readStoredUser(),
    getSession: () => state.session,
    isValid: () => state.valid,
    isReady: () => state.ready
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
  } else {
    start();
  }
})();

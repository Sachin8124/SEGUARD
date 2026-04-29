/**
 * SE-GUARD Authentication Module
 * Handles login, register, logout, and session management
 */

const AUTH_API_BASE = '/api/auth';
const STORAGE_TOKEN_KEY = 'seguard_token';
const STORAGE_USER_KEY = 'seguard_user';
const STORAGE_ROLE_KEY = 'seguard_role';
const TOKEN_EXPIRY_HOURS = 24;
const REQUEST_TIMEOUT_MS = 8000;
const RETRY_ATTEMPTS = 2;
const RETRY_BASE_DELAY_MS = 200;
const LOGIN_REQUEST_TIMEOUT_MS = 8000;
const LOGIN_RETRY_ATTEMPTS = 2;
const LOGIN_RETRY_BASE_DELAY_MS = 150;

class SEGuardAuth {
  constructor() {
    this.token = this.getStoredToken();
    this.user = this.getStoredUser();
    this.isAuthenticated = this.token ? true : false;
    this.activeControllers = new Set();
    this.abortOnNavigation = this.abortOnNavigation.bind(this);
    window.addEventListener('pagehide', this.abortOnNavigation);
    this.initAutoRefresh();
  }

  abortOnNavigation() {
    this.activeControllers.forEach(controller => controller.abort('navigation'));
    this.activeControllers.clear();
  }

  async delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async fetchWithRetry(path, options = {}, requestOptions = {}) {
    const retryAttempts = requestOptions.retryAttempts ?? RETRY_ATTEMPTS;
    const retryBaseDelayMs = requestOptions.retryBaseDelayMs ?? RETRY_BASE_DELAY_MS;
    const timeoutMs = requestOptions.timeoutMs ?? REQUEST_TIMEOUT_MS;
    let lastError = new Error('Request failed');

    for (let attempt = 0; attempt < retryAttempts; attempt += 1) {
      const controller = new AbortController();
      this.activeControllers.add(controller);
      const timeoutId = setTimeout(() => controller.abort('timeout'), timeoutMs);

      try {
        const response = await fetch(path, {
          ...options,
          signal: controller.signal,
        });
        clearTimeout(timeoutId);
        this.activeControllers.delete(controller);

        if (response.status >= 500 && attempt < retryAttempts - 1) {
          await this.delay(retryBaseDelayMs * (2 ** attempt));
          continue;
        }

        return response;
      } catch (error) {
        clearTimeout(timeoutId);
        this.activeControllers.delete(controller);
        lastError = error;

        if (attempt < retryAttempts - 1) {
          await this.delay(retryBaseDelayMs * (2 ** attempt));
          continue;
        }
      }
    }

    if (lastError?.name === 'AbortError') {
      throw new Error('Request timed out. Please try again.');
    }

    throw lastError;
  }

  /**
   * Register new user
   */
  async register(email, password, firstName, lastName, role = 'client') {
    try {
      const response = await this.fetchWithRetry(`${AUTH_API_BASE}/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
          firstName,
          lastName,
          role
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Registration failed');
      }

      // Store token and user data
      this.storeToken(data.token);
      this.storeUser({
        email,
        firstName,
        lastName,
        role,
        roles: Array.isArray(data.roles) ? data.roles : [role],
        created_at: new Date().toISOString()
      });

      this.isAuthenticated = true;
      this.token = data.token;
      this.user = { email, firstName, lastName, role };

      console.log('[Auth] Registration successful:', email);
      return { success: true, data };
    } catch (error) {
      console.error('[Auth] Registration error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Login user
   */
  async login(email, password, role = null) {
    try {
      const response = await this.fetchWithRetry(`${AUTH_API_BASE}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password, role })
      }, {
        timeoutMs: LOGIN_REQUEST_TIMEOUT_MS,
        retryAttempts: LOGIN_RETRY_ATTEMPTS,
        retryBaseDelayMs: LOGIN_RETRY_BASE_DELAY_MS,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Login failed');
      }

      // Store token and user data
      this.storeToken(data.token);
      this.storeUser({
        email,
        firstName: data.name ? data.name.split(' ')[0] : '',
        lastName: data.name ? data.name.split(' ')[1] || '' : '',
        role: data.role,
        roles: Array.isArray(data.roles) ? data.roles : [data.role],
        last_login_at: new Date().toISOString()
      });

      this.isAuthenticated = true;
      this.token = data.token;
      this.user = data;

      console.log('[Auth] Login successful:', email);
      return { success: true, data };
    } catch (error) {
      console.error('[Auth] Login error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Logout user
   */
  async logout() {
    try {
      const token = this.getStoredToken();
      if (token) {
        await this.fetchWithRetry(`${AUTH_API_BASE}/logout`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          }
        });
      }

      this.clearStorage();
      this.isAuthenticated = false;
      this.token = null;
      this.user = null;

      console.log('[Auth] Logout successful');
      return { success: true };
    } catch (error) {
      console.error('[Auth] Logout error:', error);
      // Clear local storage anyway
      this.clearStorage();
      this.isAuthenticated = false;
      return { success: true };
    }
  }

  /**
   * Get user profile and role data
   */
  async getProfile() {
    try {
      const token = this.getStoredToken();
      if (!token) {
        throw new Error('No token found');
      }

      const response = await this.fetchWithRetry(`${AUTH_API_BASE}/profile`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Failed to fetch profile');
      }

      // Update user data if fresh
      if (data.user) {
        this.storeUser(data.user);
        this.user = data.user;
      }

      console.log('[Auth] Profile fetched:', data.user.email);
      return { success: true, data };
    } catch (error) {
      console.error('[Auth] Profile fetch error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Refresh token (extends validity by 24 hours)
   */
  async refreshToken() {
    try {
      const token = this.getStoredToken();
      if (!token) {
        throw new Error('No token found');
      }

      const response = await this.fetchWithRetry(`${AUTH_API_BASE}/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || 'Token refresh failed');
      }

      this.storeToken(data.token);
      this.token = data.token;

      console.log('[Auth] Token refreshed');
      return { success: true, data };
    } catch (error) {
      console.error('[Auth] Token refresh error:', error);
      // If refresh fails, clear authentication
      this.clearStorage();
      this.isAuthenticated = false;
      return { success: false, error: error.message };
    }
  }

  /**
   * Initialize automatic token refresh
   * Refreshes token 1 hour before expiry
   */
  initAutoRefresh() {
    // Check and refresh token every 30 minutes
    setInterval(() => {
      if (this.isAuthenticated && this.token) {
        this.refreshToken().catch(err => {
          console.error('[Auth] Auto-refresh failed:', err);
        });
      }
    }, 30 * 60 * 1000); // 30 minutes

    // Also refresh on page visibility change (user comes back to tab)
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && this.isAuthenticated && this.token) {
        this.refreshToken().catch(err => {
          console.error('[Auth] Visibility refresh failed:', err);
        });
      }
    });
  }

  /**
   * Store token in localStorage
   */
  storeToken(token) {
    try {
      const expiryTime = Date.now() + (TOKEN_EXPIRY_HOURS * 60 * 60 * 1000);
      localStorage.setItem(STORAGE_TOKEN_KEY, token);
      localStorage.setItem('se_guard_token', token);
      localStorage.setItem('token_expiry', expiryTime.toString());
    } catch (error) {
      console.error('[Auth] Failed to store token:', error);
    }
  }

  /**
   * Get stored token from localStorage
   */
  getStoredToken() {
    try {
      const token = localStorage.getItem(STORAGE_TOKEN_KEY);
      const expiry = localStorage.getItem('token_expiry');

      if (!token || !expiry) {
        return null;
      }

      // Check if token is expired
      if (Date.now() > parseInt(expiry)) {
        this.clearStorage();
        return null;
      }

      return token;
    } catch (error) {
      console.error('[Auth] Failed to get token:', error);
      return null;
    }
  }

  /**
   * Store user data in localStorage
   */
  storeUser(user) {
    try {
      localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(user));
      localStorage.setItem('se_guard_user', JSON.stringify(user));
      localStorage.setItem(STORAGE_ROLE_KEY, user.role);
    } catch (error) {
      console.error('[Auth] Failed to store user:', error);
    }
  }

  /**
   * Get stored user from localStorage
   */
  getStoredUser() {
    try {
      const user = localStorage.getItem(STORAGE_USER_KEY);
      return user ? JSON.parse(user) : null;
    } catch (error) {
      console.error('[Auth] Failed to get user:', error);
      return null;
    }
  }

  /**
   * Get stored role from localStorage
   */
  getStoredRole() {
    try {
      return localStorage.getItem(STORAGE_ROLE_KEY) || 'client';
    } catch (error) {
      return 'client';
    }
  }

  /**
   * Clear all stored authentication data
   */
  clearStorage() {
    try {
      localStorage.removeItem(STORAGE_TOKEN_KEY);
      localStorage.removeItem(STORAGE_USER_KEY);
      localStorage.removeItem(STORAGE_ROLE_KEY);
      localStorage.removeItem('se_guard_token');
      localStorage.removeItem('se_guard_user');
      localStorage.removeItem('token_expiry');
    } catch (error) {
      console.error('[Auth] Failed to clear storage:', error);
    }
  }

  /**
   * Check if user is authenticated
   */
  isLoggedIn() {
    return this.isAuthenticated && this.getStoredToken() !== null;
  }

  /**
   * Get authorization header for API calls
   */
  getAuthHeader() {
    const token = this.getStoredToken();
    return token ? { 'Authorization': `Bearer ${token}` } : {};
  }

  /**
   * Get current user info
   */
  getCurrentUser() {
    return this.getStoredUser();
  }

  /**
   * Get current user role
   */
  getCurrentRole() {
    return this.getStoredRole();
  }
}

// Export for use in other scripts
const seguardAuth = new SEGuardAuth();

// Optional: Auto-redirect if not authenticated
function redirectIfNotAuth(redirectTo = '/') {
  if (!seguardAuth.isLoggedIn()) {
    window.location.href = redirectTo;
  }
}

// Optional: Auto-redirect if already authenticated
function redirectIfAuth(redirectTo = '/dashboard') {
  if (seguardAuth.isLoggedIn()) {
    window.location.href = redirectTo;
  }
}

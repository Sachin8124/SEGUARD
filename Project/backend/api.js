/**
 * api.js  —  SE-GUARD Frontend ↔ Python ML Backend Bridge
 * =========================================================
 * Drop this file in the same folder as your HTML files.
 * It patches window.fetch calls and exposes helper functions
 * so the dashboard can call the Flask ML API transparently.
 *
 * Usage in HTML (already referenced in se-guard-dashboard.html):
 *   <script src="api.js"></script>
 *
 * The dashboard can then call:
 *   SGUARD.detectMessage(text)       → { verdict, flagged, type, action … }
 *   SGUARD.detectProfile(profileObj) → { verdict, risk_level, flags … }
 *   SGUARD.detectReview(text, rating)→ { verdict, fake_probability … }
 *   SGUARD.detectPayment(payObj)     → { verdict, risk_probability … }
 *   SGUARD.detectProduct(prodObj)    → { verdict, fake_probability … }
 *   SGUARD.detectBatch(batchObj)     → { results, overall_risk }
 *   SGUARD.login(email,pwd,role)     → { token, role, name }
 *   SGUARD.register(formObj)         → { token, role }
 */

(function (window) {
  "use strict";

  const BASE_URL = "http://127.0.0.1:5000/api";
  let _token = localStorage.getItem("sg_token") || null;

  // ── Core request helper ───────────────────────────────────────────────────
  async function _post(endpoint, body) {
    try {
      const res = await fetch(`${BASE_URL}${endpoint}`, {
        method : "POST",
        headers: {
          "Content-Type" : "application/json",
          ..._token ? { "Authorization": `Bearer ${_token}` } : {}
        },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || "API error");
      return data;
    } catch (err) {
      console.warn(`[SE-GUARD API] ${endpoint} failed:`, err.message);
      // Return a safe fallback so the UI doesn't crash if backend is down
      return { status: "offline", error: err.message };
    }
  }

  async function _get(endpoint) {
    try {
      const res  = await fetch(`${BASE_URL}${endpoint}`);
      return await res.json();
    } catch (err) {
      return { status: "offline", error: err.message };
    }
  }

  // ── Auth ──────────────────────────────────────────────────────────────────
  async function login(email, password, role) {
    const data = await _post("/auth/login", { email, password, role });
    if (data.token) {
      _token = data.token;
      localStorage.setItem("sg_token", _token);
      localStorage.setItem("sg_role",  data.role);
      localStorage.setItem("sg_name",  data.name || email);
    }
    return data;
  }

  async function register(formObj) {
    const data = await _post("/auth/register", formObj);
    if (data.token) {
      _token = data.token;
      localStorage.setItem("sg_token", _token);
      localStorage.setItem("sg_role",  data.role);
    }
    return data;
  }

  function logout() {
    _token = null;
    localStorage.removeItem("sg_token");
    localStorage.removeItem("sg_role");
    localStorage.removeItem("sg_name");
  }

  // ── Detection ─────────────────────────────────────────────────────────────
  async function detectMessage(text) {
    const res = await _post("/detect/message", { text });
    return res.detection || _fallbackMessage(text);
  }

  async function detectProfile(profileObj) {
    const res = await _post("/detect/profile", profileObj);
    return res.detection || { verdict: "UNKNOWN", risk_level: "LOW" };
  }

  async function detectReview(text, rating = 5) {
    const res = await _post("/detect/review", { text, rating });
    return res.detection || { verdict: "UNKNOWN", risk_level: "LOW" };
  }

  async function detectPayment(paymentObj) {
    const res = await _post("/detect/payment", paymentObj);
    return res.detection || { verdict: "NORMAL", risk_level: "LOW" };
  }

  async function detectProduct(productObj) {
    const res = await _post("/detect/product", productObj);
    return res.detection || { verdict: "GENUINE", risk_level: "LOW" };
  }

  async function detectBatch(batchObj) {
    const res = await _post("/detect/batch", batchObj);
    return res;
  }

  async function getStats() {
    return await _get("/stats");
  }

  async function healthCheck() {
    return await _get("/health");
  }

  // ── Client-side rule fallback (works even when backend is offline) ─────────
  const ABUSE_RE    = /\b(fuck|shit|bitch|bastard|cunt|asshole|idiot|moron|dick)\b/i;
  const THREAT_RE   = /\b(kill|murder|harm|destroy|i.ll find you|your family)\b/i;
  const PRESSURE_RE = /\b(pay (me )?(now|immediately|right now)|send money now|urgent payment)\b/i;

  function _fallbackMessage(text) {
    if (THREAT_RE.test(text))   return { verdict:"THREAT",   flagged:true, type:"THREAT",   action:"BLOCK_MESSAGE",  confidence:90, matched_keywords:[], offline:true };
    if (PRESSURE_RE.test(text)) return { verdict:"PRESSURE", flagged:true, type:"PRESSURE", action:"BLOCK_MESSAGE",  confidence:85, matched_keywords:[], offline:true };
    if (ABUSE_RE.test(text))    return { verdict:"ABUSIVE",  flagged:true, type:"ABUSIVE",  action:"FLAG_MESSAGE",   confidence:80, matched_keywords:[], offline:true };
    return { verdict:"CLEAN", flagged:false, type:null, action:"ALLOW", confidence:95, offline:true };
  }

  // ── Dashboard Integration Hooks ───────────────────────────────────────────
  /**
   * Call this from the message send handler in the dashboard.
   * Returns the detection result and shows a notification automatically.
   */
  async function onSendMessage(text, showNotificationFn) {
    const result = await detectMessage(text);
    if (result.flagged && typeof showNotificationFn === "function") {
      const icons = { THREAT:"🚨", ABUSIVE:"⚠️", PRESSURE:"💸" };
      showNotificationFn(
        `${icons[result.type] || "⚠️"} ${result.type} detected! (${result.confidence}% confidence)`,
        "warning"
      );
    }
    return result;
  }

  /**
   * Call this when a new product is submitted.
   * Automatically infers features from the product object.
   */
  async function onProductSubmit(product, avgCategoryPrice) {
    const avgPrice = avgCategoryPrice || product.price * 1.2 || 1000;
    const payload  = {
      price_vs_category_avg_ratio : product.price / avgPrice,
      description_length          : (product.info || "").length,
      image_count                 : product.image ? 1 : 0,
      seller_age_days             : 30,   // default; pass real value if available
      seller_rating               : 4.0,
      seller_total_sales          : 10,
      discount_pct                : product.cost > product.price
                                      ? ((product.cost - product.price) / product.cost) * 100
                                      : 0,
      has_contact_info_in_desc    : /(@|phone|call|whatsapp|telegram)/i.test(product.info||"") ? 1 : 0
    };
    return await detectProduct(payload);
  }

  /**
   * Call this on payment initiation.
   * hour_of_day and new_device are inferred automatically.
   */
  async function onPaymentInitiate(amount, extraFlags = {}) {
    const payload = {
      amount,
      hour_of_day              : new Date().getHours(),
      retries                  : extraFlags.retries || 0,
      new_device               : extraFlags.newDevice ? 1 : 0,
      vpn_flag                 : 0,
      amount_vs_history_ratio  : extraFlags.historyRatio || 1.0,
      time_since_last_txn_min  : extraFlags.minSinceLast || 300
    };
    return await detectPayment(payload);
  }

  /**
   * Call this when a review / testimonial is submitted.
   */
  async function onReviewSubmit(text, rating) {
    return await detectReview(text, rating);
  }

  // ── Expose public API ─────────────────────────────────────────────────────
  window.SGUARD = {
    // Auth
    login, register, logout,
    // Detectors
    detectMessage, detectProfile, detectReview, detectPayment,
    detectProduct, detectBatch,
    // Utility
    getStats, healthCheck,
    // Dashboard hooks
    onSendMessage, onProductSubmit, onPaymentInitiate, onReviewSubmit,
    // Token access
    getToken : () => _token,
    getRole  : () => localStorage.getItem("sg_role"),
    getName  : () => localStorage.getItem("sg_name"),
    isOnline : async () => {
      const h = await healthCheck();
      return h.status === "ok";
    }
  };

  console.log("[SE-GUARD] api.js loaded — ML backend bridge ready.");
  console.log("[SE-GUARD] Backend URL:", BASE_URL);
  console.log("[SE-GUARD] Type SGUARD.healthCheck() to test connectivity.");

})(window);

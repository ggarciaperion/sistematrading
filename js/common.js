// common.js
// Centralized client-side helpers:
// - Fetch a CSRF token and set it as default header for all jQuery AJAX calls
// - Expose helper to play notification audio and show simple notifications
// Include this file in base.html (it is referenced by the updated base.html provided).
(function(window, document, $){
  'use strict';
  window.QC = window.QC || {};

  // Fetch CSRF token once and set default header for jQuery AJAX
  function initCsrf() {
    try {
      $.get('/get_csrf_token').done(function(data){
        if (data && data.csrf_token) {
          $.ajaxSetup({
            headers: {
              'X-CSRFToken': data.csrf_token
            }
          });
          window.QC.csrfToken = data.csrf_token;
        }
      }).fail(function(){
        console.warn('Could not obtain CSRF token via /get_csrf_token');
      });
    } catch (e) {
      console.warn('initCsrf error', e);
    }
  }

  // Audio helper (attempt AudioContext, fallback to <audio>)
  function playNotificationSound() {
    try {
      if (!window._qcAudioCtx) {
        window._qcAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      var ctx = window._qcAudioCtx;
      if (ctx.state === 'suspended') {
        ctx.resume().catch(function(){});
      }
      var now = ctx.currentTime;
      var osc = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.value = 880;
      gain.gain.setValueAtTime(0.0001, now);
      gain.gain.exponentialRampToValueAtTime(0.18, now + 0.005);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.28);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.3);
      return;
    } catch (e) {
      // fallback
      if (!window._qcAudioEl) {
        window._qcAudioEl = new Audio();
        window._qcAudioEl.preload = 'auto';
        // no src included; if you add static/sounds/beep.ogg, set it here
      }
      try { window._qcAudioEl.play().catch(()=>{}); } catch(e2){}
    }
  }

  function showNotification(payload) {
    try {
      var container = document.getElementById('notificationContainer');
      if (!container) {
        container = document.createElement('div');
        container.id = 'notificationContainer';
        container.className = 'notification-container';
        document.body.appendChild(container);
      }
      var id = 'notif-' + Date.now() + '-' + Math.floor(Math.random()*1000);
      var tipo = payload && payload.tipo ? payload.tipo : 'nueva_operacion';
      var icon = tipo === 'nuevo_cliente' ? '👤' : '💼';
      var title = tipo === 'nuevo_cliente' ? 'Nuevo Cliente' : 'Nueva Operación';
      var msg = payload && payload.mensaje ? payload.mensaje : (payload && payload.cliente ? payload.cliente : '');
      var ts = payload && payload.timestamp ? payload.timestamp : new Date().toLocaleTimeString();

      var el = document.createElement('div');
      el.className = 'notification';
      el.id = id;
      el.innerHTML = '<div style="flex:0 0 34px; text-align:center;" class="notification-icon">' + icon + '</div>' +
        '<div style="flex:1 1 auto;"><div class="notification-title">' + title + '</div>' +
        '<div class="notification-message">' + msg + '</div>' +
        '<div class="notification-time">' + ts + '</div></div>' +
        '<button class="notification-close" aria-label="Cerrar">&times;</button>';
      container.insertBefore(el, container.firstChild);
      el.querySelector('.notification-close').addEventListener('click', function(){
        el.classList.add('hiding');
        setTimeout(function(){ if (el.parentNode) el.parentNode.removeChild(el); }, 240);
      });
      // play sound
      playNotificationSound();
      // auto remove
      setTimeout(function(){
        if (el && el.parentNode) {
          el.classList.add('hiding');
          setTimeout(function(){ if (el.parentNode) el.parentNode.removeChild(el); }, 240);
        }
      }, 8000);
    } catch (e) {
      console.error('showNotification error', e);
    }
  }

  // auto init on load
  $(function(){
    initCsrf();
    window.QC.playNotificationSound = playNotificationSound;
    window.QC.showNotification = showNotification;
  });

})(window, document, window.jQuery);
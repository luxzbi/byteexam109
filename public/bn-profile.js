/* Byte Workspace 공통 프로필 버튼
   모든 앱 우측 위에 같은 프로필을 띄우고, 누르면 통합 계정 설정으로 이동한다.
   각 앱의 기존 헤더/메뉴는 건드리지 않도록 독립 요소로 주입한다. */
(function () {
  'use strict';
  var SETTINGS = 'https://byteworkspace.vercel.app/account';
  var ACCOUNT = 'https://bytenode-account.vercel.app';

  function token() {
    try { return localStorage.getItem('bn_token') || sessionStorage.getItem('bn_token') || ''; }
    catch (_) { return ''; }
  }
  function go() {
    location.href = (token() ? SETTINGS : ACCOUNT + '/login')
      + '?' + (token() ? 'from=' : 'redirect=') + encodeURIComponent(location.href);
  }

  function mount() {
    if (document.getElementById('bnProfileBtn')) return;
    var btn = document.createElement('button');
    btn.id = 'bnProfileBtn';
    btn.type = 'button';
    btn.title = '계정 설정';
    btn.setAttribute('aria-label', '계정 설정');
    btn.textContent = '·';
    btn.addEventListener('click', go);

    var css = document.createElement('style');
    css.textContent =
      '#bnProfileBtn{position:fixed;top:12px;right:14px;z-index:2147483000;width:34px;height:34px;' +
      'border-radius:50%;border:1px solid rgba(255,255,255,.22);background:rgba(20,20,22,.82);' +
      'color:#e9ecf1;font:700 14px/1 "Segoe UI","Apple SD Gothic Neo",sans-serif;cursor:pointer;' +
      'display:flex;align-items:center;justify-content:center;overflow:hidden;padding:0;' +
      'backdrop-filter:blur(6px);box-shadow:0 4px 14px rgba(0,0,0,.28)}' +
      '#bnProfileBtn:hover{border-color:#8b7ff0}' +
      '#bnProfileBtn img{width:100%;height:100%;object-fit:cover;display:block}' +
      '@media print{#bnProfileBtn{display:none!important}}';
    document.head.appendChild(css);
    document.body.appendChild(btn);

    /* 로그인 상태면 이름 첫 글자나 아바타를 보여준다 */
    var t = token();
    if (!t) { btn.textContent = '?'; return; }
    fetch(ACCOUNT + '/api/me', { headers: { Authorization: 'Bearer ' + t } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (u) {
        if (!u) { btn.textContent = '?'; return; }
        btn.title = (u.displayName || u.username) + ' · 계정 설정';
        if (u.avatar && /^https?:\/\//.test(u.avatar)) {
          var img = new Image();
          img.alt = ''; img.referrerPolicy = 'no-referrer'; img.src = u.avatar;
          img.onload = function () { btn.textContent = ''; btn.appendChild(img); };
          img.onerror = function () { btn.textContent = (u.displayName || u.username || '?').slice(0, 1); };
        } else {
          btn.textContent = (u.displayName || u.username || '?').slice(0, 1).toUpperCase();
        }
      })
      .catch(function () { btn.textContent = '?'; });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();

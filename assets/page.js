/* Progressive enhancement for the generated static pages: theme persistence,
   copy-to-clipboard, and the Linux/Windows fix tabs. Everything on these pages
   is readable and usable without this file. */
(function () {
    'use strict';

    var toastEl = document.getElementById('toast');
    var toastTimer;

    function toast(message) {
        if (!toastEl) return;
        toastEl.textContent = message;
        toastEl.classList.add('show');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { toastEl.classList.remove('show'); }, 2200);
    }

    /* ---- theme ---- */

    var icon = document.getElementById('themeToggleIcon');
    var toggle = document.getElementById('themeToggle');

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        if (icon) icon.textContent = theme === 'dark' ? '🌙' : '☀️';
        try { localStorage.setItem('theme', theme); } catch (e) { /* private mode */ }
    }

    if (toggle) {
        toggle.addEventListener('click', function () {
            applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
        });
    }
    if (icon) {
        icon.textContent = document.documentElement.getAttribute('data-theme') === 'dark' ? '🌙' : '☀️';
    }

    /* ---- copy buttons ---- */

    function fallbackCopy(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        document.body.removeChild(ta);
        return ok;
    }

    function flash(button) {
        var original = button.textContent;
        button.textContent = 'Copied!';
        button.classList.add('copied');
        setTimeout(function () {
            button.textContent = original;
            button.classList.remove('copied');
        }, 2000);
    }

    document.addEventListener('click', function (event) {
        var button = event.target.closest('.copy-button');
        if (!button) return;
        var source = document.getElementById(button.dataset.copyTarget);
        if (!source) return;
        var text = source.textContent;

        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(function () {
                flash(button);
                toast('Copied to clipboard');
            }).catch(function () {
                toast(fallbackCopy(text) ? 'Copied to clipboard' : 'Copy failed');
            });
        } else {
            if (fallbackCopy(text)) { flash(button); toast('Copied to clipboard'); }
            else { toast('Copy failed'); }
        }
    });

    /* ---- platform tabs ---- */

    var tablist = document.querySelector('.tabs[role="tablist"]');
    if (tablist) {
        var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));

        function select(tab) {
            tabs.forEach(function (t) {
                var selected = t === tab;
                t.setAttribute('aria-selected', selected ? 'true' : 'false');
                t.tabIndex = selected ? 0 : -1;
                var panel = document.getElementById(t.getAttribute('aria-controls'));
                if (panel) panel.hidden = !selected;
            });
        }

        tabs.forEach(function (tab, index) {
            tab.tabIndex = tab.getAttribute('aria-selected') === 'true' ? 0 : -1;
            tab.addEventListener('click', function () { select(tab); });
            tab.addEventListener('keydown', function (event) {
                var delta = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
                if (!delta) return;
                event.preventDefault();
                var next = tabs[(index + delta + tabs.length) % tabs.length];
                select(next);
                next.focus();
            });
        });
    }

    /* ---- '/' focuses the search box on the home page ---- */

    document.addEventListener('keydown', function (event) {
        if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
        var tag = event.target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || event.target.isContentEditable) return;
        var search = document.getElementById('searchInput');
        if (search) { event.preventDefault(); search.focus(); }
    });
}());

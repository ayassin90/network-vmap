/* Help side panel. A [data-help="topic#anchor"] button, the top bar ?, or the ? key opens the topic's help
   on the right, scrolled to the control's section. Content comes from /help/<topic>/panel/ (same origin). */
(function(){
  var panel=document.getElementById('help-panel'); if(!panel) return;
  var body=panel.querySelector('[data-help-content]'), cache={};
  function show(ref){
    var parts=(ref||'').split('#'), slug=parts[0], anchor=parts[1]||'';
    if(!slug){ location.href='/help/'; return; }
    function place(html){
      body.innerHTML=html; panel.hidden=false; document.body.classList.add('help-open');
      var target=anchor && body.querySelector('#h-'+CSS.escape(anchor));
      body.querySelectorAll('.help-sec.on').forEach(function(s){s.classList.remove('on')});
      if(target){ target.classList.add('on'); target.scrollIntoView({block:'start'}); } else { body.scrollTop=0; }
    }
    if(cache[slug]) return place(cache[slug]);
    fetch('/help/'+encodeURIComponent(slug)+'/panel/',{credentials:'same-origin'})
      .then(function(r){ if(!r.ok) throw 0; return r.text(); })
      .then(function(h){ cache[slug]=h; place(h); })
      .catch(function(){ place('<p class="muted">Help could not be loaded.</p>'); });
  }
  function hide(){ panel.hidden=true; document.body.classList.remove('help-open'); }
  document.addEventListener('click',function(e){
    var b=e.target.closest('[data-help]');
    if(b){ e.preventDefault(); e.stopPropagation(); show(b.getAttribute('data-help')); return; }
    var a=e.target.closest('#help-panel .help-toc a');
    if(a){ e.preventDefault(); show(panel.dataset.slug+'#'+a.dataset.anchor); }
    if(e.target.closest('[data-help-close]')) hide();
  });
  document.addEventListener('keydown',function(e){
    if(e.key==='Escape' && !panel.hidden) hide();
    var t=e.target, typing=t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
    if(e.key==='?' && !typing && !e.metaKey && !e.ctrlKey){ e.preventDefault(); var b=document.getElementById('tb-help'); show(b && b.getAttribute('data-help')); }
  });
  var obs=new MutationObserver(function(){ var h=body.querySelector('.help-panel-head a[href^="/help/"]'); if(h){ var m=h.getAttribute('href').match(/^\/help\/([^/]+)\//); if(m) panel.dataset.slug=m[1]; }});
  obs.observe(body,{childList:true});
})();

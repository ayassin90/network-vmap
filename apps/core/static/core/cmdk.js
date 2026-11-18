/* Cmd-K / Ctrl-K: one box that finds anything (core/search.py). Arrow keys to move, Enter to open. */
(function(){
  var me=document.currentScript, url=me.dataset.url, dlg=document.getElementById('ck'), q=document.getElementById('ck-q'),
      res=document.getElementById('ck-res'), sel=0, links=[], t;
  function open(){dlg.showModal(); q.value=''; res.innerHTML='<p class="ck-hint">Type at least two characters.</p>'; q.focus();}
  function mark(){links.forEach(function(a,i){a.classList.toggle('on',i===sel)}); if(links[sel]) links[sel].scrollIntoView({block:'nearest'});}
  function run(){
    fetch(url+'?q='+encodeURIComponent(q.value),{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(d){
      res.innerHTML='';
      d.groups.forEach(function(g){
        var h=document.createElement('div'); h.className='ck-group'; h.textContent=g.title; res.appendChild(h);
        g.items.forEach(function(it){var a=document.createElement('a'); a.href=it.url; a.className='ck-item';
          var b=document.createElement('strong'); b.textContent=it.label; var s=document.createElement('span'); s.textContent=it.sub||'';
          a.appendChild(b); a.appendChild(s); res.appendChild(a);});
      });
      if(!d.groups.length) res.innerHTML='<p class="ck-hint">Nothing found.</p>';
      links=[].slice.call(res.querySelectorAll('.ck-item')); sel=0; mark();
    });
  }
  document.addEventListener('keydown',function(e){
    if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){e.preventDefault(); open();}
  });
  document.getElementById('ck-open').addEventListener('click',open);
  q.addEventListener('input',function(){clearTimeout(t); if(q.value.trim().length<2){res.innerHTML='<p class="ck-hint">Type at least two characters.</p>';links=[];return;} t=setTimeout(run,180);});
  q.addEventListener('keydown',function(e){
    if(e.key==='ArrowDown'){sel=Math.min(sel+1,links.length-1);mark();e.preventDefault();}
    else if(e.key==='ArrowUp'){sel=Math.max(sel-1,0);mark();e.preventDefault();}
    else if(e.key==='Enter'&&links[sel]){location.href=links[sel].href;}
  });
  dlg.addEventListener('click',function(e){if(e.target===dlg) dlg.close();});
})();

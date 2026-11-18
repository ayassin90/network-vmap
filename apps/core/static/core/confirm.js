/* Confirmation dialog for anything that changes something (replaces the browser's confirm()).
   On a submit button or a form:
     data-confirm="Body text"            required; plain text, newlines kept
     data-confirm-title="Import now?"    optional
     data-confirm-ok="Import"            optional label of the confirm button
     data-confirm-danger                 optional: red confirm button
     data-confirm-type="DELETE"          optional: the user must type this word first
   A page may build the text at click time: set window.VmapConfirmText = function(el){ return {title, body} }. */
(function(){
  var dlg, title, body, ok, typed, typedWrap, pending;

  function build(){
    dlg = document.getElementById('confirm-dlg');
    title = dlg.querySelector('[data-c-title]'); body = dlg.querySelector('[data-c-body]');
    ok = dlg.querySelector('[data-c-ok]'); typed = dlg.querySelector('[data-c-typed]'); typedWrap = dlg.querySelector('[data-c-typedwrap]');
    dlg.querySelector('[data-c-cancel]').addEventListener('click', function(){ dlg.close(); pending = null; });
    typed.addEventListener('input', function(){ ok.disabled = typed.value.trim() !== typed.dataset.want; });
    ok.addEventListener('click', function(){
      var p = pending; pending = null; dlg.close();
      if(!p) return;
      p.form.dataset.confirmed = '1';
      if(p.button) p.form.requestSubmit(p.button); else p.form.requestSubmit();
    });
  }

  function ask(el, form, button){
    var dyn = window.VmapConfirmText && el.dataset.confirmDynamic !== undefined ? window.VmapConfirmText(el) : null;
    title.textContent = (dyn && dyn.title) || el.dataset.confirmTitle || 'Are you sure?';
    body.textContent = (dyn && dyn.body) || el.dataset.confirm;
    ok.textContent = el.dataset.confirmOk || 'Confirm';
    ok.className = 'btn ' + (el.dataset.confirmDanger !== undefined ? 'btn-danger-solid' : 'btn-primary');
    var want = el.dataset.confirmType || '';
    typedWrap.hidden = !want; typed.value = ''; typed.dataset.want = want;
    typedWrap.querySelector('b').textContent = want;
    ok.disabled = !!want;
    pending = {form: form, button: button};
    dlg.showModal();
    (want ? typed : ok).focus();
  }

  // A POST form goes once: a second click or Enter within a few seconds is ignored, so nothing is created or started
  // twice. Released after 8 s for forms that answer with a download and leave the page as it is.
  function once(e, form){
    if((form.method || '').toLowerCase() !== 'post') return;
    if(form.dataset.sending){ e.preventDefault(); e.stopImmediatePropagation(); return; }
    form.dataset.sending = '1';
    setTimeout(function(){ delete form.dataset.sending; }, 8000);
  }

  document.addEventListener('DOMContentLoaded', build);
  document.addEventListener('submit', function(e){
    var form = e.target, button = e.submitter;
    if(form.dataset.confirmed){ delete form.dataset.confirmed; return once(e, form); }
    var el = button && button.dataset.confirm !== undefined ? button : (form.dataset.confirm !== undefined ? form : null);
    if(!el) return once(e, form);
    e.preventDefault(); e.stopImmediatePropagation();
    ask(el, form, button);
  }, true);
})();

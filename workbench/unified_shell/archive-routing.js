/* Same-origin namespace for the experimental results page. No result substitution. */
'use strict';
(()=>{
 const prefix='/history';
 const routed=p=>p.startsWith('/api/')||p.startsWith('/export/');
 const urlFor=value=>{
  const u=new URL(value,location.href);
  if(u.origin===location.origin&&routed(u.pathname))u.pathname=prefix+u.pathname;
  return u.href;
 };
 const originalFetch=window.fetch.bind(window);
 window.fetch=(input,options)=>{
  if(input instanceof Request)return originalFetch(new Request(urlFor(input.url),input),options);
  return originalFetch(urlFor(input),options);
 };
 const originalClick=HTMLAnchorElement.prototype.click;
 HTMLAnchorElement.prototype.click=function(){
  // The original raw-data exporter clicks an anchor never inserted in the DOM.
  // MutationObserver cannot see that anchor, so route it before the real click.
  const raw=this.getAttribute('href');
  if(raw&&routed(raw))this.setAttribute('href',prefix+raw);
  return originalClick.call(this);
 };
 function links(){for(const a of document.querySelectorAll('a[href]')){
  const raw=a.getAttribute('href');
  if(raw&&routed(raw))a.setAttribute('href',prefix+raw);
 }}
 new MutationObserver(links).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['href']});
 document.addEventListener('DOMContentLoaded',links);
})();

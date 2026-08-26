async function send(url, options={}) {
  const response = await fetch(url, {headers:{'Content-Type':'application/json'}, ...options});
  if (!response.ok) {
    let message = 'Request failed';
    try { message = (await response.json()).error || message; } catch (_) {}
    throw new Error(message);
  }
  return response.json();
}

document.querySelector('#target-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const body = Object.fromEntries(new FormData(form).entries());
  try { await send('/targets', {method:'POST', body:JSON.stringify(body)}); location.reload(); }
  catch (error) { alert(error.message); }
});

document.querySelectorAll('.delete-target').forEach(button => button.addEventListener('click', async () => {
  if (!confirm('Delete this monitoring target and its history?')) return;
  try { await send(`/targets/${button.dataset.id}`, {method:'DELETE'}); location.reload(); }
  catch (error) { alert(error.message); }
}));

document.querySelectorAll('.ack').forEach(button => button.addEventListener('click', async () => {
  try { await send(`/alerts/${button.dataset.id}/ack`, {method:'POST'}); location.reload(); }
  catch (error) { alert(error.message); }
}));

setTimeout(() => location.reload(), 30000);

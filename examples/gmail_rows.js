// Visible Gmail inbox rows -> [{i, from_name, from_email, subject, snippet, unread}]
[...document.querySelectorAll('tr.zA')].filter(r => r.offsetParent !== null).map((r, i) => {
  const s = r.querySelector('.yX [email], .yW [email]');
  return {
    i,
    from_name: s ? (s.getAttribute('name') || s.textContent).trim() : '',
    from_email: s ? s.getAttribute('email') : '',
    subject: (r.querySelector('.bog')?.textContent || '').trim(),
    snippet: (r.querySelector('.y2')?.textContent || '').replace(/^\s*-\s*/, '').trim().slice(0, 200),
    unread: r.classList.contains('zE'),
  };
})

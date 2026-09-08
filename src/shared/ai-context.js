// Only called by an explicit operator click; reuse KUMA's bounded read-only search.
export async function relatedAiContext(event) {
  const send = async message => {
    const result = await browser.runtime.sendMessage(message);
    if (!result?.ok) throw new Error(result?.error || 'Не удалось получить контекст');
    return result;
  };
  const { actions } = await send({type:'related:actions',event});
  const action = actions.find(item=>item.kind === 'host') || actions[0];
  if (!action) throw new Error('В событии нет полей для поиска');
  const {result} = await send({type:'related:search',event,action,rangeSeconds:900,limit:50});
  return {event:{Events:[event,...result.events]}};
}

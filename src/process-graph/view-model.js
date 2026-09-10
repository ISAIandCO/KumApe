// KUMA display adapter for the ApePatrol canvas. Query construction stays in background.
export function buildProcessGraphView(graph, sourceNodeId) {
  const edges = (graph.edges || []).map(e => ({ sourceId: e.source, targetId: e.target }));
  const degrees = new Map(); const parents = new Map();
  for (const e of edges) { degrees.set(e.sourceId, (degrees.get(e.sourceId)||0)+1); degrees.set(e.targetId,(degrees.get(e.targetId)||0)+1); parents.set(e.targetId,e.sourceId); }
  const nodes = graph.nodes.map(n => {
    const connectionCount = degrees.get(n.id) || 0;
    const label = n.image?.split(/[\\/]/).pop() || `PID ${n.pid}`;
    const event = n.event;
    const filterValues = { name: label, path: n.image, pid: n.pid, account: n.user, host: n.host, eventType: n.mappingName };
    const details = [['Время',new Date(n.timestamp).toLocaleString('ru-RU')],['Хост',n.host],['Процесс',label],['Путь',n.image],['Командная строка',n.commandLine],['PID',n.pid],['Родительский PID',n.parentPid],['GUID',n.processGuid],['Учётная запись',n.user],['Событие',n.mappingName]].filter(([,v])=>v).map(([label,value])=>({label,value:String(value)}));
    return { id:n.id, parentId:parents.get(n.id), depth:0, time:n.timestamp, event, filterValues, connectionCount, radius:Math.min(34,10+Math.sqrt(connectionCount)*6), selected:n.id===sourceNodeId, label,
      searchText:details.map(d=>d.value).join(' ').toLowerCase(), eventText:JSON.stringify(n.event), details };
  });
  return {nodes,edges};
}

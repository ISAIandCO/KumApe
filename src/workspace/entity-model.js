export function createEntityGraph(items) {
  const nodes = []; const entities = new Map(); const edges = [];
  for (const item of items) {
    const id = `event:${item.id}`;
    nodes.push({id, itemId:item.id, kind:'event', label:item.label, description:item.label, time:Date.parse(item.timestamp)});
    for (const key of item.entityKeys || []) {
      const index = key.indexOf(':'); const entityType = key.slice(0,index); const label = key.slice(index+1);
      const entityId = `entity:${key}`;
      if (!entities.has(entityId)) entities.set(entityId,{id:entityId,kind:'entity',entityType,label,typeLabel:entityType,connectionCount:0,queryFields:[entityType]});
      entities.get(entityId).connectionCount++;
      edges.push({sourceId:id,targetId:entityId});
    }
  }
  return {nodes:[...nodes,...entities.values()],edges};
}

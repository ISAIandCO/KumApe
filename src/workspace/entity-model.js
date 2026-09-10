import { createInvestigationGraph } from "@isaiandco/ape-share-core/investigation/graph";
const labels = { host: "Хост", account: "Учётная запись", process: "Процесс", ip: "IP-адрес", hash: "Хэш" };
const build = createInvestigationGraph({
  eventIdentity: item => item.id,
  eventRef: item => item.id,
  investigationEventTime: item => typeof item.timestamp === "number" ? item.timestamp : Date.parse(item.timestamp),
  describeInvestigationEvent: event => ({ title: event.label, description: event.label }),
  extractedEntities: event => (event.entityKeys ?? []).map(key => {
    const separator = key.indexOf(":");
    const type = key.slice(0, separator);
    return { spec: { key: type, type, label: labels[type] ?? type, fields: [type] }, field: type, value: key.slice(separator + 1) };
  }),
});
export function createEntityGraph(items, options) {
  const graph = build(items.map(item => ({ ...item, type: "event", snapshot: item })), options);
  for (const node of graph.nodes) if (node.kind === "event") node.itemId = items[node.itemIndex].id;
  return graph;
}

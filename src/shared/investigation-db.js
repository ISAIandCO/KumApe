import { describeEvent as describeCanonicalEvent } from "@isaiandco/ape-share-core/events/describe";
import { createInvestigationRepository } from "@isaiandco/ape-share-core/investigation/repository";
import { workspaceToMarkdown } from "@isaiandco/ape-share-core/investigation/model";
const repository = createInvestigationRepository({ databaseFactory: () => globalThis.indexedDB, name: "kumape-investigations" });
  function eventValue(event, fields) {
    const entries = new Map(Object.entries(event || {}).map(([key, value]) => [key.toLowerCase(), value]));
    for (const field of fields) {
      const value = entries.get(field.toLowerCase());
      if (value !== undefined && value !== null && value !== "") return String(value);
    }
    return null;
  }

  function describeEvent(event) {
    return describeCanonicalEvent({
      msgid: eventValue(event, ["DeviceEventClassID", "EventID", "Name"]),
      process: eventValue(event, ["DeviceProcessName", "DestinationProcessName", "SourceProcessName", "ProcessName"]),
      account: eventValue(event, ["SourceUserName", "DestinationUserName", "UserName"]),
      host: eventValue(event, ["DeviceHostName", "SourceHostName", "DestinationHostName"]),
      commandLine: eventValue(event, ["DeviceCustomString4", "DeviceCustomString2", "FlexString1"]),
      correlationRule: eventValue(event, ["CorrelationRuleName", "CorrelationRuleTitle", "RuleName"]),
      sourceIp: eventValue(event, ["SourceAddress"]), destinationIp: eventValue(event, ["DestinationAddress"]),
      originalDescription: eventValue(event, ["Message"]),
    }).title;
  }

  function entityKeys(event) {
    const definitions = {
      host: ["DeviceHostName", "SourceHostName", "DestinationHostName"],
      account: ["SourceUserName", "DestinationUserName", "UserName"],
      process: ["DeviceProcessName", "DestinationProcessName", "SourceProcessName"],
      ip: ["SourceAddress", "DestinationAddress", "DeviceAddress"],
      hash: ["FileHash", "OldFileHash", "Hash"],
    };
    const keys = [];
    for (const [kind, fields] of Object.entries(definitions)) {
      for (const field of fields) {
        const value = eventValue(event, [field]);
        if (value) keys.push(`${kind}:${value.toLowerCase()}`);
      }
    }
    return [...new Set(keys)];
  }


function eventItem(event) {
  const value = eventValue(event, ["ID", "event.id"]) || JSON.stringify(event);
  return { type: "event", value, label: describeEvent(event), sourceEventUuid: eventValue(event, ["ID", "event.id"]), snapshot: event };
}
async function addEvent(workspaceId, event, source = {}) {
  return repository.pinWorkspaceItem({ workspaceId, siemOrigin: source.uiOrigin, item: eventItem(event) });
}
// Existing product entry points call this small mapping facade; storage and CRUD are shared.
globalThis.KumApeInvestigations = Object.freeze({ ...repository, eventItem, addEvent, describeEvent, entityKeys,
  open: repository.openDatabase,
  listInvestigations: repository.listWorkspaces,
  getInvestigation: repository.getWorkspace,
  createInvestigation: title => repository.createInvestigation({ title }),
  updateInvestigation: repository.updateWorkspace,
  deleteInvestigation: repository.deleteWorkspace,
  listItems: async id => ((await repository.getWorkspace(id))?.items ?? []).map(item => ({ ...item, id: item.value, payload: item.snapshot, timestamp: new Date(globalThis.KumApeAdapter.eventTimestamp(item.snapshot)).toISOString(), entityKeys: entityKeys(item.snapshot) })),
  toMarkdown: workspaceToMarkdown,
});

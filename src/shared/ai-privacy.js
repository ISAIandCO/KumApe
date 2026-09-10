import { createEventPrivacy } from "@isaiandco/ape-share-core/ai/privacy";
  const strictFields = [
    "ID", "EventID", "EventId", "Timestamp", "EventTime", "DeviceReceiptTime", "DeviceEventClassID", "DeviceEventCategory",
    "DeviceHostName", "SourceHostName", "DestinationHostName", "SourceAddress", "DestinationAddress",
    "SourceUserName", "DestinationUserName", "DeviceProcessName", "SourceProcessName", "DestinationProcessName",
    "DeviceProcessID", "SourceProcessID", "DestinationProcessID", "FileName", "FilePath", "FileHash",
    "RequestUrl", "CorrelationRuleID", "CorrelationRuleName", "Message",
  ];

globalThis.KumApeAiPrivacy = Object.freeze(createEventPrivacy({ strictFields, collectionKey: "Events",
  eventIdentity(event) {
    const id = event?.ID;
    return id === undefined || id === null || id === "" ? JSON.stringify(event) : `event:${id}`;
  },
}));

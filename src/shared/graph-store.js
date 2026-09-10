import { createRecordStorage } from "@isaiandco/ape-share-core/storage/records";
import { createGraphSnapshots } from "@isaiandco/ape-share-core/graph/snapshots";
const storage = createRecordStorage({ databaseFactory: () => indexedDB, name: "kumape-graph-state" });
const snapshots = createGraphSnapshots({ storage });
globalThis.KumApeGraphStore = {
  async get(id) {
    const record = await snapshots.getGraphSnapshot(id);
    return record ? { request: record.context, result: record.response, createdAt: record.createdAt } : null;
  },
  async set(id, value) {
    const input = { context: value.request, response: value.result, sourceEvent: value.request.event };
    if (await snapshots.getGraphSnapshot(id)) await snapshots.updateGraphSnapshot(id, input);
    else await snapshots.saveGraphSnapshot(input, storage, id);
  },
  remove: id => snapshots.deleteGraphSnapshot(id),
};

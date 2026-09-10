import { createRecordStorage } from "@isaiandco/ape-share-core/storage/records";
const storage = createRecordStorage({ databaseFactory: () => indexedDB, name: "kumape-graph-state" });
globalThis.KumApeGraphStore = {
  get: async id => (await storage.get(id))[id],
  set: (id, value) => storage.set({ [id]: value }),
  remove: id => storage.remove(id),
};

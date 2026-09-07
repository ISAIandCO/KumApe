// Graph snapshots live in IndexedDB: event payloads can exceed storage.session's quota.
(function (global) {
  const open = () => new Promise((resolve,reject) => {
    const request=indexedDB.open('kumape-graphs',1);
    request.onupgradeneeded=()=>request.result.createObjectStore('graphs');
    request.onsuccess=()=>resolve(request.result); request.onerror=()=>reject(request.error);
  });
  async function transact(mode, action) {
    const db=await open();
    try { return await new Promise((resolve,reject)=>{
      const tx=db.transaction('graphs',mode);const request=action(tx.objectStore('graphs'));
      tx.oncomplete=()=>resolve(request.result);tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error||new Error('Graph transaction aborted'));
    }); } finally { db.close(); }
  }
  global.KumApeGraphStore={get:id=>transact('readonly',s=>s.get(id)),set:(id,value)=>transact('readwrite',s=>s.put(value,id)),remove:id=>transact('readwrite',s=>s.delete(id))};
})(globalThis);

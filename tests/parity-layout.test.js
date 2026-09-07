import test from 'node:test';
import assert from 'node:assert/strict';
import {applyRepulsion,forceIterationLimit} from '../src/process-graph/force-layout.js';
import {createEntityGraph} from '../src/workspace/entity-model.js';
test('ApePatrol repulsion remains bounded for 10000 overlapping nodes',()=>{
 const nodes=Array.from({length:10000},(_,i)=>({id:`n${i}`,x:0,y:0,vx:0,vy:0,radius:10}));
 assert.ok(applyRepulsion(nodes,1)<=nodes.length*24);
 assert.ok(nodes.every(n=>Number.isFinite(n.vx)&&Number.isFinite(n.vy)));
 assert.ok(forceIterationLimit(nodes.length)<60);
});
test('investigation shares a single IP entity across source and destination events',()=>{
 const graph=createEntityGraph([{id:'a',entityKeys:['ip:10.0.0.1'],timestamp:'2026-09-07T10:00:00Z'},{id:'b',entityKeys:['ip:10.0.0.1'],timestamp:'2026-09-07T10:00:01Z'}]);
 assert.equal(graph.nodes.length,3);assert.equal(graph.edges.length,2);assert.equal(graph.nodes.find(n=>n.kind==='entity').connectionCount,2);
});

test('event comparison preserves KUMA field changes and classifies process fields',async()=>{
 const {compareEvents}=await import('../src/shared/event-compare.js');
 const diff=compareEvents([{DestinationProcessID:1,DeviceHostName:'pc'},{DestinationProcessID:2,DeviceHostName:'pc'}]);
 assert.equal(diff.rows.find(r=>r.field==='destinationprocessid').status,'changed');
 assert.equal(diff.rows.find(r=>r.field==='destinationprocessid').group,'process');
 assert.equal(diff.rows.find(r=>r.field==='devicehostname').status,'same');
});

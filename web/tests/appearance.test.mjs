import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readAppearance,applyAppearance,appearanceDefaults} from '../src/appearance.ts';

for(const feature of ['Dark mode','User appearance settings']){
  test(feature+' / valid',()=>{
    globalThis.localStorage={getItem:()=>JSON.stringify({theme:'dark',accent:'violet',density:'compact',textSize:'large',reduceMotion:true})};
    globalThis.document={documentElement:{dataset:{},style:{}}};
    const value=readAppearance();applyAppearance(value,false);
    assert.equal(document.documentElement.dataset.theme,'dark');
    assert.equal(value.accent,'violet');assert.equal(value.reduceMotion,true);
  });
  test(feature+' / invalid',()=>{
    globalThis.localStorage={getItem:()=>JSON.stringify({theme:'unknown',accent:'invalid',density:'bad',textSize:'bad',reduceMotion:'yes'})};
    assert.deepEqual(readAppearance(),appearanceDefaults);
  });
  test(feature+' / null-edge',()=>{
    globalThis.localStorage={getItem:()=>null};assert.deepEqual(readAppearance(),appearanceDefaults);
    globalThis.document={documentElement:{dataset:{},style:{}}};
    applyAppearance({...appearanceDefaults,theme:'system'},true);
    assert.equal(document.documentElement.dataset.theme,'dark');
    applyAppearance({...appearanceDefaults,theme:'system'},false);
    assert.equal(document.documentElement.dataset.theme,'light');
    globalThis.localStorage={getItem:()=>'{broken'};assert.deepEqual(readAppearance(),appearanceDefaults);
  });
}

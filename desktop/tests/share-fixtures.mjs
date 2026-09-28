import { writeFileSync } from 'node:fs';
import { fixtures } from './import-fixtures.mjs';
import { nativeLink, wireguardFile, shareProfiles } from '../src/profiles/share.ts';
import { parseImport } from '../src/profiles/import.ts';
export function sharedFixtures() {
  return fixtures().flatMap(f => [f.name.endsWith('multi-peer') ? wireguardFile(f) : nativeLink(f), shareProfiles([f], 'thronium-link')].map((text,i)=>{
    const [row]=parseImport(text,'personal');if(!row.draft||row.warnings.length)throw Error(f.name);
    return {name:f.name+'-shared-'+i,kind:row.draft.kind,config:row.draft.config};
  }));
}
if(process.argv[2])writeFileSync(process.argv[2],JSON.stringify(sharedFixtures(),null,2));

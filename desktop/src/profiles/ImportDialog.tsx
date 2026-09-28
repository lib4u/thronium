import { useImportController } from './useImportController';
import ImportView from './ImportView';
export * from './ImportModel';
export default function ImportDialog(props: Parameters<typeof useImportController>[0]) {
  return <ImportView controller={useImportController(props)} />;
}

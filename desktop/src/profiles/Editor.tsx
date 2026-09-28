import { useProfileEditor } from './useProfileEditor';
import ProfileEditorView from './ProfileEditorView';
export * from './EditorModel';
export default function Editor(props: Parameters<typeof useProfileEditor>[0]) {
  return <ProfileEditorView controller={useProfileEditor(props)} />;
}

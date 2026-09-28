import { useRuleEditor } from './useRuleEditor';
import RuleEditorView from './RuleEditorView';
export * from './RuleEditorModel';
export default function RuleEditor(props: Parameters<typeof useRuleEditor>[0]) {
  return <RuleEditorView controller={useRuleEditor(props)} />;
}

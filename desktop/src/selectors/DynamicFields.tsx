import { useDynamicSelector } from './useDynamicSelector';
import DynamicSelectorView from './DynamicSelectorView';
export * from './DynamicSelectorModel';
export default function DynamicFields(props: Parameters<typeof useDynamicSelector>[0]) {
  return <DynamicSelectorView controller={useDynamicSelector(props)} />;
}

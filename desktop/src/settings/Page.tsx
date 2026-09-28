import { useSettingsController } from './useSettingsController';
import SettingsView from './SettingsView';
export * from './SettingsCatalog';
export default function SettingsPage(props: Parameters<typeof useSettingsController>[0]) {
  return <SettingsView controller={useSettingsController(props)} />;
}

import './styles/tokens.css';
import './styles/styles.css';
import './styles/responsive.css';
import './styles/client.css';
import './styles/features.css';
import './App.css';
import './library/ProfileOrder.css';
import { useAppController } from './useAppController';
import AppShell from './AppShell';
export * from './AppModel';
export default function App() {
  return <AppShell controller={useAppController()} />;
}

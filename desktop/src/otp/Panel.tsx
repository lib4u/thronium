import { useOtpController } from './useOtpController';
import OtpView from './OtpView';
export * from './OtpModel';
export default function OtpPanel(props: Parameters<typeof useOtpController>[0]) {
  return <OtpView controller={useOtpController(props)} />;
}

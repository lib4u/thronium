import { useLegacyReview } from './useLegacyReview';
import LegacyReviewView from './LegacyReviewView';
export * from './LegacyReviewModel';
export default function LegacyReview(props: Parameters<typeof useLegacyReview>[0]) {
  return <LegacyReviewView controller={useLegacyReview(props)} />;
}

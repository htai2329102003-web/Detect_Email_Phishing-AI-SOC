import { EmailUpload } from "../../components/analysis/EmailUpload";
import { AppShell } from "../../components/layout/AppShell";

export default function AnalyzePage() {
  return (
    <AppShell title="Analyze email">
      <EmailUpload />
    </AppShell>
  );
}

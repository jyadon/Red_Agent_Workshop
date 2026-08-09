import { PageContainer } from "../components/layout/PageContainer";
import { AdCredentialsPanel } from "../components/config/AdCredentialsPanel";
import { MfaPanel } from "../components/config/MfaPanel";
import { PasswordChangePanel } from "../components/config/PasswordChangePanel";
import { EntraDataPanel } from "../components/entra/EntraDataPanel";

/** Config page bundling pre-verification setup (AD credentials, Entra data collection). */
export function ConfigPage() {
  return (
    <PageContainer className="mx-auto max-w-5xl space-y-8">
      <div>
        <h2 className="text-2xl font-bold text-text-primary">Settings</h2>
        <p className="mt-1 text-text-secondary">
          Pre-configure the credentials and data collection used during re-testing, and change your password for this site.
        </p>
      </div>

      <AdCredentialsPanel />
      <EntraDataPanel />
      <PasswordChangePanel />
      <MfaPanel />
    </PageContainer>
  );
}

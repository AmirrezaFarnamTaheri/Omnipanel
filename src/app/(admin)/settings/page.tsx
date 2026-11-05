import { requirePage } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, PageHeader } from "@/components/ui";

/**
 * Read-only until settings mutations have persistence, authorization and audit.
 * Do not display values from the settings table: it also stores encrypted secrets.
 */
export default async function SettingsPage() {
  await requirePage("viewer");

  return (
    <>
      <PageHeader
        title="Settings"
        subtitle="Configuration is managed through the development environment while the administration API is being implemented."
      />
      <Card>
        <CardHeader>
          <CardTitle>Configuration management is not available yet</CardTitle>
          <CardDescription>Changes are intentionally disabled rather than pretending to save settings.</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-600">
            Secret material, authentication configuration and retention policy are not exposed on this page.
            Use documented operator procedures until a verified, audited settings workflow is available.
          </p>
        </CardContent>
      </Card>
    </>
  );
}

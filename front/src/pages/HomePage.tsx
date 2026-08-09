import { Link } from "react-router";
import { useFindings } from "../hooks/useFindings";
import { useFindingsStore } from "../lib/findings-store";
import { PageContainer } from "../components/layout/PageContainer";
import { features } from "../lib/features";

type NavAccent = "accent" | "info" | "warning";

interface NavCardDef {
  to: string;
  title: string;
  description: string;
  accentClass: NavAccent;
}

export function HomePage() {
  const { findings } = useFindings();
  const reportTitle = useFindingsStore((s) => s.reportTitle);

  const stats = {
    total: findings.length,
    high: findings.filter((f) => f.risk_level === "High").length,
    medium: findings.filter((f) => f.risk_level === "Medium").length,
    low: findings.filter((f) => f.risk_level === "Low").length,
  };

  const hasFindings = findings.length > 0;

  // Retest requires existing findings, so only show that card when findings exist.
  const navCards = [
    features.retest && hasFindings
      ? {
          to: "/retest",
          title: "Run Retest",
          description:
            "Select findings and request a retest from the AI agent.",
          accentClass: "accent",
        }
      : null,
    features.rto
      ? {
          to: "/rto",
          title: "Red Team Test",
          description:
            "Request a lightweight Red Team test from the AI agent.",
          accentClass: "warning",
        }
      : null,
  ].filter((c): c is NavCardDef => c !== null);

  return (
    <PageContainer className="mx-auto max-w-5xl space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-text-primary">Red Agent</h2>
          <p className="mt-1 text-text-secondary">
            {reportTitle ?? "Security Verification Workspace"}
          </p>
        </div>
      </div>

      {hasFindings && (
        <div className="grid grid-cols-4 gap-4">
          <StatCard label="Total Findings" value={stats.total} />
          <StatCard
            label="Risk Level High"
            value={stats.high}
            colorClass="text-red-400"
          />
          <StatCard
            label="Risk Level Medium"
            value={stats.medium}
            colorClass="text-yellow-400"
          />
          <StatCard
            label="Risk Level Low"
            value={stats.low}
            colorClass="text-blue-400"
          />
        </div>
      )}

      {navCards.length > 0 ? (
        <div className="grid gap-6 sm:grid-cols-2">
          {navCards.map((card) => (
            <NavCard
              key={card.to}
              to={card.to}
              title={card.title}
              description={card.description}
              accentClass={card.accentClass}
            />
          ))}
        </div>
      ) : (
        <div className="rounded-xl border border-border bg-bg-secondary p-6 text-center text-sm text-text-muted">
          No features are enabled. Check the build-time feature flag configuration.
        </div>
      )}

      {hasFindings && (
        <div className="rounded-xl border border-border bg-bg-secondary p-6">
          <h3 className="mb-4 text-lg font-semibold text-text-primary">
            Priority Remediation Items
          </h3>
          <div className="space-y-3">
            {(() => {
              const highRiskFindings = findings.filter(
                (f) => f.risk_level === "High",
              );

              if (highRiskFindings.length === 0) {
                return (
                  <div className="py-4 text-center text-sm text-text-muted">
                    No high-risk findings.
                  </div>
                );
              }

              return highRiskFindings.map((f) => (
                <Link
                  key={f.no}
                  to={`/retest/${encodeURIComponent(f.no)}`}
                  className="flex items-center justify-between rounded-lg border border-border/50 bg-bg-primary p-3 transition-colors hover:border-border-hover"
                >
                  <div className="flex flex-col justify-center min-h-[40px]">
                    <div className="text-sm font-medium text-text-primary">
                      {f.no}　{f.title}
                    </div>
                  </div>
                  <span className="text-xs text-text-muted">Details</span>
                </Link>
              ));
            })()}
          </div>
        </div>
      )}
    </PageContainer>
  );
}

// Tailwind JIT scans class strings statically, so dynamic interpolation like
// `hover:border-${x}/50` won't generate classes. Keep full class strings per accent.
const NAV_ACCENT_CLASSES: Record<
  NavAccent,
  { border: string; shadow: string; text: string }
> = {
  accent: {
    border: "hover:border-accent/50",
    shadow: "hover:shadow-accent/5",
    text: "text-accent",
  },
  info: {
    border: "hover:border-info/50",
    shadow: "hover:shadow-info/5",
    text: "text-info",
  },
  warning: {
    border: "hover:border-warning/50",
    shadow: "hover:shadow-warning/5",
    text: "text-warning",
  },
};

function NavCard({
  to,
  title,
  description,
  badge = "",
  accentClass,
}: {
  to: string;
  title: string;
  description: string;
  badge?: string;
  accentClass: NavAccent;
}) {
  const accent = NAV_ACCENT_CLASSES[accentClass];
  return (
    <Link
      to={to}
      className={`group rounded-xl border border-border bg-bg-secondary p-6 transition-all ${accent.border} hover:shadow-lg ${accent.shadow}`}
    >
      <h3 className="text-lg font-semibold text-text-primary">{title}</h3>
      <p className="mt-2 text-sm text-text-secondary whitespace-pre-line">
        {description}
      </p>
      {badge && (
        <div className={`mt-4 text-sm font-medium ${accent.text}`}>{badge}</div>
      )}
    </Link>
  );
}

function StatCard({
  label,
  value,
  colorClass = "text-text-primary",
}: {
  label: string;
  value: number;
  colorClass?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="text-xs text-text-muted">{label}</div>
      <div className={`mt-1 text-2xl font-bold ${colorClass}`}>{value}</div>
    </div>
  );
}

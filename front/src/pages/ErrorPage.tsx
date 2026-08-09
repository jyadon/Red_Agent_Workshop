import { Link, isRouteErrorResponse, useRouteError } from "react-router";

// Root-level errorElement replaces RootLayout, so this must be a self-contained
// full-screen view that does not depend on the Sidebar or other layout pieces.
export function ErrorPage() {
  const error = useRouteError();

  const isNotFound = isRouteErrorResponse(error) && error.status === 404;
  const title = isNotFound
    ? "Page not found"
    : "An unexpected error occurred";
  const description = isNotFound
    ? "The page you are looking for does not exist or may have moved."
    : "Something went wrong. Return to the home page and try again.";

  // Never expose stack traces or other internal details in production; show them
  // only in development to aid debugging.
  const detail = import.meta.env.DEV ? formatErrorDetail(error) : null;

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 bg-bg-primary p-6 text-center">
      <div className="space-y-3">
        <div className="text-5xl font-bold text-accent">
          {isNotFound ? "404" : "Error"}
        </div>
        <h1 className="text-xl font-semibold text-text-primary">{title}</h1>
        <p className="text-sm text-text-secondary">{description}</p>
      </div>

      {detail && (
        <pre className="max-w-2xl overflow-auto rounded-lg border border-border bg-bg-secondary p-4 text-left text-xs text-text-muted">
          {detail}
        </pre>
      )}

      <Link
        to="/"
        className="rounded-lg bg-accent px-6 py-2 text-sm font-bold text-white transition-colors hover:bg-accent-hover"
      >
        Return home
      </Link>
    </div>
  );
}

function formatErrorDetail(error: unknown): string {
  if (isRouteErrorResponse(error)) {
    const body =
      error.data == null
        ? ""
        : `\n${typeof error.data === "string" ? error.data : JSON.stringify(error.data, null, 2)}`;
    return `${error.status} ${error.statusText}${body}`;
  }
  if (error instanceof Error) {
    return error.stack ?? `${error.name}: ${error.message}`;
  }
  return String(error);
}

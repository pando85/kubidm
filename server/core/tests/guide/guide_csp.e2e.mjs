import { expect, test } from "@playwright/test";

test("guided UI CSP remains self-hosted and worker-free", async ({ request }) => {
    const response = await request.get("/ui/_lab?rive=mock");
    expect(response.ok()).toBe(true);
    const csp = response.headers()["content-security-policy"] || "";

    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    expect(csp).toContain("worker-src 'none'");
    // Kubidm currently permits unsafe-eval globally. If this is tightened later,
    // Rive needs wasm-unsafe-eval or another verified WASM execution strategy.
    expect(csp.includes("'unsafe-eval'") || csp.includes("'wasm-unsafe-eval'")).toBe(true);

    for (const forbidden of ["unpkg.com", "jsdelivr.net", "cdn.rive.app"]) {
        expect(csp).not.toContain(forbidden);
    }
});

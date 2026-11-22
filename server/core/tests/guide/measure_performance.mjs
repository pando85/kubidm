import { chromium, firefox, webkit } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const baseURL = process.env.KUBIDM_UI_BASE_URL || "https://localhost:8443";
const baseOrigin = new URL(baseURL).origin;
const mode = process.env.KUBIDM_RIVE_TEST_MODE || "real";
const maxInitMs = Number(process.env.KUBIDM_RIVE_MAX_INIT_MS || 2000);
const maxFrameP95Ms = Number(process.env.KUBIDM_RIVE_MAX_FRAME_P95_MS || 50);
const maxMobileInitMs = Number(process.env.KUBIDM_RIVE_MAX_MOBILE_INIT_MS || 4000);
const maxMobileFrameP95Ms = Number(process.env.KUBIDM_RIVE_MAX_MOBILE_FRAME_P95_MS || 80);
const maxHeapGrowthBytes = Number(process.env.KUBIDM_RIVE_MAX_HEAP_GROWTH_BYTES || 8 * 1024 * 1024);
const maxIdleTaskMs = Number(process.env.KUBIDM_RIVE_MAX_IDLE_TASK_MS || 200);
const idleSampleMs = Number(process.env.KUBIDM_RIVE_IDLE_SAMPLE_MS || 2000);
const stressTransitions = Number(process.env.KUBIDM_RIVE_STRESS_TRANSITIONS || 100);
const mobileCpuRate = Number(process.env.KUBIDM_RIVE_MOBILE_CPU_RATE || 4);
const output = path.resolve("artifacts", "guide-performance.json");

function percentile(values, percentileValue) {
    if (values.length === 0) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.min(sorted.length - 1, Math.ceil(sorted.length * percentileValue) - 1);
    return sorted[index];
}

function labUrl(story) {
    const query = mode === "mock" ? "?rive=mock" : "";
    return `${baseURL}/ui/_lab${query}#story=${story}&theme=light&viewport=desktop&motion=full`;
}

async function performanceMetric(session, name) {
    const response = await session.send("Performance.getMetrics");
    return response.metrics.find((metric) => metric.name === name)?.value || 0;
}

async function heapUsed(session) {
    await session.send("HeapProfiler.collectGarbage");
    return performanceMetric(session, "JSHeapUsedSize");
}

async function collectFrameIntervals(page) {
    return page.evaluate(async () => {
        const intervals = [];
        await new Promise((resolve) => {
            let first = null;
            let previous = null;
            const tick = (timestamp) => {
                if (first === null) first = timestamp;
                if (previous !== null) intervals.push(timestamp - previous);
                previous = timestamp;
                if (timestamp - first >= 1200) resolve();
                else requestAnimationFrame(tick);
            };
            requestAnimationFrame(tick);
        });
        return intervals;
    });
}

async function resourceTiming(page) {
    return page.evaluate(() => {
        const entries = performance.getEntriesByType("resource");
        const lookup = (pathname) => {
            const entry = entries.find((candidate) => {
                try {
                    return new URL(candidate.name).pathname === pathname;
                } catch {
                    return false;
                }
            });
            if (!entry) return null;
            return {
                transferSize: entry.transferSize,
                encodedBodySize: entry.encodedBodySize,
                decodedBodySize: entry.decodedBodySize,
                durationMs: entry.duration,
            };
        };
        return {
            javascript: lookup("/pkg/rive/rive.js"),
            wasm: lookup("/pkg/rive/rive.wasm"),
            riv: lookup("/pkg/img/guide/kubidm-guide.riv"),
        };
    });
}

async function churn(page, count) {
    const sequence = ["first-login", "method-choice", "passkey-working", "success", "policy-required", "goodbye"];
    for (let index = 0; index < count; index += 1) {
        const story = sequence[index % sequence.length];
        await page.locator(`[data-story="${story}"]`).click();
        await page.waitForFunction(
            (expected) =>
                document.querySelector("#ui-lab-story-title")?.textContent?.length > 0 &&
                document.querySelector(`[data-story="${expected}"]`)?.getAttribute("aria-current") === "true",
            story,
        );
    }
}

async function measureProfile({
    browserType,
    name,
    viewport,
    initLimit,
    frameLimit,
    cpuRate = 1,
    measureHeap = false,
    measureIdleCpu = false,
}) {
    const browser = await browserType.launch();
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport });
    const page = await context.newPage();
    const consoleErrors = [];
    const externalRequests = [];

    page.on("console", (message) => {
        if (message.type() === "error") consoleErrors.push(message.text());
    });
    page.on("request", (request) => {
        const url = request.url();
        if (/^https?:/.test(url) && new URL(url).origin !== baseOrigin) externalRequests.push(url);
    });

    await page.addInitScript(() => {
        globalThis.__kubidmRivePerf = {
            loadedAt: null,
            firstDiagnosticAt: null,
            firstVisibleAt: null,
        };
        window.addEventListener("kubidm:guide-diagnostics", (event) => {
            const now = performance.now();
            if (globalThis.__kubidmRivePerf.firstDiagnosticAt === null) {
                globalThis.__kubidmRivePerf.firstDiagnosticAt = now;
            }
            if (event.detail?.loaded === true && globalThis.__kubidmRivePerf.loadedAt === null) {
                globalThis.__kubidmRivePerf.loadedAt = now;
            }
        });
        window.addEventListener(
            "DOMContentLoaded",
            () => {
                const detectVisibleCanvas = () => {
                    const canvas = document.querySelector("[data-guide-rive-canvas]");
                    if (canvas && !canvas.hidden) {
                        const style = getComputedStyle(canvas);
                        const rect = canvas.getBoundingClientRect();
                        if (
                            style.display !== "none" &&
                            style.visibility !== "hidden" &&
                            rect.width > 0 &&
                            rect.height > 0
                        ) {
                            globalThis.__kubidmRivePerf.firstVisibleAt = performance.now();
                            return;
                        }
                    }
                    requestAnimationFrame(detectVisibleCanvas);
                };
                requestAnimationFrame(detectVisibleCanvas);
            },
            { once: true },
        );
    });

    let cdp = null;
    if (browserType === chromium) {
        cdp = await context.newCDPSession(page);
        await cdp.send("Performance.enable");
        if (cpuRate > 1) await cdp.send("Emulation.setCPUThrottlingRate", { rate: cpuRate });
    }

    await page.goto(labUrl("applications-arrival"), { waitUntil: "networkidle" });
    await page.waitForFunction(() => globalThis.__kubidmGuideDiagnostics?.loaded === true, null, {
        timeout: initLimit + 5000,
    });
    await page.waitForFunction(() => globalThis.__kubidmRivePerf?.firstVisibleAt !== null, null, {
        timeout: initLimit + 5000,
    });

    const init = await page.evaluate(() => globalThis.__kubidmRivePerf);
    const initMs = init.loadedAt;
    const firstVisibleMs = init.firstVisibleAt;
    const transfers = await resourceTiming(page);
    const frameIntervals = await collectFrameIntervals(page);
    const frameP95Ms = percentile(frameIntervals, 0.95);

    let idleTaskMs = null;
    if (measureIdleCpu && cdp) {
        await page.locator('[data-story="returning"]').click();
        await page.waitForFunction(() => document.querySelector("#ui-lab-mascot-state")?.textContent === "idle");
        await page.waitForTimeout(500);
        const taskBefore = await performanceMetric(cdp, "TaskDuration");
        await page.waitForTimeout(idleSampleMs);
        const taskAfter = await performanceMetric(cdp, "TaskDuration");
        idleTaskMs = (taskAfter - taskBefore) * 1000;
    }

    let heapBefore = null;
    let heapAfter = null;
    let heapGrowthBytes = null;
    if (measureHeap && cdp) {
        await churn(page, 20);
        heapBefore = await heapUsed(cdp);
        await churn(page, stressTransitions);
        heapAfter = await heapUsed(cdp);
        heapGrowthBytes = heapAfter - heapBefore;
    }

    const canvasCount = await page.locator("[data-guide-rive-canvas]").count();
    const diagnostics = await page.evaluate(() => globalThis.__kubidmGuideDiagnostics);
    const browserVersion = browser.version();
    await browser.close();

    const failures = [];
    if (!Number.isFinite(initMs) || initMs > initLimit) failures.push(`Rive init ${initMs}ms > ${initLimit}ms`);
    if (!Number.isFinite(firstVisibleMs) || firstVisibleMs > initLimit + 1000) {
        failures.push(`first visible mascot frame ${firstVisibleMs}ms > ${initLimit + 1000}ms`);
    }
    if (frameP95Ms > frameLimit) failures.push(`frame p95 ${frameP95Ms}ms > ${frameLimit}ms`);
    if (idleTaskMs !== null && idleTaskMs > maxIdleTaskMs) {
        failures.push(`idle main-thread task time ${idleTaskMs}ms > ${maxIdleTaskMs}ms over ${idleSampleMs}ms`);
    }
    if (heapGrowthBytes !== null && heapGrowthBytes > maxHeapGrowthBytes) {
        failures.push(`post-GC JS heap growth ${heapGrowthBytes} > ${maxHeapGrowthBytes}`);
    }
    if (canvasCount > 1) failures.push(`active Rive canvases ${canvasCount} > 1`);
    if (diagnostics?.fallbackActive) failures.push("Rive unexpectedly fell back to static renderer");
    const applicationErrors = consoleErrors.filter((error) => !/ERR_TOO_MANY_RETRIES/.test(error));
    if (applicationErrors.length > 0) failures.push(`console errors: ${applicationErrors.join("; ")}`);
    if (mode === "real") {
        for (const [asset, timing] of Object.entries(transfers)) {
            if (!timing) failures.push(`missing Resource Timing entry for ${asset}`);
        }
        if (externalRequests.length > 0) failures.push(`external requests: ${externalRequests.join("; ")}`);
    }

    return {
        name,
        browserVersion,
        viewport,
        cpuRate,
        thresholds: {
            maxInitMs: initLimit,
            maxFirstVisibleMs: initLimit + 1000,
            maxFrameP95Ms: frameLimit,
            maxIdleTaskMs: measureIdleCpu ? maxIdleTaskMs : null,
            idleSampleMs: measureIdleCpu ? idleSampleMs : null,
            maxHeapGrowthBytes: measureHeap ? maxHeapGrowthBytes : null,
            stressTransitions: measureHeap ? stressTransitions : null,
        },
        measurements: {
            initMs,
            firstVisibleMs,
            frameP95Ms,
            frameSampleCount: frameIntervals.length,
            idleTaskMs,
            heapBefore,
            heapAfter,
            heapGrowthBytes,
            canvasCount,
            transfers,
        },
        diagnostics,
        consoleErrors,
        externalRequests,
        failures,
    };
}

const profiles = [
    {
        browserType: chromium,
        name: "chromium-desktop",
        viewport: { width: 1440, height: 900 },
        initLimit: maxInitMs,
        frameLimit: maxFrameP95Ms,
        measureHeap: true,
        measureIdleCpu: true,
    },
    {
        browserType: firefox,
        name: "firefox-desktop",
        viewport: { width: 1440, height: 900 },
        initLimit: maxInitMs,
        frameLimit: maxFrameP95Ms,
    },
    {
        browserType: webkit,
        name: "webkit-desktop",
        viewport: { width: 1440, height: 900 },
        initLimit: maxInitMs,
        frameLimit: maxFrameP95Ms,
    },
    {
        browserType: chromium,
        name: `chromium-mobile-${mobileCpuRate}x-cpu`,
        viewport: { width: 390, height: 844 },
        initLimit: maxMobileInitMs,
        frameLimit: maxMobileFrameP95Ms,
        cpuRate: mobileCpuRate,
    },
];

const results = [];
for (const profile of profiles) results.push(await measureProfile(profile));

const result = {
    mode,
    thresholds: {
        maxInitMs,
        maxFrameP95Ms,
        maxMobileInitMs,
        maxMobileFrameP95Ms,
        maxIdleTaskMs,
        idleSampleMs,
        maxHeapGrowthBytes,
        stressTransitions,
        mobileCpuRate,
    },
    profiles: results,
};

await mkdir(path.dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);

const failures = results.flatMap((profile) => profile.failures.map((failure) => `${profile.name}: ${failure}`));
if (failures.length > 0) {
    console.error(`Kubidm Rive performance gate failed:\n- ${failures.join("\n- ")}`);
    process.exit(1);
}

console.log(output);

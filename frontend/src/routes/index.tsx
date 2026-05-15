import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Slider } from "@/components/ui/slider";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Activity,
  ShieldCheck,
  Radar,
  Cpu,
  Loader2,
  Zap,
  AlertTriangle,
  ShieldAlert,
  ShieldQuestion,
  Terminal,
} from "lucide-react";

export const Route = createFileRoute("/")({
  component: Dashboard,
});

type Metrics = {
  failure_rate: number;
  port_scan_intensity: number;
  process_cpu_ratio: number;
  packet_spike_ratio: number;
  connection_spike_ratio: number;
  cpu_spike_ratio: number;
};

type ApiResponse = {
  anomaly_pred: number;
  attack_pred: string;
  final_prediction: string;
  confidence: number;
  severity: string;
};

const METRIC_LABELS: { key: keyof Metrics; label: string }[] = [
  { key: "failure_rate", label: "Failure Rate" },
  { key: "port_scan_intensity", label: "Port Scan Intensity" },
  { key: "process_cpu_ratio", label: "Process CPU Ratio" },
  { key: "packet_spike_ratio", label: "Packet Spike Ratio" },
  { key: "connection_spike_ratio", label: "Connection Spike Ratio" },
  { key: "cpu_spike_ratio", label: "CPU Spike Ratio" },
];

const SAMPLE_DETECTIONS = [
  { ts: "12:04:21", type: "ddos", severity: "high", conf: 0.92 },
  { ts: "12:01:09", type: "port_scan", severity: "medium", conf: 0.74 },
  { ts: "11:58:42", type: "none", severity: "low", conf: 0.98 },
  { ts: "11:55:17", type: "brute_force", severity: "high", conf: 0.88 },
  { ts: "11:50:03", type: "suspicious_unknown", severity: "medium", conf: 0.61 },
];

function severityColor(sev: string) {
  if (sev === "high") return "text-neon-red text-glow-red";
  if (sev === "medium") return "text-neon-yellow";
  return "text-neon-green text-glow-green";
}
function severityDot(sev: string) {
  if (sev === "high") return "bg-neon-red text-neon-red";
  if (sev === "medium") return "bg-neon-yellow text-neon-yellow";
  return "bg-neon-green text-neon-green";
}

function StatusCard({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
}) {
  return (
    <div className="panel relative overflow-hidden rounded-2xl p-4">
      <div className="flex items-center gap-3">
        <div className="rounded-lg border border-neon-cyan/30 bg-neon-cyan/5 p-2 text-neon-cyan">
          <Icon className="h-4 w-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
          <div className="mt-1 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-neon-green text-neon-green animate-pulse-glow" />
            <span className="text-sm font-semibold text-neon-green">{value}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function ThreatGauge({ severity, confidence }: { severity?: string; confidence?: number }) {
  const pct = Math.round((confidence ?? 0) * 100);
  const sev = severity ?? "low";
  const color =
    sev === "high"
      ? "var(--neon-red)"
      : sev === "medium"
        ? "var(--neon-yellow)"
        : "var(--neon-green)";
  const radius = 70;
  const circ = 2 * Math.PI * radius;
  const offset = circ - (pct / 100) * circ;
  return (
    <div className="relative flex flex-col items-center justify-center">
      <svg width="180" height="180" className="-rotate-90">
        <circle cx="90" cy="90" r={radius} stroke="oklch(0.3 0.04 220 / 0.4)" strokeWidth="10" fill="none" />
        <circle
          cx="90"
          cy="90"
          r={radius}
          stroke={color}
          strokeWidth="10"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-3xl font-bold" style={{ color, textShadow: `0 0 12px ${color}` }}>
          {pct}%
        </div>
        <div className="text-[10px] uppercase tracking-widest text-muted-foreground mt-1">
          Threat Level
        </div>
        <div className="text-xs uppercase tracking-wider mt-1" style={{ color }}>
          {sev}
        </div>
      </div>
    </div>
  );
}

function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics>({
    failure_rate: 0.5,
    port_scan_intensity: 0.3,
    process_cpu_ratio: 0.4,
    packet_spike_ratio: 0.5,
    connection_spike_ratio: 0.5,
    cpu_spike_ratio: 0.5,
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ApiResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runDetection = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("http://127.0.0.1:8000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(metrics),
      });
      if (!response.ok) throw new Error(`API error ${response.status}`);
      const data: ApiResponse = await response.json();
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Connection to backend failed");
    } finally {
      setLoading(false);
    }
  };

  const isSafe = result?.final_prediction === "none";
  const isUnknown = result?.final_prediction === "suspicious_unknown";

  return (
    <main className="min-h-screen text-foreground">
      <div className="mx-auto max-w-7xl px-4 py-8 md:px-8 md:py-12">
        {/* HERO */}
        <header className="panel scanline relative overflow-hidden rounded-3xl p-6 md:p-10">
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-neon-cyan to-transparent" />
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.3em] text-neon-cyan/80">
                <ShieldCheck className="h-3.5 w-3.5" />
                <span>Edge-AI · SOC Console</span>
              </div>
              <h1 className="mt-2 text-4xl md:text-6xl font-bold tracking-tight text-glow-cyan">
                Cyber<span className="text-neon-cyan">Sentinel</span>
              </h1>
              <p className="mt-2 text-sm md:text-base text-muted-foreground">
                Hybrid Edge-AI Intrusion Detection System
              </p>
            </div>
            <div className="flex items-center gap-3 rounded-full border border-neon-green/30 bg-neon-green/5 px-4 py-2 self-start md:self-auto">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-neon-green" />
              </span>
              <span className="text-xs font-semibold uppercase tracking-widest text-neon-green">
                System Online
              </span>
            </div>
          </div>
        </header>

        {/* SYSTEM STATUS */}
        <section className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-4">
          <StatusCard icon={Activity} label="API Status" value="Online" />
          <StatusCard icon={Radar} label="Detection Engine" value="Active" />
          <StatusCard icon={ShieldCheck} label="Threat Monitor" value="Running" />
          <StatusCard icon={Cpu} label="Hybrid Model" value="Loaded" />
        </section>

        {/* MAIN GRID */}
        <section className="mt-6 grid gap-6 lg:grid-cols-3">
          {/* Traffic Simulation */}
          <div className="panel rounded-2xl p-6 lg:col-span-2">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-widest text-neon-cyan">
                Traffic Simulation
              </h2>
              <span className="text-[10px] uppercase tracking-widest text-muted-foreground">
                Input Vector
              </span>
            </div>
            <div className="mt-6 grid gap-5 sm:grid-cols-2">
              {METRIC_LABELS.map(({ key, label }) => (
                <div key={key}>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground uppercase tracking-wider">{label}</span>
                    <span className="font-mono text-neon-cyan">{metrics[key].toFixed(2)}</span>
                  </div>
                  <Slider
                    value={[metrics[key]]}
                    min={0}
                    max={1}
                    step={0.01}
                    onValueChange={(v) => setMetrics({ ...metrics, [key]: v[0] })}
                    className="mt-2"
                  />
                </div>
              ))}
            </div>
            <div className="mt-6 flex flex-col-reverse sm:flex-row sm:items-center sm:justify-between gap-3">
              <p className="text-xs text-muted-foreground">
                Sends vector to <span className="font-mono text-neon-cyan">POST /predict</span>
              </p>
              <Button
                onClick={runDetection}
                disabled={loading}
                className="bg-neon-cyan text-primary-foreground hover:bg-neon-cyan/90 glow-cyan font-semibold uppercase tracking-widest"
              >
                {loading ? (
                  <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Scanning</>
                ) : (
                  <><Zap className="mr-2 h-4 w-4" /> Run Detection</>
                )}
              </Button>
            </div>
            {loading && (
              <div className="mt-4 relative h-1 w-full overflow-hidden rounded-full bg-neon-cyan/10">
                <div className="absolute inset-y-0 w-1/3 bg-gradient-to-r from-transparent via-neon-cyan to-transparent animate-sweep" />
              </div>
            )}
            {error && (
              <div className="mt-4 rounded-lg border border-neon-red/40 bg-neon-red/10 p-3 text-xs text-neon-red flex items-center gap-2">
                <AlertTriangle className="h-4 w-4" /> {error}
              </div>
            )}
          </div>

          {/* Threat Gauge */}
          <div className="panel rounded-2xl p-6 flex flex-col">
            <h2 className="text-sm font-semibold uppercase tracking-widest text-neon-cyan">
              Threat Meter
            </h2>
            <div className="flex-1 flex items-center justify-center py-4">
              <ThreatGauge severity={result?.severity} confidence={result?.confidence} />
            </div>
            <div className="grid grid-cols-3 gap-2 text-center text-[10px] uppercase tracking-widest">
              <div className="rounded border border-neon-green/30 bg-neon-green/5 py-1.5 text-neon-green">Low</div>
              <div className="rounded border border-neon-yellow/30 bg-neon-yellow/5 py-1.5 text-neon-yellow">Med</div>
              <div className="rounded border border-neon-red/30 bg-neon-red/5 py-1.5 text-neon-red">High</div>
            </div>
          </div>
        </section>

        {/* DETECTION RESULT */}
        <section className="mt-6 panel rounded-2xl p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-widest text-neon-cyan">
              Detection Result
            </h2>
            {result && (
              <Badge
                variant="outline"
                className={`uppercase tracking-widest border-current ${severityColor(result.severity)}`}
              >
                {isSafe ? "Safe" : isUnknown ? "Unknown Threat" : result.severity}
              </Badge>
            )}
          </div>

          {!result ? (
            <div className="mt-6 flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Radar className="h-10 w-10 opacity-40" />
              <p className="mt-3 text-sm">Awaiting first scan…</p>
            </div>
          ) : isSafe ? (
            <div className="mt-6 rounded-xl border border-neon-green/40 bg-neon-green/5 p-6 text-center glow-green">
              <ShieldCheck className="mx-auto h-10 w-10 text-neon-green text-glow-green" />
              <div className="mt-2 text-2xl font-bold text-neon-green text-glow-green">SYSTEM SAFE</div>
              <div className="text-xs text-muted-foreground mt-1">No anomalies detected</div>
            </div>
          ) : isUnknown ? (
            <div className="mt-6 rounded-xl border border-neon-yellow/40 bg-neon-yellow/5 p-6 text-center">
              <ShieldQuestion className="mx-auto h-10 w-10 text-neon-yellow" />
              <div className="mt-2 text-2xl font-bold text-neon-yellow">UNKNOWN THREAT</div>
              <div className="text-xs text-muted-foreground mt-1">
                Suspicious pattern — manual review recommended
              </div>
            </div>
          ) : (
            <div className="mt-6 grid gap-3 sm:grid-cols-4">
              <ResultTile label="Final Prediction" value={result.final_prediction.toUpperCase()} accent="cyan" />
              <ResultTile label="Confidence" value={`${(result.confidence * 100).toFixed(1)}%`} accent="cyan" />
              <ResultTile
                label="Severity"
                value={result.severity.toUpperCase()}
                accent={result.severity === "high" ? "red" : result.severity === "medium" ? "yellow" : "green"}
              />
              <ResultTile
                label="Anomaly"
                value={result.anomaly_pred === 1 ? "DETECTED" : "CLEAR"}
                accent={result.anomaly_pred === 1 ? "red" : "green"}
              />
            </div>
          )}
        </section>

        {/* JSON + RECENT */}
        <section className="mt-6 grid gap-6 lg:grid-cols-2">
          <div className="panel rounded-2xl overflow-hidden">
            <div className="flex items-center gap-2 border-b border-border/60 bg-black/30 px-4 py-2.5">
              <Terminal className="h-3.5 w-3.5 text-neon-green" />
              <span className="text-[11px] font-mono text-neon-green">api_response.json</span>
              <div className="ml-auto flex gap-1.5">
                <span className="h-2 w-2 rounded-full bg-neon-red/60" />
                <span className="h-2 w-2 rounded-full bg-neon-yellow/60" />
                <span className="h-2 w-2 rounded-full bg-neon-green/60" />
              </div>
            </div>
            <pre className="p-4 text-xs font-mono text-neon-green/90 leading-relaxed overflow-auto max-h-80">
{result
  ? JSON.stringify(result, null, 2)
  : `// Run detection to view response
{
  "anomaly_pred": null,
  "attack_pred": null,
  "final_prediction": null,
  "confidence": null,
  "severity": null
}`}
            </pre>
          </div>

          <div className="panel rounded-2xl p-6">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-widest text-neon-cyan">
                Recent Detections
              </h2>
              <span className="text-[10px] uppercase tracking-widest text-muted-foreground">Sample</span>
            </div>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-[10px] uppercase tracking-widest text-muted-foreground border-b border-border/60">
                    <th className="py-2 font-medium">Time</th>
                    <th className="py-2 font-medium">Attack</th>
                    <th className="py-2 font-medium">Severity</th>
                    <th className="py-2 font-medium text-right">Conf.</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {SAMPLE_DETECTIONS.map((d, i) => (
                    <tr key={i} className="border-b border-border/30 last:border-0 hover:bg-neon-cyan/5">
                      <td className="py-2.5 text-muted-foreground">{d.ts}</td>
                      <td className="py-2.5 text-foreground">{d.type}</td>
                      <td className="py-2.5">
                        <span className={`inline-flex items-center gap-1.5 ${severityColor(d.severity)}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${severityDot(d.severity).split(" ")[0]} animate-pulse-glow`} />
                          {d.severity}
                        </span>
                      </td>
                      <td className="py-2.5 text-right text-neon-cyan">{(d.conf * 100).toFixed(0)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <footer className="mt-10 border-t border-border/40 pt-6 text-center">
          <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
            <ShieldAlert className="h-3.5 w-3.5 text-neon-cyan" />
            <span>CyberSentinel — Lightweight Hybrid IDS for IoT and Edge Devices</span>
          </div>
        </footer>
      </div>
    </main>
  );
}

function ResultTile({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent: "cyan" | "red" | "green" | "yellow";
}) {
  const map = {
    cyan: "border-neon-cyan/40 text-neon-cyan text-glow-cyan",
    red: "border-neon-red/40 text-neon-red text-glow-red",
    green: "border-neon-green/40 text-neon-green text-glow-green",
    yellow: "border-neon-yellow/40 text-neon-yellow",
  }[accent];
  return (
    <div className={`rounded-xl border bg-black/30 p-4 ${map}`}>
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="mt-2 text-lg font-bold font-mono break-words">{value}</div>
    </div>
  );
}

"use client";

import { useState, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import { uploadPcap, analyzeStream, generateDemo } from "@/lib/api";
import { formatBytes, ANALYSIS_STAGES } from "@/lib/constants";
import type { AnalysisProgress, AnalysisResult } from "@/lib/types";
import styles from "./page.module.css";

type AppState = "idle" | "uploaded" | "analyzing" | "complete" | "error";

export default function UploadPage() {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [state, setState] = useState<AppState>("idle");
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [progress, setProgress] = useState<AnalysisProgress | null>(null);
  const [error, setError] = useState<string>("");
  const [analysisId, setAnalysisId] = useState<string>("");
  const [demoLoading, setDemoLoading] = useState(false);

  // Stash analysis result in sessionStorage for the dashboard to read
  const storeAndNavigate = useCallback(
    (result: AnalysisResult) => {
      sessionStorage.setItem(
        `analysis_${result.analysis_id}`,
        JSON.stringify(result),
      );
      router.push(`/analysis/${result.analysis_id}`);
    },
    [router],
  );

  const handleFile = useCallback((f: File) => {
    const ext = f.name.toLowerCase();
    if (!ext.endsWith(".pcap") && !ext.endsWith(".pcapng")) {
      setError("Only .pcap and .pcapng files are supported.");
      return;
    }
    setFile(f);
    setState("uploaded");
    setError("");
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const f = e.dataTransfer.files[0];
      if (f) handleFile(f);
    },
    [handleFile],
  );

  const handleStartAnalysis = useCallback(async () => {
    if (!file) return;
    setState("analyzing");
    setError("");

    try {
      const upload = await uploadPcap(file);
      setAnalysisId(upload.analysis_id);

      analyzeStream(
        upload.analysis_id,
        (p) => setProgress(p),
        (result) => storeAndNavigate(result),
        (err) => {
          setError(err);
          setState("error");
        },
      );
    } catch (e: any) { // eslint-disable-next-line @typescript-eslint/no-explicit-any
      setError(e?.message || "Upload failed");
      setState("error");
    }
  }, [file, storeAndNavigate]);

  const handleDemo = useCallback(async () => {
    setDemoLoading(true);
    setError("");
    try {
      const result = await generateDemo();
      storeAndNavigate(result);
    } catch (e: any) { // eslint-disable-next-line @typescript-eslint/no-explicit-any
      setError(e?.message || "Demo generation failed");
      setDemoLoading(false);
    }
  }, [storeAndNavigate]);

  return (
    <main className={styles.main}>
      {/* Background gradient overlay */}
      <div className={styles.bgGradient} />

      <div className={styles.container}>
        {/* Logo & Title */}
        <div className={styles.hero}>
          <div className={styles.logoIcon}>
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
              <rect width="48" height="48" rx="12" fill="url(#grad)" />
              <path
                d="M14 18L24 25L34 18M14 30H34M14 18V30H34V18H14Z"
                stroke="white"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <circle cx="36" cy="12" r="6" fill="#0F766E" stroke="white" strokeWidth="2" />
              <path d="M36 10V14M34 12H38" stroke="white" strokeWidth="1.5" strokeLinecap="round" />
              <defs>
                <linearGradient id="grad" x1="0" y1="0" x2="48" y2="48">
                  <stop stopColor="#0F172A" />
                  <stop offset="0.5" stopColor="#155E75" />
                  <stop offset="1" stopColor="#0F766E" />
                </linearGradient>
              </defs>
            </svg>
          </div>
          <h1 className={styles.title}>SECUREMAILSCOPE</h1>
          <p className={styles.subtitle}>Passive Email Cryptographic Forensics</p>
        </div>

        {/* Drop Zone */}
        {(state === "idle" || state === "uploaded") && (
          <div
            className={`${styles.dropZone} ${dragOver ? styles.dropZoneActive : ""} ${state === "uploaded" ? styles.dropZoneUploaded : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => state === "idle" && fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng"
              className={styles.fileInput}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) handleFile(f);
              }}
            />

            {state === "idle" ? (
              <>
                <div className={styles.uploadIcon}>
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
                <p className={styles.dropText}>Drop PCAP file here</p>
                <p className={styles.dropSubtext}>or</p>
                <button className={styles.browseBtn}>Browse PCAP</button>
                <p className={styles.formatHint}>Supports .pcap and .pcapng</p>
              </>
            ) : (
              <div className={styles.fileInfo}>
                <div className={styles.fileIcon}>📦</div>
                <div className={styles.fileDetails}>
                  <p className={styles.fileName}>{file?.name}</p>
                  <p className={styles.fileSize}>{file ? formatBytes(file.size) : ""}</p>
                </div>
                <button
                  className={styles.removeBtn}
                  onClick={(e) => { e.stopPropagation(); setFile(null); setState("idle"); }}
                >
                  ✕
                </button>
              </div>
            )}
          </div>
        )}

        {/* Start Analysis Button */}
        {state === "uploaded" && (
          <button className={styles.analyzeBtn} onClick={handleStartAnalysis}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="5 3 19 12 5 21 5 3" strokeLinejoin="round" />
            </svg>
            Start Analysis
          </button>
        )}

        {/* Analysis Progress */}
        {state === "analyzing" && (
          <div className={styles.progressContainer}>
            <div className={styles.progressHeader}>
              <span className={styles.progressTitle}>
                {progress ? ANALYSIS_STAGES[progress.stage] || progress.stage : "Starting analysis..."}
              </span>
              <span className={styles.progressPct}>{progress?.progress || 0}%</span>
            </div>
            <div className={styles.progressBar}>
              <div
                className={styles.progressFill}
                style={{ width: `${progress?.progress || 0}%` }}
              />
            </div>
            <div className={styles.progressStages}>
              {["parsing", "detecting_protocols", "reconstructing", "extracting_tls", "analyzing_certs", "rule_engine", "ml_detection"].map((stage) => {
                const currentIdx = progress ? ["parsing", "detecting_protocols", "reconstructing", "extracting_tls", "analyzing_certs", "rule_engine", "ml_detection"].indexOf(progress.stage) : -1;
                const stageIdx = ["parsing", "detecting_protocols", "reconstructing", "extracting_tls", "analyzing_certs", "rule_engine", "ml_detection"].indexOf(stage);
                const isDone = stageIdx < currentIdx;
                const isCurrent = stageIdx === currentIdx;

                return (
                  <div key={stage} className={`${styles.stageItem} ${isDone ? styles.stageDone : ""} ${isCurrent ? styles.stageCurrent : ""}`}>
                    <span className={styles.stageIcon}>
                      {isDone ? "✓" : isCurrent ? "●" : "○"}
                    </span>
                    <span>{ANALYSIS_STAGES[stage]}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className={styles.errorBox}>
            <span>⚠️</span>
            <p>{error}</p>
            <button onClick={() => { setError(""); setState("idle"); setFile(null); }}>
              Try Again
            </button>
          </div>
        )}

        {/* Divider */}
        <div className={styles.divider}>
          <span>or</span>
        </div>

        {/* Demo Button */}
        <button
          className={styles.demoBtn}
          onClick={handleDemo}
          disabled={demoLoading || state === "analyzing"}
        >
          {demoLoading ? (
            <>
              <span className={styles.spinner} />
              Generating Demo...
            </>
          ) : (
            <>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" strokeLinejoin="round" />
                <path d="M14 2v6h6M10 13l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              Try with Demo Data
            </>
          )}
        </button>
        <p className={styles.demoHint}>
          Explore SecureMailScope with 37 simulated email sessions — no PCAP needed
        </p>
      </div>
    </main>
  );
}
